// Package main is the entry point for Threat Telemetry Hub
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/lvonguyen/threat-telemetry-hub/internal/ai"
	"github.com/lvonguyen/threat-telemetry-hub/internal/config"
	"github.com/lvonguyen/threat-telemetry-hub/internal/correlation"
	"github.com/lvonguyen/threat-telemetry-hub/internal/enrichment"
	"github.com/lvonguyen/threat-telemetry-hub/internal/ingestion"
	"github.com/lvonguyen/threat-telemetry-hub/internal/normalization"
)

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Load configuration
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	logger.Info("Starting Threat Telemetry Hub",
		zap.String("version", "1.0.0"),
		zap.Int("port", cfg.Server.Port),
	)

	// Initialize AI analyzer
	aiAnalyzer, err := ai.NewAnalyzer(cfg.AI, logger)
	if err != nil {
		logger.Fatal("Failed to initialize AI analyzer", zap.Error(err))
	}

	// Initialize components
	ingestionMgr := ingestion.NewManager(cfg.Ingestion, logger)
	normalizer := normalization.NewNormalizer(cfg.Normalization, logger)
	enricher := enrichment.NewEnricher(cfg.Enrichment, logger)
	correlator := correlation.NewCorrelator(logger)

	// Create processing pipeline
	pipeline := NewPipeline(ingestionMgr, normalizer, aiAnalyzer, enricher, correlator, logger)

	// Start pipeline
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pipeline.Start(ctx)

	// Setup HTTP server
	router := gin.Default()
	setupRoutes(router, pipeline, logger)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(err))
		}
	}()

	logger.Info("Threat Telemetry Hub started successfully",
		zap.String("api_url", fmt.Sprintf("http://localhost:%d", cfg.Server.Port)),
	)

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	cancel() // Stop pipeline
	logger.Info("Threat Telemetry Hub stopped")
}

// Pipeline orchestrates the telemetry processing flow
type Pipeline struct {
	ingestion   *ingestion.Manager
	normalizer  *normalization.Normalizer
	aiAnalyzer  *ai.Analyzer
	enricher    *enrichment.Enricher
	correlator  *correlation.Correlator
	logger      *zap.Logger
	eventChan   chan *ingestion.RawEvent
	outputChan  chan *ProcessedEvent
}

// ProcessedEvent represents a fully processed telemetry event
type ProcessedEvent struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	Source          string                 `json:"source"`
	SourceType      string                 `json:"source_type"`
	NormalizedData  map[string]interface{} `json:"normalized_data"`
	RawData         map[string]interface{} `json:"raw_data"`
	AIAnalysis      *ai.RiskAnalysis       `json:"ai_analysis,omitempty"`
	Enrichments     map[string]interface{} `json:"enrichments,omitempty"`
	CorrelationID   string                 `json:"correlation_id,omitempty"`
	RiskScore       float64                `json:"risk_score"`
	RiskLevel       string                 `json:"risk_level"`
	MITRETactics    []string               `json:"mitre_tactics,omitempty"`
	MITRETechniques []string               `json:"mitre_techniques,omitempty"`
}

// NewPipeline creates a new processing pipeline
func NewPipeline(
	ingestionMgr *ingestion.Manager,
	normalizer *normalization.Normalizer,
	aiAnalyzer *ai.Analyzer,
	enricher *enrichment.Enricher,
	correlator *correlation.Correlator,
	logger *zap.Logger,
) *Pipeline {
	return &Pipeline{
		ingestion:  ingestionMgr,
		normalizer: normalizer,
		aiAnalyzer: aiAnalyzer,
		enricher:   enricher,
		correlator: correlator,
		logger:     logger,
		eventChan:  make(chan *ingestion.RawEvent, 1000),
		outputChan: make(chan *ProcessedEvent, 1000),
	}
}

// Start begins processing events
func (p *Pipeline) Start(ctx context.Context) {
	p.logger.Info("Starting telemetry processing pipeline")

	// Start ingestion
	go p.ingestion.Start(ctx, p.eventChan)

	// Process events
	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Pipeline shutting down")
			return
		case rawEvent := <-p.eventChan:
			go p.processEvent(ctx, rawEvent)
		}
	}
}

func (p *Pipeline) processEvent(ctx context.Context, raw *ingestion.RawEvent) {
	p.logger.Debug("Processing event",
		zap.String("source", raw.Source),
		zap.String("id", raw.ID),
	)

	// Step 1: AI analysis on raw data (before normalization)
	// This catches context that might be lost in normalization
	aiAnalysis, err := p.aiAnalyzer.AnalyzeRawEvent(ctx, raw)
	if err != nil {
		p.logger.Warn("AI analysis failed, continuing without",
			zap.Error(err),
			zap.String("event_id", raw.ID),
		)
	}

	// Step 2: Normalize to standard schema
	normalized, err := p.normalizer.Normalize(raw)
	if err != nil {
		p.logger.Error("Normalization failed",
			zap.Error(err),
			zap.String("event_id", raw.ID),
		)
		return
	}

	// Step 3: Enrich with context
	enrichments, err := p.enricher.Enrich(ctx, normalized)
	if err != nil {
		p.logger.Warn("Enrichment partially failed",
			zap.Error(err),
			zap.String("event_id", raw.ID),
		)
	}

	// Step 4: Correlate with other events
	correlationID := p.correlator.Correlate(normalized)

	// Build processed event
	processed := &ProcessedEvent{
		ID:             raw.ID,
		Timestamp:      raw.Timestamp,
		Source:         raw.Source,
		SourceType:     raw.SourceType,
		NormalizedData: normalized.Data,
		RawData:        raw.Data,
		AIAnalysis:     aiAnalysis,
		Enrichments:    enrichments,
		CorrelationID:  correlationID,
	}

	// Calculate final risk score (combining AI + rules)
	processed.RiskScore, processed.RiskLevel = p.calculateRisk(aiAnalysis, normalized)

	// Extract MITRE mappings
	if aiAnalysis != nil {
		processed.MITRETactics = aiAnalysis.MITRETactics
		processed.MITRETechniques = aiAnalysis.MITRETechniques
	}

	p.outputChan <- processed

	p.logger.Info("Event processed",
		zap.String("event_id", processed.ID),
		zap.Float64("risk_score", processed.RiskScore),
		zap.String("risk_level", processed.RiskLevel),
	)
}

func (p *Pipeline) calculateRisk(aiAnalysis *ai.RiskAnalysis, _ *normalization.NormalizedEvent) (float64, string) {
	if aiAnalysis == nil {
		return 0.0, "unknown"
	}

	score := aiAnalysis.RiskScore

	// Determine level
	var level string
	switch {
	case score >= 0.9:
		level = "critical"
	case score >= 0.7:
		level = "high"
	case score >= 0.4:
		level = "medium"
	case score >= 0.1:
		level = "low"
	default:
		level = "info"
	}

	return score, level
}

func setupRoutes(router *gin.Engine, pipeline *Pipeline, logger *zap.Logger) {
	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// API v1
	v1 := router.Group("/api/v1")
	{
		// Events
		v1.GET("/events", func(c *gin.Context) {
			// TODO: Implement event listing
			c.JSON(http.StatusOK, gin.H{"events": []interface{}{}})
		})

		v1.GET("/events/:id", func(c *gin.Context) {
			// TODO: Implement event retrieval
			c.JSON(http.StatusNotFound, gin.H{"error": "not implemented"})
		})

		// Risk analysis
		v1.GET("/risk/summary", func(c *gin.Context) {
			// TODO: Implement risk summary
			c.JSON(http.StatusOK, gin.H{
				"critical": 0,
				"high":     0,
				"medium":   0,
				"low":      0,
			})
		})

		// Sources
		v1.GET("/sources", func(c *gin.Context) {
			// TODO: Implement source listing
			c.JSON(http.StatusOK, gin.H{"sources": []interface{}{}})
		})

		v1.GET("/sources/:name/status", func(c *gin.Context) {
			// TODO: Implement source status
			c.JSON(http.StatusNotFound, gin.H{"error": "not implemented"})
		})
	}

	logger.Info("API routes configured")
}

