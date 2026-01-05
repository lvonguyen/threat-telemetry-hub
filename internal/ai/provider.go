// Package ai provides AI-powered analysis for security telemetry
package ai

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	"github.com/lvonguyen/threat-telemetry-hub/internal/config"
	"github.com/lvonguyen/threat-telemetry-hub/internal/ingestion"
)

// Provider defines the interface for AI providers
type Provider interface {
	// Analyze performs AI analysis on the given prompt
	Analyze(ctx context.Context, prompt string) (*Response, error)
	// Name returns the provider name
	Name() string
}

// Response represents an AI analysis response
type Response struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   Usage  `json:"usage"`
}

// Usage represents token usage
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// RiskAnalysis represents the AI-generated risk analysis
type RiskAnalysis struct {
	RiskScore       float64  `json:"risk_score"`        // 0.0 - 1.0
	RiskLevel       string   `json:"risk_level"`        // critical, high, medium, low, info
	Summary         string   `json:"summary"`           // Natural language summary
	Indicators      []string `json:"indicators"`        // Key indicators of compromise
	MITRETactics    []string `json:"mitre_tactics"`     // MITRE ATT&CK tactics
	MITRETechniques []string `json:"mitre_techniques"`  // MITRE ATT&CK techniques
	Recommendations []string `json:"recommendations"`   // Suggested actions
	Confidence      float64  `json:"confidence"`        // AI confidence 0.0 - 1.0
	RawContext      string   `json:"raw_context"`       // Context from raw data analysis
}

// Analyzer orchestrates AI analysis
type Analyzer struct {
	provider Provider
	logger   *zap.Logger
}

// NewAnalyzer creates a new AI analyzer based on configuration
func NewAnalyzer(cfg config.AIConfig, logger *zap.Logger) (*Analyzer, error) {
	var provider Provider
	var err error

	switch cfg.Provider {
	case "anthropic":
		provider, err = NewAnthropicProvider(cfg.Anthropic, logger)
	case "openai":
		provider, err = NewOpenAIProvider(cfg.OpenAI, logger)
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("initializing AI provider %s: %w", cfg.Provider, err)
	}

	logger.Info("AI analyzer initialized",
		zap.String("provider", cfg.Provider),
	)

	return &Analyzer{
		provider: provider,
		logger:   logger,
	}, nil
}

// AnalyzeRawEvent performs AI analysis on raw event data before normalization
// This captures context that might be lost during schema normalization
func (a *Analyzer) AnalyzeRawEvent(ctx context.Context, event *ingestion.RawEvent) (*RiskAnalysis, error) {
	// Build prompt for raw event analysis
	prompt := a.buildRawEventPrompt(event)

	// Call AI provider
	response, err := a.provider.Analyze(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	// Parse response into RiskAnalysis
	analysis, err := a.parseRiskAnalysis(response.Content)
	if err != nil {
		a.logger.Warn("Failed to parse AI response, using fallback",
			zap.Error(err),
			zap.String("event_id", event.ID),
		)
		return a.fallbackAnalysis(event), nil
	}

	return analysis, nil
}

func (a *Analyzer) buildRawEventPrompt(event *ingestion.RawEvent) string {
	eventJSON, _ := json.MarshalIndent(event.Data, "", "  ")

	return fmt.Sprintf(`Analyze this raw security telemetry event and provide a risk assessment.

Source: %s
Source Type: %s
Timestamp: %s

Raw Event Data:
%s

Provide your analysis as JSON with the following structure:
{
  "risk_score": <float 0.0-1.0>,
  "risk_level": "<critical|high|medium|low|info>",
  "summary": "<1-2 sentence natural language summary>",
  "indicators": ["<indicator1>", "<indicator2>"],
  "mitre_tactics": ["<tactic1>", "<tactic2>"],
  "mitre_techniques": ["<T1234>", "<T5678>"],
  "recommendations": ["<action1>", "<action2>"],
  "confidence": <float 0.0-1.0>,
  "raw_context": "<any important context from raw data that might be lost in normalization>"
}

Focus on:
1. Identifying potential threats or anomalies
2. Mapping to MITRE ATT&CK framework
3. Contextual information that might be lost during schema normalization
4. Actionable recommendations for security analysts`,
		event.Source,
		event.SourceType,
		event.Timestamp.Format("2006-01-02T15:04:05Z"),
		string(eventJSON),
	)
}

func (a *Analyzer) parseRiskAnalysis(content string) (*RiskAnalysis, error) {
	var analysis RiskAnalysis
	if err := json.Unmarshal([]byte(content), &analysis); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w", err)
	}
	return &analysis, nil
}

func (a *Analyzer) fallbackAnalysis(event *ingestion.RawEvent) *RiskAnalysis {
	return &RiskAnalysis{
		RiskScore:       0.5,
		RiskLevel:       "medium",
		Summary:         fmt.Sprintf("Event from %s requires manual review", event.Source),
		Indicators:      []string{},
		MITRETactics:    []string{},
		MITRETechniques: []string{},
		Recommendations: []string{"Review event manually", "Check for related events"},
		Confidence:      0.0,
		RawContext:      "AI analysis unavailable - fallback applied",
	}
}

