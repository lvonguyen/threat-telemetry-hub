// Package ingestion handles data ingestion from various security sources
package ingestion

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/lvonguyen/threat-telemetry-hub/internal/config"
)

// RawEvent represents a raw event from any source
type RawEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Source     string                 `json:"source"`      // e.g., "crowdstrike", "splunk", "aws"
	SourceType string                 `json:"source_type"` // e.g., "edr", "siem", "cloud", "dlp"
	Data       map[string]interface{} `json:"data"`
}

// Manager orchestrates data ingestion from all configured sources
type Manager struct {
	config     config.IngestionConfig
	logger     *zap.Logger
	collectors []Collector
}

// Collector defines the interface for data collectors
type Collector interface {
	// Name returns the collector name
	Name() string
	// Type returns the collector type (edr, siem, cloud, dlp)
	Type() string
	// Collect gathers events and sends them to the output channel
	Collect(ctx context.Context, output chan<- *RawEvent) error
	// Enabled returns whether this collector is enabled
	Enabled() bool
}

// NewManager creates a new ingestion manager
func NewManager(cfg config.IngestionConfig, logger *zap.Logger) *Manager {
	m := &Manager{
		config:     cfg,
		logger:     logger,
		collectors: make([]Collector, 0),
	}

	// Initialize EDR collectors
	if cfg.EDR.CrowdStrike.Enabled {
		m.collectors = append(m.collectors, NewCrowdStrikeCollector(cfg.EDR.CrowdStrike, logger))
	}
	if cfg.EDR.SentinelOne.Enabled {
		m.collectors = append(m.collectors, NewSentinelOneCollector(cfg.EDR.SentinelOne, logger))
	}
	if cfg.EDR.Defender.Enabled {
		m.collectors = append(m.collectors, NewDefenderCollector(cfg.EDR.Defender, logger))
	}

	// Initialize SIEM collectors
	if cfg.SIEM.Splunk.Enabled {
		m.collectors = append(m.collectors, NewSplunkCollector(cfg.SIEM.Splunk, logger))
	}
	if cfg.SIEM.Elasticsearch.Enabled {
		m.collectors = append(m.collectors, NewElasticsearchCollector(cfg.SIEM.Elasticsearch, logger))
	}

	// Initialize Cloud collectors
	if cfg.Cloud.AWS.Enabled {
		m.collectors = append(m.collectors, NewAWSCloudTrailCollector(cfg.Cloud.AWS, logger))
	}
	if cfg.Cloud.Azure.Enabled {
		m.collectors = append(m.collectors, NewAzureActivityCollector(cfg.Cloud.Azure, logger))
	}
	if cfg.Cloud.GCP.Enabled {
		m.collectors = append(m.collectors, NewGCPAuditCollector(cfg.Cloud.GCP, logger))
	}

	// Initialize DLP collectors (COTS integrations)
	if cfg.DLP.DigitalGuardian.Enabled {
		m.collectors = append(m.collectors, NewDigitalGuardianCollector(cfg.DLP.DigitalGuardian, logger))
	}
	if cfg.DLP.Proofpoint.Enabled {
		m.collectors = append(m.collectors, NewProofpointCollector(cfg.DLP.Proofpoint, logger))
	}
	if cfg.DLP.Purview.Enabled {
		m.collectors = append(m.collectors, NewPurviewCollector(cfg.DLP.Purview, logger))
	}
	if cfg.DLP.Netskope.Enabled {
		m.collectors = append(m.collectors, NewNetskopeCollector(cfg.DLP.Netskope, logger))
	}

	logger.Info("Ingestion manager initialized",
		zap.Int("collectors", len(m.collectors)),
	)

	return m
}

// Start begins data collection from all enabled sources
func (m *Manager) Start(ctx context.Context, output chan<- *RawEvent) {
	m.logger.Info("Starting ingestion from all sources")

	for _, collector := range m.collectors {
		if collector.Enabled() {
			go func(c Collector) {
				m.logger.Info("Starting collector",
					zap.String("name", c.Name()),
					zap.String("type", c.Type()),
				)
				if err := c.Collect(ctx, output); err != nil {
					m.logger.Error("Collector error",
						zap.String("name", c.Name()),
						zap.Error(err),
					)
				}
			}(collector)
		}
	}
}

// GetCollectorStatus returns the status of all collectors
func (m *Manager) GetCollectorStatus() []CollectorStatus {
	statuses := make([]CollectorStatus, 0, len(m.collectors))
	for _, c := range m.collectors {
		statuses = append(statuses, CollectorStatus{
			Name:    c.Name(),
			Type:    c.Type(),
			Enabled: c.Enabled(),
		})
	}
	return statuses
}

// CollectorStatus represents the status of a collector
type CollectorStatus struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

