// Package enrichment handles event enrichment with contextual data
package enrichment

import (
	"context"

	"go.uber.org/zap"

	"github.com/lvonguyen/threat-telemetry-hub/internal/config"
	"github.com/lvonguyen/threat-telemetry-hub/internal/normalization"
)

// Enricher handles event enrichment from multiple sources
type Enricher struct {
	config  config.EnrichmentConfig
	logger  *zap.Logger
	sources []EnrichmentSource
}

// EnrichmentSource defines the interface for enrichment sources
type EnrichmentSource interface {
	// Name returns the source name
	Name() string
	// Enrich adds context to the event
	Enrich(ctx context.Context, event *normalization.NormalizedEvent) (map[string]interface{}, error)
	// Enabled returns whether this source is enabled
	Enabled() bool
}

// NewEnricher creates a new enricher
func NewEnricher(cfg config.EnrichmentConfig, logger *zap.Logger) *Enricher {
	e := &Enricher{
		config:  cfg,
		logger:  logger,
		sources: make([]EnrichmentSource, 0),
	}

	// Initialize enrichment sources
	if cfg.ThreatForge.Enabled {
		e.sources = append(e.sources, NewThreatForgeSource(cfg.ThreatForge, logger))
	}
	if cfg.Identity.EntraID.Enabled {
		e.sources = append(e.sources, NewEntraIDSource(cfg.Identity.EntraID, logger))
	}
	if cfg.Identity.Okta.Enabled {
		e.sources = append(e.sources, NewOktaSource(cfg.Identity.Okta, logger))
	}
	if cfg.Asset.Enabled {
		e.sources = append(e.sources, NewAssetSource(cfg.Asset, logger))
	}

	logger.Info("Enricher initialized",
		zap.Int("sources", len(e.sources)),
	)

	return e
}

// Enrich adds contextual data to an event from all enabled sources
func (e *Enricher) Enrich(ctx context.Context, event *normalization.NormalizedEvent) (map[string]interface{}, error) {
	enrichments := make(map[string]interface{})

	for _, source := range e.sources {
		if source.Enabled() {
			data, err := source.Enrich(ctx, event)
			if err != nil {
				e.logger.Warn("Enrichment source failed",
					zap.String("source", source.Name()),
					zap.Error(err),
				)
				continue
			}
			enrichments[source.Name()] = data
		}
	}

	return enrichments, nil
}

// =============================================================================
// Enrichment Sources
// =============================================================================

// ThreatForgeSource enriches with threat intelligence from threatforge
type ThreatForgeSource struct {
	config  config.ThreatForgeConfig
	logger  *zap.Logger
	enabled bool
}

func NewThreatForgeSource(cfg config.ThreatForgeConfig, logger *zap.Logger) *ThreatForgeSource {
	return &ThreatForgeSource{config: cfg, logger: logger, enabled: cfg.Enabled}
}

func (s *ThreatForgeSource) Name() string  { return "threatforge" }
func (s *ThreatForgeSource) Enabled() bool { return s.enabled }

func (s *ThreatForgeSource) Enrich(ctx context.Context, event *normalization.NormalizedEvent) (map[string]interface{}, error) {
	// TODO: Implement threatforge integration
	// - Extract IOCs from event (IPs, domains, hashes)
	// - Query threatforge API for enrichment
	// - Return threat intel context
	return map[string]interface{}{
		"threat_score": 0,
		"ioc_matches":  []string{},
	}, nil
}

// EntraIDSource enriches with identity context from Microsoft Entra ID
type EntraIDSource struct {
	config  config.EntraIDConfig
	logger  *zap.Logger
	enabled bool
}

func NewEntraIDSource(cfg config.EntraIDConfig, logger *zap.Logger) *EntraIDSource {
	return &EntraIDSource{config: cfg, logger: logger, enabled: cfg.Enabled}
}

func (s *EntraIDSource) Name() string  { return "entra_id" }
func (s *EntraIDSource) Enabled() bool { return s.enabled }

func (s *EntraIDSource) Enrich(ctx context.Context, event *normalization.NormalizedEvent) (map[string]interface{}, error) {
	// TODO: Implement Entra ID integration
	// - Extract user principal from event
	// - Query Microsoft Graph API for user details
	// - Return: department, manager, risk score, group memberships
	return map[string]interface{}{
		"user":       nil,
		"risk_level": "unknown",
	}, nil
}

// OktaSource enriches with identity context from Okta
type OktaSource struct {
	config  config.OktaConfig
	logger  *zap.Logger
	enabled bool
}

func NewOktaSource(cfg config.OktaConfig, logger *zap.Logger) *OktaSource {
	return &OktaSource{config: cfg, logger: logger, enabled: cfg.Enabled}
}

func (s *OktaSource) Name() string  { return "okta" }
func (s *OktaSource) Enabled() bool { return s.enabled }

func (s *OktaSource) Enrich(ctx context.Context, event *normalization.NormalizedEvent) (map[string]interface{}, error) {
	// TODO: Implement Okta integration
	// - Extract user identifier from event
	// - Query Okta API for user details
	// - Return: user profile, factors, group memberships
	return map[string]interface{}{
		"user":   nil,
		"groups": []string{},
	}, nil
}

// AssetSource enriches with asset context from CMDB
type AssetSource struct {
	config  config.AssetConfig
	logger  *zap.Logger
	enabled bool
}

func NewAssetSource(cfg config.AssetConfig, logger *zap.Logger) *AssetSource {
	return &AssetSource{config: cfg, logger: logger, enabled: cfg.Enabled}
}

func (s *AssetSource) Name() string  { return "asset" }
func (s *AssetSource) Enabled() bool { return s.enabled }

func (s *AssetSource) Enrich(ctx context.Context, event *normalization.NormalizedEvent) (map[string]interface{}, error) {
	// TODO: Implement CMDB/Asset integration
	// - Extract hostname/IP from event
	// - Query asset database for details
	// - Return: owner, business unit, criticality, environment
	return map[string]interface{}{
		"asset":         nil,
		"criticality":   "unknown",
		"business_unit": "unknown",
	}, nil
}
