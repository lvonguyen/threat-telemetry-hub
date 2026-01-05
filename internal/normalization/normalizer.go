// Package normalization handles schema normalization for security events
package normalization

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/lvonguyen/threat-telemetry-hub/internal/config"
	"github.com/lvonguyen/threat-telemetry-hub/internal/ingestion"
)

// NormalizedEvent represents an event normalized to a standard schema
type NormalizedEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	Schema        string                 `json:"schema"` // "ocsf" or "ecs"
	SchemaVersion string                 `json:"schema_version"`
	Category      string                 `json:"category"` // e.g., "security_finding", "detection"
	Type          string                 `json:"type"`     // e.g., "malware", "policy_violation"
	Severity      int                    `json:"severity"` // 0-100
	Source        SourceInfo             `json:"source"`
	Data          map[string]interface{} `json:"data"`
	Raw           map[string]interface{} `json:"raw,omitempty"`
}

// SourceInfo contains information about the event source
type SourceInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version,omitempty"`
}

// Normalizer handles schema normalization
type Normalizer struct {
	config config.NormalizationConfig
	logger *zap.Logger
}

// NewNormalizer creates a new normalizer
func NewNormalizer(cfg config.NormalizationConfig, logger *zap.Logger) *Normalizer {
	return &Normalizer{
		config: cfg,
		logger: logger,
	}
}

// Normalize converts a raw event to the configured schema
func (n *Normalizer) Normalize(raw *ingestion.RawEvent) (*NormalizedEvent, error) {
	switch n.config.DefaultSchema {
	case "ocsf":
		return n.normalizeToOCSF(raw)
	case "ecs":
		return n.normalizeToECS(raw)
	default:
		return nil, fmt.Errorf("unsupported schema: %s", n.config.DefaultSchema)
	}
}

// normalizeToOCSF converts to Open Cybersecurity Schema Framework
func (n *Normalizer) normalizeToOCSF(raw *ingestion.RawEvent) (*NormalizedEvent, error) {
	// OCSF Schema Reference: https://schema.ocsf.io/

	event := &NormalizedEvent{
		ID:            raw.ID,
		Timestamp:     raw.Timestamp,
		Schema:        "ocsf",
		SchemaVersion: "1.1.0",
		Source:        n.getSourceInfo(raw),
		Raw:           raw.Data,
		Data:          make(map[string]interface{}),
	}

	// Map to OCSF categories based on source type
	switch raw.SourceType {
	case "edr":
		event.Category = "security_finding"
		event.Type = "detection"
		n.mapEDRToOCSF(raw, event)
	case "siem":
		event.Category = "security_finding"
		event.Type = "alert"
		n.mapSIEMToOCSF(raw, event)
	case "cloud":
		event.Category = "api_activity"
		event.Type = "audit"
		n.mapCloudToOCSF(raw, event)
	case "dlp":
		event.Category = "data_security"
		event.Type = "policy_violation"
		n.mapDLPToOCSF(raw, event)
	default:
		event.Category = "unknown"
		event.Type = "unknown"
	}

	return event, nil
}

// normalizeToECS converts to Elastic Common Schema
func (n *Normalizer) normalizeToECS(raw *ingestion.RawEvent) (*NormalizedEvent, error) {
	// ECS Reference: https://www.elastic.co/guide/en/ecs/current/index.html

	event := &NormalizedEvent{
		ID:            raw.ID,
		Timestamp:     raw.Timestamp,
		Schema:        "ecs",
		SchemaVersion: "8.11.0",
		Source:        n.getSourceInfo(raw),
		Raw:           raw.Data,
		Data:          make(map[string]interface{}),
	}

	// Map to ECS categories based on source type
	switch raw.SourceType {
	case "edr":
		event.Category = "malware"
		event.Type = "detection"
		n.mapEDRToECS(raw, event)
	case "siem":
		event.Category = "threat"
		event.Type = "indicator"
		n.mapSIEMToECS(raw, event)
	case "cloud":
		event.Category = "configuration"
		event.Type = "change"
		n.mapCloudToECS(raw, event)
	case "dlp":
		event.Category = "file"
		event.Type = "access"
		n.mapDLPToECS(raw, event)
	default:
		event.Category = "unknown"
		event.Type = "unknown"
	}

	return event, nil
}

func (n *Normalizer) getSourceInfo(raw *ingestion.RawEvent) SourceInfo {
	vendorMap := map[string]string{
		"crowdstrike":      "CrowdStrike",
		"sentinelone":      "SentinelOne",
		"defender":         "Microsoft",
		"splunk":           "Splunk",
		"elasticsearch":    "Elastic",
		"aws-cloudtrail":   "Amazon Web Services",
		"azure-activity":   "Microsoft",
		"gcp-audit":        "Google Cloud",
		"digital-guardian": "Fortra",
		"proofpoint":       "Proofpoint",
		"purview":          "Microsoft",
		"netskope":         "Netskope",
	}

	productMap := map[string]string{
		"crowdstrike":      "Falcon",
		"sentinelone":      "Singularity",
		"defender":         "Defender for Endpoint",
		"splunk":           "Splunk Enterprise",
		"elasticsearch":    "Elasticsearch Security",
		"aws-cloudtrail":   "CloudTrail",
		"azure-activity":   "Activity Log",
		"gcp-audit":        "Audit Logs",
		"digital-guardian": "Digital Guardian",
		"proofpoint":       "Email Protection",
		"purview":          "Purview DLP",
		"netskope":         "Cloud Security",
	}

	return SourceInfo{
		Name:    raw.Source,
		Type:    raw.SourceType,
		Vendor:  vendorMap[raw.Source],
		Product: productMap[raw.Source],
	}
}

// Schema-specific mapping functions (stubs)

func (n *Normalizer) mapEDRToOCSF(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement EDR to OCSF mapping
	// Map fields like: detection_type, severity, process_name, file_hash, etc.
	event.Severity = 70 // Default high for EDR
}

func (n *Normalizer) mapSIEMToOCSF(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement SIEM to OCSF mapping
	event.Severity = 50
}

func (n *Normalizer) mapCloudToOCSF(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement Cloud to OCSF mapping
	event.Severity = 30
}

func (n *Normalizer) mapDLPToOCSF(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement DLP to OCSF mapping
	event.Severity = 60
}

func (n *Normalizer) mapEDRToECS(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement EDR to ECS mapping
	event.Severity = 70
}

func (n *Normalizer) mapSIEMToECS(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement SIEM to ECS mapping
	event.Severity = 50
}

func (n *Normalizer) mapCloudToECS(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement Cloud to ECS mapping
	event.Severity = 30
}

func (n *Normalizer) mapDLPToECS(raw *ingestion.RawEvent, event *NormalizedEvent) {
	// TODO: Implement DLP to ECS mapping
	event.Severity = 60
}
