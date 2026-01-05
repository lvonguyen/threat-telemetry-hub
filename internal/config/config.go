// Package config handles configuration loading for Threat Telemetry Hub
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	AI            AIConfig            `yaml:"ai"`
	Ingestion     IngestionConfig     `yaml:"ingestion"`
	Normalization NormalizationConfig `yaml:"normalization"`
	Enrichment    EnrichmentConfig    `yaml:"enrichment"`
	Output        OutputConfig        `yaml:"output"`
	DRBC          DRBCConfig          `yaml:"dr_bc"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Port         int    `yaml:"port"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
}

// AIConfig represents AI provider configuration
// Supports both Anthropic (Claude) and OpenAI for flexibility
type AIConfig struct {
	Provider  string          `yaml:"provider"` // "anthropic" or "openai"
	Anthropic AnthropicConfig `yaml:"anthropic"`
	OpenAI    OpenAIConfig    `yaml:"openai"`
}

// AnthropicConfig represents Anthropic Claude configuration
type AnthropicConfig struct {
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
}

// OpenAIConfig represents OpenAI configuration
type OpenAIConfig struct {
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
}

// IngestionConfig represents data ingestion sources
type IngestionConfig struct {
	EDR   EDRConfig   `yaml:"edr"`
	SIEM  SIEMConfig  `yaml:"siem"`
	Cloud CloudConfig `yaml:"cloud"`
	DLP   DLPConfig   `yaml:"dlp"`
}

// EDRConfig represents EDR tool integrations
type EDRConfig struct {
	CrowdStrike  CrowdStrikeConfig  `yaml:"crowdstrike"`
	SentinelOne  SentinelOneConfig  `yaml:"sentinelone"`
	Defender     DefenderConfig     `yaml:"defender"`
	CarbonBlack  CarbonBlackConfig  `yaml:"carbon_black"`
}

// CrowdStrikeConfig represents CrowdStrike Falcon configuration
type CrowdStrikeConfig struct {
	Enabled         bool   `yaml:"enabled"`
	APIURL          string `yaml:"api_url"`
	ClientIDEnv     string `yaml:"client_id_env"`
	ClientSecretEnv string `yaml:"client_secret_env"`
}

// SentinelOneConfig represents SentinelOne configuration
type SentinelOneConfig struct {
	Enabled     bool   `yaml:"enabled"`
	APIURL      string `yaml:"api_url"`
	APITokenEnv string `yaml:"api_token_env"`
}

// DefenderConfig represents Microsoft Defender for Endpoint configuration
type DefenderConfig struct {
	Enabled     bool   `yaml:"enabled"`
	TenantIDEnv string `yaml:"tenant_id_env"`
	ClientIDEnv string `yaml:"client_id_env"`
	SecretEnv   string `yaml:"secret_env"`
}

// CarbonBlackConfig represents VMware Carbon Black configuration
type CarbonBlackConfig struct {
	Enabled     bool   `yaml:"enabled"`
	APIURL      string `yaml:"api_url"`
	APIKeyEnv   string `yaml:"api_key_env"`
	APISecretEnv string `yaml:"api_secret_env"`
}

// SIEMConfig represents SIEM integrations
type SIEMConfig struct {
	Splunk        SplunkConfig        `yaml:"splunk"`
	Sentinel      SentinelConfig      `yaml:"sentinel"`
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
}

// SplunkConfig represents Splunk HEC configuration
type SplunkConfig struct {
	Enabled     bool   `yaml:"enabled"`
	HECURL      string `yaml:"hec_url"`
	HECTokenEnv string `yaml:"hec_token_env"`
}

// SentinelConfig represents Microsoft Sentinel configuration
type SentinelConfig struct {
	Enabled         bool   `yaml:"enabled"`
	WorkspaceID     string `yaml:"workspace_id"`
	SharedKeyEnv    string `yaml:"shared_key_env"`
}

// ElasticsearchConfig represents Elasticsearch configuration
type ElasticsearchConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Addresses []string `yaml:"addresses"`
	Username  string   `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
	Index     string   `yaml:"index"`
}

// CloudConfig represents cloud audit log sources
type CloudConfig struct {
	AWS   AWSCloudConfig   `yaml:"aws"`
	Azure AzureCloudConfig `yaml:"azure"`
	GCP   GCPCloudConfig   `yaml:"gcp"`
}

// AWSCloudConfig represents AWS CloudTrail configuration
type AWSCloudConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Region      string `yaml:"region"`
	RoleARN     string `yaml:"role_arn"`
	TrailName   string `yaml:"trail_name"`
}

// AzureCloudConfig represents Azure Activity Log configuration
type AzureCloudConfig struct {
	Enabled        bool   `yaml:"enabled"`
	SubscriptionID string `yaml:"subscription_id"`
	TenantIDEnv    string `yaml:"tenant_id_env"`
}

// GCPCloudConfig represents GCP Audit Log configuration
type GCPCloudConfig struct {
	Enabled   bool   `yaml:"enabled"`
	ProjectID string `yaml:"project_id"`
}

// DLPConfig represents DLP tool integrations (COTS aggregation)
type DLPConfig struct {
	DigitalGuardian DigitalGuardianConfig `yaml:"digital_guardian"`
	Proofpoint      ProofpointConfig      `yaml:"proofpoint"`
	Purview         PurviewConfig         `yaml:"purview"`
	Netskope        NetskopeConfig        `yaml:"netskope"`
}

// DigitalGuardianConfig represents Digital Guardian DLP configuration
type DigitalGuardianConfig struct {
	Enabled     bool   `yaml:"enabled"`
	APIURL      string `yaml:"api_url"`
	APIKeyEnv   string `yaml:"api_key_env"`
}

// ProofpointConfig represents Proofpoint DLP configuration
type ProofpointConfig struct {
	Enabled       bool   `yaml:"enabled"`
	APIURL        string `yaml:"api_url"`
	APIKeyEnv     string `yaml:"api_key_env"`
	WebhookSecret string `yaml:"webhook_secret_env"`
}

// PurviewConfig represents Microsoft Purview DLP configuration
type PurviewConfig struct {
	Enabled     bool   `yaml:"enabled"`
	TenantIDEnv string `yaml:"tenant_id_env"`
	ClientIDEnv string `yaml:"client_id_env"`
	SecretEnv   string `yaml:"secret_env"`
}

// NetskopeConfig represents Netskope DLP configuration
type NetskopeConfig struct {
	Enabled     bool   `yaml:"enabled"`
	TenantURL   string `yaml:"tenant_url"`
	APITokenEnv string `yaml:"api_token_env"`
}

// NormalizationConfig represents schema normalization settings
type NormalizationConfig struct {
	DefaultSchema string `yaml:"default_schema"` // "ocsf" or "ecs"
}

// EnrichmentConfig represents enrichment sources
type EnrichmentConfig struct {
	ThreatForge ThreatForgeConfig `yaml:"threatforge"`
	Identity    IdentityConfig    `yaml:"identity"`
	Asset       AssetConfig       `yaml:"asset"`
}

// ThreatForgeConfig represents threatforge integration
type ThreatForgeConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIURL  string `yaml:"api_url"`
}

// IdentityConfig represents identity enrichment sources
type IdentityConfig struct {
	EntraID EntraIDConfig `yaml:"entra_id"`
	Okta    OktaConfig    `yaml:"okta"`
}

// EntraIDConfig represents Microsoft Entra ID configuration
type EntraIDConfig struct {
	Enabled     bool   `yaml:"enabled"`
	TenantIDEnv string `yaml:"tenant_id_env"`
	ClientIDEnv string `yaml:"client_id_env"`
	SecretEnv   string `yaml:"secret_env"`
}

// OktaConfig represents Okta configuration
type OktaConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Domain      string `yaml:"domain"`
	APITokenEnv string `yaml:"api_token_env"`
}

// AssetConfig represents asset/CMDB enrichment
type AssetConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIURL  string `yaml:"api_url"`
}

// OutputConfig represents output destinations
type OutputConfig struct {
	Splunk        SplunkOutputConfig        `yaml:"splunk"`
	Elasticsearch ElasticsearchOutputConfig `yaml:"elasticsearch"`
}

// SplunkOutputConfig represents Splunk HEC output
type SplunkOutputConfig struct {
	Enabled     bool   `yaml:"enabled"`
	HECURL      string `yaml:"hec_url"`
	HECTokenEnv string `yaml:"hec_token_env"`
	Index       string `yaml:"index"`
	SourceType  string `yaml:"sourcetype"`
}

// ElasticsearchOutputConfig represents Elasticsearch output
type ElasticsearchOutputConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Addresses []string `yaml:"addresses"`
	Index     string   `yaml:"index"`
}

// DRBCConfig represents DR/BC configuration
type DRBCConfig struct {
	Enabled        bool   `yaml:"enabled"`
	PrimaryRegion  string `yaml:"primary_region"`
	FailoverRegion string `yaml:"failover_region"`
	RPOMinutes     int    `yaml:"rpo_minutes"`
	RTOMinutes     int    `yaml:"rto_minutes"`
}

// Load reads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Set defaults
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.AI.Provider == "" {
		cfg.AI.Provider = "anthropic"
	}
	if cfg.AI.Anthropic.Model == "" {
		cfg.AI.Anthropic.Model = "claude-opus-4-5-20250514"
	}
	if cfg.AI.OpenAI.Model == "" {
		cfg.AI.OpenAI.Model = "gpt-4-turbo"
	}
	if cfg.Normalization.DefaultSchema == "" {
		cfg.Normalization.DefaultSchema = "ocsf"
	}

	return &cfg, nil
}

