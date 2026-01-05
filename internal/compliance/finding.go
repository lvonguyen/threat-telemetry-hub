// Package compliance provides finding schema and compliance mapping
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// FindingType categorizes the finding
type FindingType string

const (
	FindingTypeMisconfiguration     FindingType = "misconfiguration"
	FindingTypeVulnerability        FindingType = "vulnerability"
	FindingTypeThreatDetection      FindingType = "threat_detection"
	FindingTypeMalware              FindingType = "malware"
	FindingTypeCryptomining         FindingType = "cryptomining"
	FindingTypeDataExfiltration     FindingType = "data_exfiltration"
	FindingTypeIAMAnomaly           FindingType = "iam_anomaly"
	FindingTypeNetworkAnomaly       FindingType = "network_anomaly"
	FindingTypePrivilegeEscalation  FindingType = "privilege_escalation"
	FindingTypeCredentialAccess     FindingType = "credential_access"
	FindingTypeLateralMovement      FindingType = "lateral_movement"
	FindingTypeInitialAccess        FindingType = "initial_access"
	FindingTypePersistence          FindingType = "persistence"
	FindingTypeDefenseEvasion       FindingType = "defense_evasion"
	FindingTypeOSVulnerability      FindingType = "os_vulnerability"
	FindingTypeSoftwareVulnerability FindingType = "software_vulnerability"
	FindingTypeContainerVulnerability FindingType = "container_vulnerability"
)

// FindingCategory represents the high-level category
type FindingCategory string

const (
	CategoryThreat          FindingCategory = "THREAT"
	CategoryVulnerability   FindingCategory = "VULNERABILITY"
	CategoryAnomaly         FindingCategory = "ANOMALY"
	CategoryCompliance      FindingCategory = "COMPLIANCE"
	CategoryDataProtection  FindingCategory = "DATA_PROTECTION"
)

// ResourceType categorizes the resource
type ResourceType string

const (
	ResourceTypeCompute    ResourceType = "compute"
	ResourceTypeNetwork    ResourceType = "network"
	ResourceTypeStorage    ResourceType = "storage"
	ResourceTypeDatabase   ResourceType = "database"
	ResourceTypeIdentity   ResourceType = "identity"
	ResourceTypeContainer  ResourceType = "container"
	ResourceTypeEndpoint   ResourceType = "endpoint"
)

// Platform represents the infrastructure platform
type Platform string

const (
	PlatformOnPrem  Platform = "on-premises"
	PlatformCloud   Platform = "cloud"
	PlatformHybrid  Platform = "hybrid"
)

// CloudProvider represents a cloud provider
type CloudProvider string

const (
	CloudProviderAWS   CloudProvider = "aws"
	CloudProviderGCP   CloudProvider = "gcp"
	CloudProviderAzure CloudProvider = "azure"
	CloudProviderNone  CloudProvider = "none"
)

// EnvironmentType represents the environment
type EnvironmentType string

const (
	EnvProduction   EnvironmentType = "production"
	EnvStaging      EnvironmentType = "staging"
	EnvDevelopment  EnvironmentType = "development"
)

// WorkflowStatus represents the finding workflow status
type WorkflowStatus string

const (
	StatusNew          WorkflowStatus = "new"
	StatusTriaged      WorkflowStatus = "triaged"
	StatusAssigned     WorkflowStatus = "assigned"
	StatusInProgress   WorkflowStatus = "in_progress"
	StatusRemediated   WorkflowStatus = "remediated"
	StatusClosed       WorkflowStatus = "closed"
	StatusSuppressed   WorkflowStatus = "suppressed"
	StatusFalsePositive WorkflowStatus = "false_positive"
)

// Finding represents a comprehensive security finding
type Finding struct {
	// Core Identification
	ID              string      `json:"id"`
	Source          string      `json:"source"`
	SourceFindingID string      `json:"source_finding_id"`
	Type            FindingType `json:"type"`
	Category        FindingCategory `json:"category"`
	Title           string      `json:"title"`
	Description     string      `json:"description"`

	// Resource Information
	ResourceType  ResourceType  `json:"resource_type"`
	ResourceID    string        `json:"resource_id"`
	ResourceName  string        `json:"resource_name"`

	// On-Premises Identification
	Hostname     string `json:"hostname,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`

	// Platform & Environment
	Platform        Platform        `json:"platform"`
	CloudProvider   CloudProvider   `json:"cloud_provider"`
	Region          string          `json:"region"`
	AccountID       string          `json:"account_id"`
	EnvironmentType EnvironmentType `json:"environment_type"`

	// Severity & Risk
	StaticSeverity      string  `json:"static_severity"`
	Severity            string  `json:"severity"`
	AIRiskScore         float64 `json:"ai_risk_score"`
	AIRiskLevel         string  `json:"ai_risk_level"`
	AIRiskRationale     string  `json:"ai_risk_rationale"`
	AIContextualFactors []string `json:"ai_contextual_factors"`

	// CVE References
	CVEs []CVEReference `json:"cves,omitempty"`
	CWEs []string       `json:"cwes,omitempty"`

	// MITRE ATT&CK
	MITRETactics    []string `json:"mitre_tactics,omitempty"`
	MITRETechniques []string `json:"mitre_techniques,omitempty"`

	// Remediation
	Remediation      string   `json:"remediation"`
	RemediationSteps []string `json:"remediation_steps,omitempty"`

	// Workflow
	Status         string         `json:"status"`
	WorkflowStatus WorkflowStatus `json:"workflow_status"`
	Assignee       *AssigneeInfo  `json:"assignee,omitempty"`

	// Ownership
	TechnicalContact *Contact `json:"technical_contact,omitempty"`
	ServiceName      string   `json:"service_name"`
	LineOfBusiness   string   `json:"line_of_business"`
	Team             string   `json:"team,omitempty"`

	// Timestamps
	FirstFoundAt time.Time  `json:"first_found_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	DueDate      *time.Time `json:"due_date,omitempty"`

	// Deduplication
	DeduplicationKey string   `json:"deduplication_key"`
	CanonicalRuleID  string   `json:"canonical_rule_id"`
	RelatedRules     []string `json:"related_rules,omitempty"`

	// Ticketing
	TicketID     string `json:"ticket_id,omitempty"`
	TicketURL    string `json:"ticket_url,omitempty"`
	TicketStatus string `json:"ticket_status,omitempty"`

	// Raw Data
	RawData map[string]interface{} `json:"raw_data,omitempty"`
	Tags    map[string]string      `json:"tags,omitempty"`
}

// CVEReference represents a CVE with hyperlink
type CVEReference struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	NVDUrl      string    `json:"nvd_url"`
	Description string    `json:"description"`
	CVSS        float64   `json:"cvss"`
	CVSSVector  string    `json:"cvss_vector"`
	Published   time.Time `json:"published"`
}

// AssigneeInfo represents finding assignment
type AssigneeInfo struct {
	UserID     string     `json:"user_id"`
	UserEmail  string     `json:"user_email"`
	UserName   string     `json:"user_name"`
	Team       string     `json:"team"`
	AssignedAt time.Time  `json:"assigned_at"`
	AssignedBy string     `json:"assigned_by"`
	DueDate    *time.Time `json:"due_date,omitempty"`
}

// Contact represents a contact person
type Contact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Team  string `json:"team,omitempty"`
}

// GenerateDeduplicationKey generates a unique key for deduplication
func (f *Finding) GenerateDeduplicationKey() string {
	components := []string{
		string(f.ResourceType),
		f.ResourceID,
		f.CanonicalRuleID,
		f.Title,
	}
	for _, cve := range f.CVEs {
		components = append(components, cve.ID)
	}
	data := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// BuildCVEURLs populates CVE URLs
func (c *CVEReference) BuildCVEURLs() {
	if c.ID == "" {
		return
	}
	c.NVDUrl = "https://nvd.nist.gov/vuln/detail/" + c.ID
	c.URL = c.NVDUrl
}

// EnrichCVEReferences enriches CVE references with URLs
func (f *Finding) EnrichCVEReferences() {
	for i := range f.CVEs {
		f.CVEs[i].BuildCVEURLs()
	}
}

