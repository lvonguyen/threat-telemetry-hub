// Package ticketing provides integration with ticketing and GRC systems
package ticketing

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Provider defines the interface for ticketing systems
type Provider interface {
	// Name returns the provider name
	Name() string

	// CreateTicket creates a new ticket/incident
	CreateTicket(ctx context.Context, ticket *Ticket) (*TicketResult, error)

	// UpdateTicket updates an existing ticket
	UpdateTicket(ctx context.Context, ticketID string, update *TicketUpdate) error

	// GetTicket retrieves a ticket by ID
	GetTicket(ctx context.Context, ticketID string) (*Ticket, error)

	// SearchTickets searches for tickets
	SearchTickets(ctx context.Context, query TicketQuery) ([]*Ticket, error)

	// AddComment adds a comment to a ticket
	AddComment(ctx context.Context, ticketID string, comment string) error

	// Close closes a ticket
	CloseTicket(ctx context.Context, ticketID string, resolution string) error
}

// Ticket represents a ticket/incident
type Ticket struct {
	ID              string            `json:"id,omitempty"`
	ExternalID      string            `json:"external_id,omitempty"`
	Type            string            `json:"type"`               // incident, problem, change, risk
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Priority        string            `json:"priority"`           // critical, high, medium, low
	Severity        string            `json:"severity"`
	Status          string            `json:"status"`
	AssignmentGroup string            `json:"assignment_group"`
	AssignedTo      string            `json:"assigned_to,omitempty"`
	Category        string            `json:"category"`
	Subcategory     string            `json:"subcategory,omitempty"`
	Source          string            `json:"source"`             // threat-telemetry-hub
	SourceEventID   string            `json:"source_event_id"`
	RiskScore       float64           `json:"risk_score,omitempty"`
	MITRETactics    []string          `json:"mitre_tactics,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty"`
	AffectedAssets  []string          `json:"affected_assets,omitempty"`
	Remediation     string            `json:"remediation,omitempty"`
	DueDate         *time.Time        `json:"due_date,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	ClosedAt        *time.Time        `json:"closed_at,omitempty"`
	CustomFields    map[string]string `json:"custom_fields,omitempty"`
}

// TicketResult represents the result of ticket creation
type TicketResult struct {
	TicketID   string `json:"ticket_id"`
	TicketURL  string `json:"ticket_url"`
	ExternalID string `json:"external_id"`
}

// TicketUpdate represents updates to a ticket
type TicketUpdate struct {
	Status       string            `json:"status,omitempty"`
	Priority     string            `json:"priority,omitempty"`
	AssignedTo   string            `json:"assigned_to,omitempty"`
	Description  string            `json:"description,omitempty"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
}

// TicketQuery for searching tickets
type TicketQuery struct {
	Status        string    `json:"status,omitempty"`
	Priority      string    `json:"priority,omitempty"`
	Category      string    `json:"category,omitempty"`
	SourceEventID string    `json:"source_event_id,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	Limit         int       `json:"limit,omitempty"`
}

// Manager manages ticketing providers
type Manager struct {
	providers map[string]Provider
	logger    *zap.Logger
	config    ManagerConfig
}

// ManagerConfig configures the ticketing manager
type ManagerConfig struct {
	DefaultProvider  string            `yaml:"default_provider"`
	AutoCreateTicket bool              `yaml:"auto_create_ticket"`
	MinRiskScore     float64           `yaml:"min_risk_score"`     // Only create tickets above this score
	PriorityMapping  map[string]string `yaml:"priority_mapping"`   // risk_level -> priority
	AssignmentRules  []AssignmentRule  `yaml:"assignment_rules"`
}

// AssignmentRule defines rules for ticket assignment
type AssignmentRule struct {
	Condition       string `yaml:"condition"`        // e.g., "category == 'malware'"
	AssignmentGroup string `yaml:"assignment_group"`
}

// NewManager creates a new ticketing manager
func NewManager(cfg ManagerConfig, logger *zap.Logger) *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		logger:    logger,
		config:    cfg,
	}
}

// RegisterProvider registers a ticketing provider
func (m *Manager) RegisterProvider(provider Provider) {
	m.providers[provider.Name()] = provider
	m.logger.Info("Registered ticketing provider",
		zap.String("provider", provider.Name()),
	)
}

// GetProvider returns a provider by name
func (m *Manager) GetProvider(name string) (Provider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// CreateTicketForEvent creates a ticket for a security event
func (m *Manager) CreateTicketForEvent(ctx context.Context, event *SecurityEvent) (*TicketResult, error) {
	// Check if auto-create is enabled and risk score meets threshold
	if !m.config.AutoCreateTicket {
		return nil, nil
	}

	if event.RiskScore < m.config.MinRiskScore {
		m.logger.Debug("Event risk score below threshold, skipping ticket creation",
			zap.String("event_id", event.ID),
			zap.Float64("risk_score", event.RiskScore),
			zap.Float64("threshold", m.config.MinRiskScore),
		)
		return nil, nil
	}

	// Get default provider
	provider, ok := m.providers[m.config.DefaultProvider]
	if !ok {
		m.logger.Warn("Default ticketing provider not found",
			zap.String("provider", m.config.DefaultProvider),
		)
		return nil, nil
	}

	// Map event to ticket
	ticket := m.eventToTicket(event)

	// Create ticket
	result, err := provider.CreateTicket(ctx, ticket)
	if err != nil {
		return nil, err
	}

	m.logger.Info("Created ticket for security event",
		zap.String("event_id", event.ID),
		zap.String("ticket_id", result.TicketID),
		zap.String("provider", provider.Name()),
	)

	return result, nil
}

// SecurityEvent represents a security event that may need a ticket
type SecurityEvent struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Source          string                 `json:"source"`
	Timestamp       time.Time              `json:"timestamp"`
	RiskScore       float64                `json:"risk_score"`
	RiskLevel       string                 `json:"risk_level"`
	Summary         string                 `json:"summary"`
	Description     string                 `json:"description"`
	MITRETactics    []string               `json:"mitre_tactics"`
	MITRETechniques []string               `json:"mitre_techniques"`
	AffectedAssets  []string               `json:"affected_assets"`
	Recommendations []string               `json:"recommendations"`
	RawData         map[string]interface{} `json:"raw_data"`
}

func (m *Manager) eventToTicket(event *SecurityEvent) *Ticket {
	// Map risk level to priority
	priority := "medium"
	if p, ok := m.config.PriorityMapping[event.RiskLevel]; ok {
		priority = p
	}

	// Determine assignment group based on rules
	assignmentGroup := "Security Operations"
	for _, rule := range m.config.AssignmentRules {
		// Simplified rule matching - would need proper expression evaluation
		if rule.Condition == "default" {
			assignmentGroup = rule.AssignmentGroup
		}
	}

	// Build description
	description := event.Description
	if len(event.Recommendations) > 0 {
		description += "\n\nRecommendations:\n"
		for _, rec := range event.Recommendations {
			description += "- " + rec + "\n"
		}
	}

	return &Ticket{
		Type:            "incident",
		Title:           event.Summary,
		Description:     description,
		Priority:        priority,
		Severity:        event.RiskLevel,
		Status:          "new",
		AssignmentGroup: assignmentGroup,
		Category:        "Security",
		Subcategory:     event.Type,
		Source:          "threat-telemetry-hub",
		SourceEventID:   event.ID,
		RiskScore:       event.RiskScore,
		MITRETactics:    event.MITRETactics,
		MITRETechniques: event.MITRETechniques,
		AffectedAssets:  event.AffectedAssets,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

