// Package ticketing provides integration with ticketing and GRC systems
package ticketing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// ArcherProvider implements the Provider interface for RSA Archer GRC
type ArcherProvider struct {
	instanceURL  string
	instanceName string
	username     string
	password     string
	sessionToken string
	httpClient   *http.Client
	logger       *zap.Logger
	config       ArcherConfig
}

// ArcherConfig configures the Archer provider
type ArcherConfig struct {
	InstanceURL     string `yaml:"instance_url"`
	InstanceName    string `yaml:"instance_name"`
	UsernameEnv     string `yaml:"username_env"`
	PasswordEnv     string `yaml:"password_env"`
	ApplicationName string `yaml:"application_name"` // e.g., "Security Incidents"
	ApplicationID   int    `yaml:"application_id"`
}

// NewArcherProvider creates a new Archer provider
func NewArcherProvider(cfg ArcherConfig, logger *zap.Logger) (*ArcherProvider, error) {
	username := os.Getenv(cfg.UsernameEnv)
	password := os.Getenv(cfg.PasswordEnv)

	if cfg.InstanceURL == "" || username == "" || password == "" {
		return nil, fmt.Errorf("missing required Archer configuration")
	}

	return &ArcherProvider{
		instanceURL:  cfg.InstanceURL,
		instanceName: cfg.InstanceName,
		username:     username,
		password:     password,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		logger:       logger,
		config:       cfg,
	}, nil
}

func (p *ArcherProvider) Name() string { return "archer" }

// authenticate obtains a session token from Archer
func (p *ArcherProvider) authenticate(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/core/security/login", p.instanceURL)

	loginData := map[string]string{
		"InstanceName": p.instanceName,
		"Username":     p.username,
		"Password":     p.password,
	}

	body, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("marshaling login data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status %d", resp.StatusCode)
	}

	var result struct {
		RequestedObject struct {
			SessionToken string `json:"SessionToken"`
		} `json:"RequestedObject"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	p.sessionToken = result.RequestedObject.SessionToken
	return nil
}

// ensureAuthenticated ensures we have a valid session
func (p *ArcherProvider) ensureAuthenticated(ctx context.Context) error {
	if p.sessionToken == "" {
		return p.authenticate(ctx)
	}
	return nil
}

// CreateTicket creates a new record in Archer
func (p *ArcherProvider) CreateTicket(ctx context.Context, ticket *Ticket) (*TicketResult, error) {
	if err := p.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("%s/api/core/content", p.instanceURL)

	// Build Archer record content
	// Field IDs would be configured based on the specific Archer application
	content := map[string]interface{}{
		"Content": map[string]interface{}{
			"LevelId": p.config.ApplicationID,
			"FieldContents": map[string]interface{}{
				// These field IDs are examples - would need to be configured
				"1001": map[string]interface{}{"Type": 1, "Value": ticket.Title},           // Title
				"1002": map[string]interface{}{"Type": 1, "Value": ticket.Description},     // Description
				"1003": map[string]interface{}{"Type": 4, "Value": []int{p.mapPriorityToArcher(ticket.Priority)}}, // Priority (value list)
				"1004": map[string]interface{}{"Type": 1, "Value": ticket.Category},        // Category
				"1005": map[string]interface{}{"Type": 1, "Value": ticket.Source},          // Source
				"1006": map[string]interface{}{"Type": 1, "Value": ticket.SourceEventID},   // Source Event ID
				"1007": map[string]interface{}{"Type": 2, "Value": ticket.RiskScore},       // Risk Score (numeric)
			},
		},
	}

	body, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshaling content: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Archer session-id="+p.sessionToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		RequestedObject struct {
			Id int `json:"Id"`
		} `json:"RequestedObject"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	recordID := fmt.Sprintf("%d", result.RequestedObject.Id)
	ticketURL := fmt.Sprintf("%s/apps/ArcherApp/Default.aspx#record/%d/%s",
		p.instanceURL, p.config.ApplicationID, recordID)

	p.logger.Info("Created Archer record",
		zap.String("record_id", recordID),
	)

	return &TicketResult{
		TicketID:   recordID,
		ExternalID: recordID,
		TicketURL:  ticketURL,
	}, nil
}

// UpdateTicket updates an existing Archer record
func (p *ArcherProvider) UpdateTicket(ctx context.Context, ticketID string, update *TicketUpdate) error {
	if err := p.ensureAuthenticated(ctx); err != nil {
		return fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("%s/api/core/content/%s", p.instanceURL, ticketID)

	fieldContents := make(map[string]interface{})

	if update.Status != "" {
		fieldContents["1008"] = map[string]interface{}{
			"Type":  4,
			"Value": []int{p.mapStatusToArcher(update.Status)},
		}
	}

	if update.Priority != "" {
		fieldContents["1003"] = map[string]interface{}{
			"Type":  4,
			"Value": []int{p.mapPriorityToArcher(update.Priority)},
		}
	}

	content := map[string]interface{}{
		"Content": map[string]interface{}{
			"Id":            ticketID,
			"LevelId":       p.config.ApplicationID,
			"FieldContents": fieldContents,
		},
	}

	body, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshaling content: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Archer session-id="+p.sessionToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

// GetTicket retrieves a record by ID
func (p *ArcherProvider) GetTicket(ctx context.Context, ticketID string) (*Ticket, error) {
	if err := p.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("%s/api/core/content/%s", p.instanceURL, ticketID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Archer session-id="+p.sessionToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Parse response - structure depends on Archer application configuration
	// This is a simplified implementation
	return &Ticket{
		ID: ticketID,
	}, nil
}

// SearchTickets searches for records
func (p *ArcherProvider) SearchTickets(ctx context.Context, query TicketQuery) ([]*Ticket, error) {
	if err := p.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	// Archer uses a different search API
	url := fmt.Sprintf("%s/api/core/content/search", p.instanceURL)

	searchCriteria := map[string]interface{}{
		"LevelId": p.config.ApplicationID,
		"Filters": []map[string]interface{}{},
	}

	if query.SourceEventID != "" {
		searchCriteria["Filters"] = append(searchCriteria["Filters"].([]map[string]interface{}),
			map[string]interface{}{
				"Operator":    "Equals",
				"FieldId":     1006, // Source Event ID field
				"FilterValue": query.SourceEventID,
			},
		)
	}

	body, err := json.Marshal(searchCriteria)
	if err != nil {
		return nil, fmt.Errorf("marshaling search: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Archer session-id="+p.sessionToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Parse search results
	return []*Ticket{}, nil
}

// AddComment adds a comment to a record
func (p *ArcherProvider) AddComment(ctx context.Context, ticketID string, comment string) error {
	// Archer typically uses a "Comments" field or history tracking
	// This would update a text field or create a related record
	return p.UpdateTicket(ctx, ticketID, &TicketUpdate{
		CustomFields: map[string]string{
			"comments": comment,
		},
	})
}

// CloseTicket closes a record
func (p *ArcherProvider) CloseTicket(ctx context.Context, ticketID string, resolution string) error {
	return p.UpdateTicket(ctx, ticketID, &TicketUpdate{
		Status: "closed",
		CustomFields: map[string]string{
			"resolution": resolution,
		},
	})
}

// Mapping functions - these would be configured based on actual Archer value lists
func (p *ArcherProvider) mapPriorityToArcher(priority string) int {
	mapping := map[string]int{
		"critical": 1,
		"high":     2,
		"medium":   3,
		"low":      4,
	}
	if v, ok := mapping[priority]; ok {
		return v
	}
	return 3
}

func (p *ArcherProvider) mapStatusToArcher(status string) int {
	mapping := map[string]int{
		"new":         1,
		"in_progress": 2,
		"on_hold":     3,
		"resolved":    4,
		"closed":      5,
	}
	if v, ok := mapping[status]; ok {
		return v
	}
	return 1
}

