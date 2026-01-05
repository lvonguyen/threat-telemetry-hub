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

// ServiceNowProvider implements the Provider interface for ServiceNow
type ServiceNowProvider struct {
	instanceURL string
	username    string
	password    string
	httpClient  *http.Client
	logger      *zap.Logger
	config      ServiceNowConfig
}

// ServiceNowConfig configures the ServiceNow provider
type ServiceNowConfig struct {
	InstanceURL    string `yaml:"instance_url"`
	UsernameEnv    string `yaml:"username_env"`
	PasswordEnv    string `yaml:"password_env"`
	DefaultTable   string `yaml:"default_table"`     // incident, sn_si_incident (SecOps)
	AssignmentGroup string `yaml:"assignment_group"`
	CallerID       string `yaml:"caller_id"`
}

// NewServiceNowProvider creates a new ServiceNow provider
func NewServiceNowProvider(cfg ServiceNowConfig, logger *zap.Logger) (*ServiceNowProvider, error) {
	username := os.Getenv(cfg.UsernameEnv)
	password := os.Getenv(cfg.PasswordEnv)

	if cfg.InstanceURL == "" || username == "" || password == "" {
		return nil, fmt.Errorf("missing required ServiceNow configuration")
	}

	if cfg.DefaultTable == "" {
		cfg.DefaultTable = "incident"
	}

	return &ServiceNowProvider{
		instanceURL: cfg.InstanceURL,
		username:    username,
		password:    password,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		logger:      logger,
		config:      cfg,
	}, nil
}

func (p *ServiceNowProvider) Name() string { return "servicenow" }

// CreateTicket creates a new incident in ServiceNow
func (p *ServiceNowProvider) CreateTicket(ctx context.Context, ticket *Ticket) (*TicketResult, error) {
	url := fmt.Sprintf("%s/api/now/table/%s", p.instanceURL, p.config.DefaultTable)

	// Map ticket to ServiceNow format
	snIncident := map[string]interface{}{
		"short_description": ticket.Title,
		"description":       ticket.Description,
		"urgency":           p.mapPriorityToUrgency(ticket.Priority),
		"impact":            p.mapSeverityToImpact(ticket.Severity),
		"category":          ticket.Category,
		"subcategory":       ticket.Subcategory,
		"assignment_group":  ticket.AssignmentGroup,
		"caller_id":         p.config.CallerID,
		"u_source":          ticket.Source,
		"u_source_event_id": ticket.SourceEventID,
	}

	// Add custom fields
	for k, v := range ticket.CustomFields {
		snIncident[k] = v
	}

	body, err := json.Marshal(snIncident)
	if err != nil {
		return nil, fmt.Errorf("marshaling incident: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.SetBasicAuth(p.username, p.password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	ticketURL := fmt.Sprintf("%s/nav_to.do?uri=%s.do?sys_id=%s",
		p.instanceURL, p.config.DefaultTable, result.Result.SysID)

	p.logger.Info("Created ServiceNow incident",
		zap.String("number", result.Result.Number),
		zap.String("sys_id", result.Result.SysID),
	)

	return &TicketResult{
		TicketID:   result.Result.SysID,
		ExternalID: result.Result.Number,
		TicketURL:  ticketURL,
	}, nil
}

// UpdateTicket updates an existing incident
func (p *ServiceNowProvider) UpdateTicket(ctx context.Context, ticketID string, update *TicketUpdate) error {
	url := fmt.Sprintf("%s/api/now/table/%s/%s", p.instanceURL, p.config.DefaultTable, ticketID)

	updateData := make(map[string]interface{})

	if update.Status != "" {
		updateData["state"] = p.mapStatusToState(update.Status)
	}
	if update.Priority != "" {
		updateData["urgency"] = p.mapPriorityToUrgency(update.Priority)
	}
	if update.AssignedTo != "" {
		updateData["assigned_to"] = update.AssignedTo
	}
	if update.Description != "" {
		updateData["work_notes"] = update.Description
	}

	for k, v := range update.CustomFields {
		updateData[k] = v
	}

	body, err := json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("marshaling update: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.SetBasicAuth(p.username, p.password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

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

// GetTicket retrieves an incident by ID
func (p *ServiceNowProvider) GetTicket(ctx context.Context, ticketID string) (*Ticket, error) {
	url := fmt.Sprintf("%s/api/now/table/%s/%s", p.instanceURL, p.config.DefaultTable, ticketID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.SetBasicAuth(p.username, p.password)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Result struct {
			SysID            string `json:"sys_id"`
			Number           string `json:"number"`
			ShortDescription string `json:"short_description"`
			Description      string `json:"description"`
			State            string `json:"state"`
			Urgency          string `json:"urgency"`
			Impact           string `json:"impact"`
			Category         string `json:"category"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &Ticket{
		ID:          result.Result.SysID,
		ExternalID:  result.Result.Number,
		Title:       result.Result.ShortDescription,
		Description: result.Result.Description,
		Status:      p.mapStateToStatus(result.Result.State),
		Priority:    p.mapUrgencyToPriority(result.Result.Urgency),
		Category:    result.Result.Category,
	}, nil
}

// SearchTickets searches for incidents
func (p *ServiceNowProvider) SearchTickets(ctx context.Context, query TicketQuery) ([]*Ticket, error) {
	url := fmt.Sprintf("%s/api/now/table/%s", p.instanceURL, p.config.DefaultTable)

	// Build query string
	sysparm := ""
	if query.SourceEventID != "" {
		sysparm += fmt.Sprintf("u_source_event_id=%s", query.SourceEventID)
	}
	if query.Status != "" {
		if sysparm != "" {
			sysparm += "^"
		}
		sysparm += fmt.Sprintf("state=%s", p.mapStatusToState(query.Status))
	}

	if sysparm != "" {
		url += "?sysparm_query=" + sysparm
	}
	if query.Limit > 0 {
		if sysparm != "" {
			url += "&"
		} else {
			url += "?"
		}
		url += fmt.Sprintf("sysparm_limit=%d", query.Limit)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.SetBasicAuth(p.username, p.password)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Result []struct {
			SysID            string `json:"sys_id"`
			Number           string `json:"number"`
			ShortDescription string `json:"short_description"`
			State            string `json:"state"`
			Urgency          string `json:"urgency"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	tickets := make([]*Ticket, 0, len(result.Result))
	for _, r := range result.Result {
		tickets = append(tickets, &Ticket{
			ID:         r.SysID,
			ExternalID: r.Number,
			Title:      r.ShortDescription,
			Status:     p.mapStateToStatus(r.State),
			Priority:   p.mapUrgencyToPriority(r.Urgency),
		})
	}

	return tickets, nil
}

// AddComment adds a work note to an incident
func (p *ServiceNowProvider) AddComment(ctx context.Context, ticketID string, comment string) error {
	return p.UpdateTicket(ctx, ticketID, &TicketUpdate{
		CustomFields: map[string]string{
			"work_notes": comment,
		},
	})
}

// CloseTicket closes an incident with resolution
func (p *ServiceNowProvider) CloseTicket(ctx context.Context, ticketID string, resolution string) error {
	return p.UpdateTicket(ctx, ticketID, &TicketUpdate{
		Status: "resolved",
		CustomFields: map[string]string{
			"close_notes":      resolution,
			"close_code":       "Solved (Permanently)",
			"resolution_notes": resolution,
		},
	})
}

// Mapping functions
func (p *ServiceNowProvider) mapPriorityToUrgency(priority string) string {
	mapping := map[string]string{
		"critical": "1",
		"high":     "2",
		"medium":   "3",
		"low":      "4",
	}
	if u, ok := mapping[priority]; ok {
		return u
	}
	return "3"
}

func (p *ServiceNowProvider) mapSeverityToImpact(severity string) string {
	mapping := map[string]string{
		"critical": "1",
		"high":     "2",
		"medium":   "3",
		"low":      "4",
	}
	if i, ok := mapping[severity]; ok {
		return i
	}
	return "3"
}

func (p *ServiceNowProvider) mapStatusToState(status string) string {
	mapping := map[string]string{
		"new":         "1",
		"in_progress": "2",
		"on_hold":     "3",
		"resolved":    "6",
		"closed":      "7",
	}
	if s, ok := mapping[status]; ok {
		return s
	}
	return "1"
}

func (p *ServiceNowProvider) mapStateToStatus(state string) string {
	mapping := map[string]string{
		"1": "new",
		"2": "in_progress",
		"3": "on_hold",
		"6": "resolved",
		"7": "closed",
	}
	if s, ok := mapping[state]; ok {
		return s
	}
	return "unknown"
}

func (p *ServiceNowProvider) mapUrgencyToPriority(urgency string) string {
	mapping := map[string]string{
		"1": "critical",
		"2": "high",
		"3": "medium",
		"4": "low",
	}
	if p, ok := mapping[urgency]; ok {
		return p
	}
	return "medium"
}

