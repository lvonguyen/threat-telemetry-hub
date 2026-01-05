// Package observability provides logging, metrics, and tracing capabilities
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthChecker provides application health monitoring
type HealthChecker struct {
	checks     map[string]HealthCheck
	mu         sync.RWMutex
	logger     *zap.Logger
	lastStatus *HealthStatus
	telemetry  *Telemetry
}

// HealthCheck defines a health check function
type HealthCheck struct {
	Name     string
	Check    func(ctx context.Context) error
	Timeout  time.Duration
	Critical bool // If true, failure makes the app unhealthy
}

// HealthStatus represents overall health status
type HealthStatus struct {
	Status     string                     `json:"status"` // healthy, degraded, unhealthy
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version"`
	Uptime     string                     `json:"uptime"`
	Components map[string]ComponentHealth `json:"components"`
	Pipeline   PipelineHealth             `json:"pipeline"`
}

// ComponentHealth represents health of a single component
type ComponentHealth struct {
	Status      string        `json:"status"` // healthy, unhealthy
	Message     string        `json:"message,omitempty"`
	LastChecked time.Time     `json:"last_checked"`
	Latency     time.Duration `json:"latency_ms"`
}

// PipelineHealth represents the health of the data pipeline
type PipelineHealth struct {
	EventsPerSecond float64            `json:"events_per_second"`
	QueueDepth      map[string]int64   `json:"queue_depth"`
	CollectorStatus map[string]string  `json:"collector_status"`
	LastEventTime   time.Time          `json:"last_event_time"`
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *zap.Logger, telemetry *Telemetry) *HealthChecker {
	return &HealthChecker{
		checks:    make(map[string]HealthCheck),
		logger:    logger,
		telemetry: telemetry,
	}
}

// RegisterCheck registers a health check
func (h *HealthChecker) RegisterCheck(check HealthCheck) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if check.Timeout == 0 {
		check.Timeout = 5 * time.Second
	}
	h.checks[check.Name] = check
}

// RegisterCollectorCheck registers a collector health check
func (h *HealthChecker) RegisterCollectorCheck(name, endpoint string) {
	h.RegisterCheck(HealthCheck{
		Name:     "collector_" + name,
		Critical: false, // Individual collectors are not critical
		Timeout:  10 * time.Second,
		Check: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/health", nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				return fmt.Errorf("collector unhealthy: HTTP %d", resp.StatusCode)
			}
			return nil
		},
	})
}

// Check performs all health checks
func (h *HealthChecker) Check(ctx context.Context) *HealthStatus {
	h.mu.RLock()
	checks := make(map[string]HealthCheck, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	status := &HealthStatus{
		Status:     "healthy",
		Timestamp:  time.Now(),
		Components: make(map[string]ComponentHealth),
		Pipeline: PipelineHealth{
			QueueDepth:      make(map[string]int64),
			CollectorStatus: make(map[string]string),
		},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, check := range checks {
		wg.Add(1)
		go func(c HealthCheck) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, c.Timeout)
			defer cancel()

			start := time.Now()
			err := c.Check(checkCtx)
			latency := time.Since(start)

			health := ComponentHealth{
				Status:      "healthy",
				LastChecked: time.Now(),
				Latency:     latency,
			}

			if err != nil {
				health.Status = "unhealthy"
				health.Message = err.Error()

				h.logger.Warn("Health check failed",
					zap.String("component", c.Name),
					zap.Error(err),
					zap.Duration("latency", latency),
				)

				// Update metrics
				if h.telemetry != nil && h.telemetry.Metrics() != nil {
					h.telemetry.Metrics().HealthStatus.WithLabelValues(c.Name).Set(0)
				}
			} else {
				if h.telemetry != nil && h.telemetry.Metrics() != nil {
					h.telemetry.Metrics().HealthStatus.WithLabelValues(c.Name).Set(1)
				}
			}

			mu.Lock()
			status.Components[c.Name] = health

			// Update overall status
			if health.Status == "unhealthy" {
				if c.Critical {
					status.Status = "unhealthy"
				} else if status.Status == "healthy" {
					status.Status = "degraded"
				}
			}
			mu.Unlock()
		}(check)
	}

	wg.Wait()

	// Update metrics
	if h.telemetry != nil && h.telemetry.Metrics() != nil {
		h.telemetry.Metrics().LastHealthCheck.SetToCurrentTime()
	}

	h.mu.Lock()
	h.lastStatus = status
	h.mu.Unlock()

	return status
}

// LivenessHandler returns an HTTP handler for liveness probes
func (h *HealthChecker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "alive",
			"time":   time.Now().Format(time.RFC3339),
		})
	}
}

// ReadinessHandler returns an HTTP handler for readiness probes
func (h *HealthChecker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		if status.Status == "unhealthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(status)
	}
}

// HealthHandler returns an HTTP handler for detailed health info
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		switch status.Status {
		case "healthy":
			w.WriteHeader(http.StatusOK)
		case "degraded":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(status)
	}
}

// Troubleshooting provides common issue detection and remediation
type Troubleshooting struct {
	logger *zap.Logger
}

// CommonIssue represents a detected issue
type CommonIssue struct {
	Component   string   `json:"component"`
	Issue       string   `json:"issue"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Remediation []string `json:"remediation_steps"`
	KBArticle   string   `json:"kb_article,omitempty"`
}

// NewTroubleshooting creates a new troubleshooting helper
func NewTroubleshooting(logger *zap.Logger) *Troubleshooting {
	return &Troubleshooting{logger: logger}
}

// DiagnoseHealthStatus analyzes health status and provides remediation
func (t *Troubleshooting) DiagnoseHealthStatus(status *HealthStatus) []CommonIssue {
	var issues []CommonIssue

	for name, component := range status.Components {
		if component.Status != "healthy" {
			issue := t.diagnoseComponent(name, component)
			if issue != nil {
				issues = append(issues, *issue)
			}
		}
	}

	return issues
}

func (t *Troubleshooting) diagnoseComponent(name string, health ComponentHealth) *CommonIssue {
	switch {
	case name == "crowdstrike" || name == "sentinelone" || name == "collector_edr":
		return t.diagnoseEDRCollectorIssue(name, health)
	case name == "splunk" || name == "collector_siem":
		return t.diagnoseSIEMCollectorIssue(health)
	case name == "ai_provider" || name == "anthropic" || name == "openai":
		return t.diagnoseAIProviderIssue(health)
	case name == "servicenow" || name == "archer":
		return t.diagnoseTicketingIssue(name, health)
	default:
		return &CommonIssue{
			Component:   name,
			Issue:       "Component unhealthy",
			Severity:    "high",
			Description: health.Message,
			Remediation: []string{
				"Check component logs for errors",
				"Verify network connectivity to the component",
				"Check component resource utilization (CPU, memory)",
				"Restart the component if other checks pass",
			},
		}
	}
}

func (t *Troubleshooting) diagnoseEDRCollectorIssue(name string, health ComponentHealth) *CommonIssue {
	return &CommonIssue{
		Component:   name,
		Issue:       "EDR collector connection failure",
		Severity:    "high",
		Description: health.Message,
		Remediation: []string{
			"1. Verify EDR API credentials are valid and not expired",
			"2. Check EDR console for API rate limiting",
			"3. Verify network connectivity to EDR API endpoint",
			"4. Check firewall rules allow outbound HTTPS",
			"5. For CrowdStrike: Verify OAuth2 client ID/secret",
			"6. For SentinelOne: Verify API token and site ID",
			"7. Test API connectivity: `curl -H 'Authorization: Bearer $TOKEN' $API_URL/health`",
			"8. Check EDR vendor status page for outages",
		},
		KBArticle: "https://docs.threat-telemetry-hub.io/troubleshooting/edr-collectors",
	}
}

func (t *Troubleshooting) diagnoseSIEMCollectorIssue(health ComponentHealth) *CommonIssue {
	return &CommonIssue{
		Component:   "siem",
		Issue:       "SIEM collector connection failure",
		Severity:    "high",
		Description: health.Message,
		Remediation: []string{
			"1. Verify Splunk HEC token is valid",
			"2. Check Splunk indexer is running and accepting data",
			"3. Verify network connectivity to Splunk endpoint",
			"4. Check HEC port (8088 default) is open",
			"5. Verify SSL certificate if using HTTPS",
			"6. Check Splunk license for data ingestion limits",
			"7. Review Splunk internal logs: /opt/splunk/var/log/splunk/",
			"8. Test HEC: `curl -k https://splunk:8088/services/collector/health`",
		},
		KBArticle: "https://docs.threat-telemetry-hub.io/troubleshooting/siem-collectors",
	}
}

func (t *Troubleshooting) diagnoseAIProviderIssue(health ComponentHealth) *CommonIssue {
	return &CommonIssue{
		Component:   "ai_provider",
		Issue:       "AI provider connection failure",
		Severity:    "medium",
		Description: health.Message,
		Remediation: []string{
			"1. Verify API key is set: ANTHROPIC_API_KEY or OPENAI_API_KEY",
			"2. Check API key validity at provider dashboard",
			"3. Verify rate limits haven't been exceeded",
			"4. Check network allows outbound HTTPS to api.anthropic.com or api.openai.com",
			"5. Test connectivity: `curl -I https://api.anthropic.com`",
			"6. Check for provider status at status.anthropic.com or status.openai.com",
			"7. If rate limited, enable cached responses or upgrade plan",
			"8. Consider enabling fallback provider in config",
		},
		KBArticle: "https://docs.threat-telemetry-hub.io/troubleshooting/ai-provider",
	}
}

func (t *Troubleshooting) diagnoseTicketingIssue(name string, health ComponentHealth) *CommonIssue {
	return &CommonIssue{
		Component:   name,
		Issue:       "Ticketing system connection failure",
		Severity:    "medium",
		Description: health.Message,
		Remediation: []string{
			"1. Verify ServiceNow/Archer credentials are valid",
			"2. Check API endpoint URL is correct",
			"3. Verify OAuth tokens haven't expired",
			"4. Check network connectivity to ticketing system",
			"5. Verify required fields/tables exist in target system",
			"6. Review ticketing system for API rate limiting",
			"7. Check ticketing system logs for authentication errors",
			"8. Test API manually with curl or Postman",
		},
		KBArticle: "https://docs.threat-telemetry-hub.io/troubleshooting/ticketing",
	}
}

// GetCommonRemediations returns common remediation patterns
func (t *Troubleshooting) GetCommonRemediations() map[string][]string {
	return map[string][]string{
		"collector_timeout": {
			"Increase collector timeout in config",
			"Check network latency to source system",
			"Verify source system is not overloaded",
			"Consider pagination for large data pulls",
		},
		"queue_backlog": {
			"Check processing rate vs ingestion rate",
			"Scale horizontally if processing is bottleneck",
			"Reduce batch sizes for faster processing",
			"Check for slow downstream dependencies",
		},
		"ai_rate_limit": {
			"Enable response caching to reduce API calls",
			"Implement request queuing with backoff",
			"Consider upgrading API tier",
			"Enable fallback to static analysis",
		},
		"event_normalization_failure": {
			"Check source event schema against expected format",
			"Review normalization rules for this event type",
			"Check for null/missing required fields",
			"Add schema validation logging",
		},
		"correlation_failure": {
			"Check correlation rule syntax",
			"Verify required event types are being ingested",
			"Check time window configuration",
			"Review correlation rule dependencies",
		},
	}
}

