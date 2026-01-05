// Package correlation handles event correlation across sources
package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/lvonguyen/threat-telemetry-hub/internal/normalization"
)

// Correlator correlates events across sources
type Correlator struct {
	logger       *zap.Logger
	correlations map[string]*CorrelationGroup
	mu           sync.RWMutex
	ttl          time.Duration
}

// CorrelationGroup represents a group of related events
type CorrelationGroup struct {
	ID        string
	Events    []*normalization.NormalizedEvent
	CreatedAt time.Time
	UpdatedAt time.Time
	Keys      []string // Correlation keys (IPs, users, hosts)
}

// NewCorrelator creates a new correlator
func NewCorrelator(logger *zap.Logger) *Correlator {
	c := &Correlator{
		logger:       logger,
		correlations: make(map[string]*CorrelationGroup),
		ttl:          1 * time.Hour,
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// Correlate attempts to correlate an event with existing events
func (c *Correlator) Correlate(event *normalization.NormalizedEvent) string {
	keys := c.extractCorrelationKeys(event)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if event matches any existing correlation group
	for _, group := range c.correlations {
		if c.matchesGroup(keys, group) {
			group.Events = append(group.Events, event)
			group.UpdatedAt = time.Now()
			c.logger.Debug("Event correlated with existing group",
				zap.String("event_id", event.ID),
				zap.String("correlation_id", group.ID),
			)
			return group.ID
		}
	}

	// Create new correlation group
	groupID := c.generateCorrelationID(keys)
	c.correlations[groupID] = &CorrelationGroup{
		ID:        groupID,
		Events:    []*normalization.NormalizedEvent{event},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Keys:      keys,
	}

	c.logger.Debug("New correlation group created",
		zap.String("event_id", event.ID),
		zap.String("correlation_id", groupID),
	)

	return groupID
}

// extractCorrelationKeys extracts keys that can be used for correlation
func (c *Correlator) extractCorrelationKeys(event *normalization.NormalizedEvent) []string {
	keys := make([]string, 0)

	// Extract common correlation keys from event data
	if ip, ok := event.Data["source_ip"].(string); ok && ip != "" {
		keys = append(keys, "ip:"+ip)
	}
	if user, ok := event.Data["user"].(string); ok && user != "" {
		keys = append(keys, "user:"+user)
	}
	if host, ok := event.Data["hostname"].(string); ok && host != "" {
		keys = append(keys, "host:"+host)
	}
	if hash, ok := event.Data["file_hash"].(string); ok && hash != "" {
		keys = append(keys, "hash:"+hash)
	}
	if domain, ok := event.Data["domain"].(string); ok && domain != "" {
		keys = append(keys, "domain:"+domain)
	}

	return keys
}

// matchesGroup checks if keys match a correlation group
func (c *Correlator) matchesGroup(keys []string, group *CorrelationGroup) bool {
	for _, key := range keys {
		for _, groupKey := range group.Keys {
			if key == groupKey {
				return true
			}
		}
	}
	return false
}

// generateCorrelationID generates a unique correlation ID
func (c *Correlator) generateCorrelationID(keys []string) string {
	h := sha256.New()
	for _, key := range keys {
		h.Write([]byte(key))
	}
	h.Write([]byte(time.Now().String()))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// cleanup removes expired correlation groups
func (c *Correlator) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for id, group := range c.correlations {
			if now.Sub(group.UpdatedAt) > c.ttl {
				delete(c.correlations, id)
			}
		}
		c.mu.Unlock()
	}
}

// GetGroup returns a correlation group by ID
func (c *Correlator) GetGroup(id string) *CorrelationGroup {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.correlations[id]
}

// GetActiveGroups returns all active correlation groups
func (c *Correlator) GetActiveGroups() []*CorrelationGroup {
	c.mu.RLock()
	defer c.mu.RUnlock()

	groups := make([]*CorrelationGroup, 0, len(c.correlations))
	for _, group := range c.correlations {
		groups = append(groups, group)
	}
	return groups
}
