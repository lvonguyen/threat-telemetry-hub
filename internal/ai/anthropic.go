// Package ai provides AI-powered analysis for security telemetry
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/lvonguyen/threat-telemetry-hub/internal/config"
)

// AnthropicProvider implements the Provider interface for Anthropic Claude
type AnthropicProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewAnthropicProvider creates a new Anthropic provider
func NewAnthropicProvider(cfg config.AnthropicConfig, logger *zap.Logger) (*AnthropicProvider, error) {
	apiKey := os.Getenv(cfg.APIKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("API key environment variable %s not set", cfg.APIKeyEnv)
	}

	return &AnthropicProvider{
		apiKey: apiKey,
		model:  cfg.Model,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		logger: logger,
	}, nil
}

// Name returns the provider name
func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

// Analyze performs AI analysis using Claude
func (p *AnthropicProvider) Analyze(ctx context.Context, prompt string) (*Response, error) {
	requestBody := map[string]interface{}{
		"model":      p.model,
		"max_tokens": 4096,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("empty response from API")
	}

	return &Response{
		Content: result.Content[0].Text,
		Model:   p.model,
		Usage: Usage{
			InputTokens:  result.Usage.InputTokens,
			OutputTokens: result.Usage.OutputTokens,
		},
	}, nil
}

