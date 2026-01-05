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

// OpenAIProvider implements the Provider interface for OpenAI
type OpenAIProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(cfg config.OpenAIConfig, logger *zap.Logger) (*OpenAIProvider, error) {
	apiKey := os.Getenv(cfg.APIKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("API key environment variable %s not set", cfg.APIKeyEnv)
	}

	return &OpenAIProvider{
		apiKey: apiKey,
		model:  cfg.Model,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		logger: logger,
	}, nil
}

// Name returns the provider name
func (p *OpenAIProvider) Name() string {
	return "openai"
}

// Analyze performs AI analysis using OpenAI
func (p *OpenAIProvider) Analyze(ctx context.Context, prompt string) (*Response, error) {
	requestBody := map[string]interface{}{
		"model":      p.model,
		"max_tokens": 4096,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a security analyst AI. Analyze security telemetry events and provide risk assessments in JSON format.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"response_format": map[string]string{
			"type": "json_object",
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("empty response from API")
	}

	return &Response{
		Content: result.Choices[0].Message.Content,
		Model:   p.model,
		Usage: Usage{
			InputTokens:  result.Usage.PromptTokens,
			OutputTokens: result.Usage.CompletionTokens,
		},
	}, nil
}

