package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OpenAICompatConfig configures an OpenAI-compatible chat backend. The same shape
// serves a local vLLM / llama.cpp server / KoboldCpp / Ollama (OpenAI endpoint)
// and a cloud gateway — only BaseURL, Model and (optionally) APIKey differ. This
// is why the rest of the system needs exactly one Provider implementation.
type OpenAICompatConfig struct {
	// BaseURL is the API root, e.g. "http://127.0.0.1:8000/v1". The client posts
	// to BaseURL + "/chat/completions".
	BaseURL string
	// Model is the served model name; the Go program treats it as an opaque label.
	Model string
	// APIKey is optional; local servers ignore it. Sent as a Bearer token when set.
	APIKey string
	// Timeout bounds a single request (default 60s).
	Timeout time.Duration
	// HTTPClient is optional; a dedicated client is built when nil. NOTE: this is
	// the infrastructure client for the model endpoint, deliberately separate from
	// internal/httpx (which probes scan targets under a policy allowlist). The
	// model endpoint is not a scan target.
	HTTPClient *http.Client
	// MaxCompletionTokens caps the reply length per call (default 1024).
	MaxCompletionTokens int
}

type openAICompat struct {
	cfg     OpenAICompatConfig
	client  *http.Client
	tracker *Tracker
	name    string
}

// NewOpenAICompat builds an OpenAI-compatible Provider. tracker may be nil (no
// budget). It validates the base URL up front so a misconfiguration fails before
// any request.
func NewOpenAICompat(cfg OpenAICompatConfig, tracker *Tracker) (Provider, error) {
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("ai: BaseURL must be an absolute http(s) URL, e.g. http://127.0.0.1:8000/v1")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("ai: Model is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.MaxCompletionTokens <= 0 {
		cfg.MaxCompletionTokens = 1024
	}
	cfg.BaseURL = u.String()
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &openAICompat{cfg: cfg, client: client, tracker: tracker, name: "openai-compat:" + cfg.Model}, nil
}

func (p *openAICompat) Name() string { return p.name }

// chat request/response types (the subset we use of the OpenAI chat schema).
type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []Message       `json:"messages"`
	Temperature    float64         `json:"temperature"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (p *openAICompat) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResult, error) {
	if !req.Task.valid() {
		return nil, fmt.Errorf("ai: unknown task %q", req.Task)
	}
	if p.tracker != nil {
		if err := p.tracker.Reserve(); err != nil {
			return nil, err
		}
	}
	body, err := json.Marshal(chatRequest{
		Model:          p.cfg.Model,
		Messages:       BuildMessages(req),
		Temperature:    0, // determinism: we want stable, low-creativity analysis
		MaxTokens:      p.cfg.MaxCompletionTokens,
		ResponseFormat: &responseFormat{Type: "json_object"},
	})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ai: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("ai: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ai: backend returned HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return nil, fmt.Errorf("ai: malformed chat response: %w", err)
	}
	if len(cr.Choices) == 0 {
		return nil, errors.New("ai: backend returned no choices")
	}
	result, err := parseResult(cr.Choices[0].Message.Content)
	if err != nil {
		return nil, err
	}
	result.Usage = Usage{Requests: 1, PromptTokens: cr.Usage.PromptTokens, CompletionTokens: cr.Usage.CompletionTokens}
	if p.tracker != nil {
		p.tracker.Record(result.Usage)
	}
	return result, nil
}

// parseResult extracts the AnalysisResult from a model reply. Backends that honor
// response_format return a bare JSON object; others may wrap it in prose or code
// fences, so we fall back to the first balanced {...} object. Unknown fields
// (including any invented "verdict"/"state") are dropped by json.Unmarshal, so a
// misbehaving model cannot smuggle a decision through.
func parseResult(content string) (*AnalysisResult, error) {
	content = strings.TrimSpace(content)
	var r AnalysisResult
	if json.Unmarshal([]byte(content), &r) == nil {
		return &r, nil
	}
	if obj := firstJSONObject(content); obj != "" {
		if err := json.Unmarshal([]byte(obj), &r); err == nil {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("ai: model reply was not JSON matching the result schema: %s", truncate(content, 200))
}

// firstJSONObject returns the first brace-balanced JSON object in s, ignoring
// braces inside strings. Empty string if none.
func firstJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
			// skip
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
