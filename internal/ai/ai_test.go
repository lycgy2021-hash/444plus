package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBudgetTracker(t *testing.T) {
	tr := NewTracker(Budget{MaxRequests: 2})
	if err := tr.Reserve(); err != nil {
		t.Fatalf("reserve 1: %v", err)
	}
	tr.Record(Usage{PromptTokens: 10, CompletionTokens: 5})
	if err := tr.Reserve(); err != nil {
		t.Fatalf("reserve 2: %v", err)
	}
	if err := tr.Reserve(); err == nil {
		t.Fatal("third reserve should exceed MaxRequests")
	}
	if u := tr.Used(); u.Requests != 2 || u.PromptTokens != 10 || u.CompletionTokens != 5 {
		t.Fatalf("usage = %+v", u)
	}

	// Token cap.
	tr2 := NewTracker(Budget{MaxPromptTokens: 100})
	_ = tr2.Reserve()
	tr2.Record(Usage{PromptTokens: 100})
	if err := tr2.Reserve(); err == nil {
		t.Fatal("reserve should exceed MaxPromptTokens")
	}

	// Wall clock.
	tr3 := NewTracker(Budget{MaxWallClock: time.Nanosecond})
	time.Sleep(time.Millisecond)
	if err := tr3.Reserve(); err == nil {
		t.Fatal("reserve should exceed MaxWallClock")
	}
}

func TestBuildMessagesEnforcesBoundaryInPrompt(t *testing.T) {
	msgs := BuildMessages(AnalysisRequest{Task: TaskFindingAnalysis, Target: "http://t", Payload: json.RawMessage(`{"x":1}`)})
	if len(msgs) != 2 || msgs[0].Role != "system" || msgs[1].Role != "user" {
		t.Fatalf("unexpected messages: %+v", msgs)
	}
	sys := msgs[0].Content
	for _, must := range []string{"do NOT decide", "MUST NOT", "confirmed", "proposals", "missing_evidence"} {
		if !strings.Contains(sys, must) {
			t.Errorf("system prompt missing %q", must)
		}
	}
	if !strings.Contains(msgs[1].Content, `{"x":1}`) {
		t.Error("user message missing payload")
	}
}

// fakeBackend serves an OpenAI-compatible chat-completions reply whose content is
// the given model output.
func fakeBackend(t *testing.T, content string, promptTok, compTok int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			w.WriteHeader(404)
			return
		}
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Temperature != 0 {
			t.Errorf("expected temperature 0, got %v", req.Temperature)
		}
		resp := map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": content}}},
			"usage":   map[string]int{"prompt_tokens": promptTok, "completion_tokens": compTok},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestOpenAICompatAnalyzeParsesProposals(t *testing.T) {
	// A well-behaved model reply — and note the sneaky "verdict" key, which must be
	// dropped because AnalysisResult has no such field.
	content := `{"proposals":[{"candidate_type":"path_normalization","title":"double-encoded traversal","evidence_required":["baseline_response","normalized_response"],"confidence":0.7}],"missing_evidence":["alternate_encoding_response"],"verdict":"confirmed","severity":"critical"}`
	s := fakeBackend(t, content, 42, 17)
	defer s.Close()

	tr := NewTracker(Budget{MaxRequests: 5})
	p, err := NewOpenAICompat(OpenAICompatConfig{BaseURL: s.URL + "/v1", Model: "qwen2.5"}, tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Name(), "openai-compat:") {
		t.Errorf("name = %q", p.Name())
	}
	res, err := p.Analyze(context.Background(), AnalysisRequest{Task: TaskFindingAnalysis, Target: "http://t", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Proposals) != 1 || res.Proposals[0].CandidateType != "path_normalization" {
		t.Fatalf("proposals = %+v", res.Proposals)
	}
	if len(res.MissingEvidence) != 1 {
		t.Fatalf("missing evidence = %+v", res.MissingEvidence)
	}
	if res.Usage.PromptTokens != 42 || res.Usage.CompletionTokens != 17 || res.Usage.Requests != 1 {
		t.Fatalf("usage = %+v", res.Usage)
	}
	if u := tr.Used(); u.Requests != 1 || u.PromptTokens != 42 {
		t.Fatalf("tracker usage = %+v", u)
	}
}

func TestOpenAICompatToleratesWrappedJSON(t *testing.T) {
	// Some backends ignore response_format and wrap JSON in prose / code fences.
	content := "Sure, here is the analysis:\n```json\n{\"proposals\":[{\"candidate_type\":\"x\",\"title\":\"y\"}]}\n```\nHope that helps!"
	s := fakeBackend(t, content, 1, 1)
	defer s.Close()
	p, _ := NewOpenAICompat(OpenAICompatConfig{BaseURL: s.URL + "/v1", Model: "m"}, nil)
	res, err := p.Analyze(context.Background(), AnalysisRequest{Task: TaskEvidenceGap})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Proposals) != 1 || res.Proposals[0].Title != "y" {
		t.Fatalf("proposals = %+v", res.Proposals)
	}
}

func TestOpenAICompatErrors(t *testing.T) {
	// Unknown task never hits the network.
	p, _ := NewOpenAICompat(OpenAICompatConfig{BaseURL: "http://127.0.0.1:1/v1", Model: "m"}, nil)
	if _, err := p.Analyze(context.Background(), AnalysisRequest{Task: "not-a-task"}); err == nil {
		t.Fatal("unknown task accepted")
	}
	// Non-200 backend.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer s.Close()
	p2, _ := NewOpenAICompat(OpenAICompatConfig{BaseURL: s.URL + "/v1", Model: "m"}, nil)
	if _, err := p2.Analyze(context.Background(), AnalysisRequest{Task: TaskFindingAnalysis}); err == nil {
		t.Fatal("500 accepted")
	}
	// Budget exhausted before request.
	tr := NewTracker(Budget{MaxRequests: 0})
	// MaxRequests 0 means unlimited, so use 1 then exhaust.
	tr = NewTracker(Budget{MaxRequests: 1})
	_ = tr.Reserve()
	s2 := fakeBackend(t, `{"proposals":[]}`, 1, 1)
	defer s2.Close()
	p3, _ := NewOpenAICompat(OpenAICompatConfig{BaseURL: s2.URL + "/v1", Model: "m"}, tr)
	if _, err := p3.Analyze(context.Background(), AnalysisRequest{Task: TaskFindingAnalysis}); err != ErrBudgetExceeded {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}
}

func TestNewOpenAICompatValidation(t *testing.T) {
	for _, cfg := range []OpenAICompatConfig{
		{BaseURL: "", Model: "m"},
		{BaseURL: "ftp://x/v1", Model: "m"},
		{BaseURL: "http://x/v1", Model: ""},
	} {
		if _, err := NewOpenAICompat(cfg, nil); err == nil {
			t.Errorf("accepted bad config %+v", cfg)
		}
	}
}
