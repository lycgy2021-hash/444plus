// Package ai is the AI gateway for the Research Plane. It defines one contract —
// Provider.Analyze — behind which any model backend hides: a local llama.cpp /
// vLLM / KoboldCpp / Ollama OpenAI-compatible server, or a cloud endpoint. The Go
// program never knows which model answers.
//
// The package is deliberately dependency-free of the detection plane: it imports
// neither internal/model nor research, so it cannot reach a Verdict. Its output
// (AnalysisResult) carries proposals and missing-evidence notes only — never a
// verdict, never a confirmed state. The authority boundary (AI proposes,
// deterministic validators decide) is enforced downstream in the research
// package; this package simply has no vocabulary for a verdict.
package ai

import (
	"errors"
	"sync"
	"time"
)

// Usage is the resource cost of one or more Analyze calls. USD is optional and
// stays zero for local models (which are free); it exists so a cloud Provider can
// report spend against a budget.
type Usage struct {
	Requests         int     `json:"requests"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	USD              float64 `json:"usd,omitempty"`
}

func (u Usage) add(o Usage) Usage {
	return Usage{
		Requests:         u.Requests + o.Requests,
		PromptTokens:     u.PromptTokens + o.PromptTokens,
		CompletionTokens: u.CompletionTokens + o.CompletionTokens,
		USD:              u.USD + o.USD,
	}
}

// Budget caps what the Research Plane may spend on a model. A zero field means
// "no limit for that dimension" — local models are free and effectively
// unmetered, so a default Budget{} imposes only the caps a caller sets.
type Budget struct {
	MaxRequests         int           `yaml:"max_requests"`
	MaxPromptTokens     int           `yaml:"max_prompt_tokens"`
	MaxCompletionTokens int           `yaml:"max_completion_tokens"`
	MaxWallClock        time.Duration `yaml:"max_wall_clock"`
	MaxUSD              float64       `yaml:"max_usd"`
}

// ErrBudgetExceeded is returned by Reserve when a further request would break the
// budget, so a Provider stops before issuing the call.
var ErrBudgetExceeded = errors.New("ai: budget exceeded")

// Tracker enforces a Budget across concurrent Analyze calls. A Provider calls
// Reserve() before each request and Record() after, so the budget is honored
// even when several analyses run at once.
type Tracker struct {
	budget Budget
	start  time.Time
	mu     sync.Mutex
	used   Usage
}

func NewTracker(b Budget) *Tracker { return &Tracker{budget: b, start: time.Now()} }

// Reserve accounts for one upcoming request and reports whether the budget still
// allows it. It counts the request optimistically (incrementing before the call)
// so a burst of concurrent Reserves cannot collectively overshoot MaxRequests.
func (t *Tracker) Reserve() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.budget.MaxWallClock > 0 && time.Since(t.start) > t.budget.MaxWallClock {
		return ErrBudgetExceeded
	}
	if t.budget.MaxRequests > 0 && t.used.Requests >= t.budget.MaxRequests {
		return ErrBudgetExceeded
	}
	if t.budget.MaxPromptTokens > 0 && t.used.PromptTokens >= t.budget.MaxPromptTokens {
		return ErrBudgetExceeded
	}
	if t.budget.MaxCompletionTokens > 0 && t.used.CompletionTokens >= t.budget.MaxCompletionTokens {
		return ErrBudgetExceeded
	}
	if t.budget.MaxUSD > 0 && t.used.USD >= t.budget.MaxUSD {
		return ErrBudgetExceeded
	}
	t.used.Requests++
	return nil
}

// Record adds the measured usage of a completed request (token counts, spend).
// The request itself was already counted by Reserve.
func (t *Tracker) Record(u Usage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	u.Requests = 0 // Reserve already counted the request
	t.used = t.used.add(u)
}

// Used returns a snapshot of consumption so far.
func (t *Tracker) Used() Usage {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.used
}
