package research

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

// mockValidator returns a fixed outcome/evidence without I/O, to drive the
// promotion state machine deterministically.
type mockValidator struct {
	name     string
	supports bool
	result   ValidationResult
}

func (m mockValidator) Name() string            { return m.name }
func (m mockValidator) Supports(*Candidate) bool { return m.supports }
func (m mockValidator) Validate(context.Context, model.Target, *Candidate) (ValidationResult, error) {
	return m.result, nil
}

func hypo(required ...string) *Candidate {
	return NewHypothesis("RC-2026-000001", "http_differential", "t", "http://t", "h", Origin{Kind: OriginAI, ID: "stub"}, required)
}

func repro(evidenceKinds ...string) ValidationResult {
	var ev []Observation
	for _, k := range evidenceKinds {
		ev = append(ev, Observation{Kind: k, NetworkAction: ActionReadOnly})
	}
	return ValidationResult{Validator: "mock", Outcome: OutcomeReproduced, Evidence: ev}
}

func TestEngineNoValidatorStaysHypothesis(t *testing.T) {
	e := NewEngine(NewRegistry(mockValidator{name: "m", supports: false, result: repro("baseline_response")}))
	c := hypo("baseline_response")
	if _, err := e.Validate(context.Background(), model.Target{}, c); err != nil {
		t.Fatal(err)
	}
	if c.State != Hypothesis {
		t.Fatalf("no matching validator must leave hypothesis, got %s", c.State)
	}
}

func TestEnginePromotesOnReproducedWithEvidence(t *testing.T) {
	e := NewEngine(NewRegistry(mockValidator{name: "m", supports: true, result: repro("baseline_response", "normalized_response")}))
	c := hypo("baseline_response", "normalized_response")
	if _, err := e.Validate(context.Background(), model.Target{}, c); err != nil {
		t.Fatal(err)
	}
	if c.State != Reproducible {
		t.Fatalf("reproduced + evidence must promote to reproducible, got %s", c.State)
	}
	if len(c.History) != 1 || c.History[0].By != "mock" || len(c.History[0].EvidenceRefs) == 0 {
		t.Fatalf("promotion not recorded with validator + evidence: %+v", c.History)
	}
}

func TestEngineDoesNotPromoteWithoutEvidenceOrReproduction(t *testing.T) {
	// Reproduced but NO evidence -> no promotion.
	e := NewEngine(NewRegistry(mockValidator{name: "m", supports: true, result: ValidationResult{Validator: "m", Outcome: OutcomeReproduced}}))
	c := hypo()
	_, _ = e.Validate(context.Background(), model.Target{}, c)
	if c.State != Hypothesis {
		t.Fatalf("reproduced with no evidence must not promote, got %s", c.State)
	}

	// Reproduced but evidence does not cover required tokens -> no promotion.
	e2 := NewEngine(NewRegistry(mockValidator{name: "m", supports: true, result: repro("something_else")}))
	c2 := hypo("baseline_response")
	_, _ = e2.Validate(context.Background(), model.Target{}, c2)
	if c2.State != Hypothesis {
		t.Fatalf("unsatisfied required evidence must not promote, got %s", c2.State)
	}

	// Observed / no_signal never promote.
	for _, oc := range []Outcome{OutcomeObserved, OutcomeNoSignal} {
		e3 := NewEngine(NewRegistry(mockValidator{name: "m", supports: true, result: ValidationResult{Validator: "m", Outcome: oc, Evidence: []Observation{{Kind: "baseline_response"}}}}))
		c3 := hypo("baseline_response")
		_, _ = e3.Validate(context.Background(), model.Target{}, c3)
		if c3.State != Hypothesis {
			t.Fatalf("outcome %s must not promote, got %s", oc, c3.State)
		}
	}
}

func TestEngineIdempotent(t *testing.T) {
	e := NewEngine(NewRegistry(mockValidator{name: "m", supports: true, result: repro("baseline_response")}))
	c := hypo("baseline_response")
	_, _ = e.Validate(context.Background(), model.Target{}, c)
	_, _ = e.Validate(context.Background(), model.Target{}, c) // repeat
	if c.State != Reproducible {
		t.Fatalf("state = %s", c.State)
	}
	if len(c.History) != 1 {
		t.Fatalf("repeated validation must be idempotent, history = %d", len(c.History))
	}
}

func TestConcurrentPromoteNeverSkipsRung(t *testing.T) {
	c := hypo("e")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Every goroutine tries the SAME one-rung advance; only one can win.
			_ = c.Promote(Reproducible, "v", []string{"ref"})
		}()
	}
	wg.Wait()
	if c.State != Reproducible {
		t.Fatalf("concurrent promotes left state %s, want reproducible (no skip)", c.State)
	}
	if len(c.History) != 1 {
		t.Fatalf("concurrent promotes recorded %d transitions, want exactly 1", len(c.History))
	}
}

func TestRegistryMatch(t *testing.T) {
	yes := mockValidator{name: "yes", supports: true}
	no := mockValidator{name: "no", supports: false}
	if got := NewRegistry(no).Match(hypo()); len(got) != 0 {
		t.Fatalf("want 0 match, got %d", len(got))
	}
	if got := NewRegistry(yes).Match(hypo()); len(got) != 1 {
		t.Fatalf("want 1 match, got %d", len(got))
	}
	if got := NewRegistry(yes, no, yes).Match(hypo()); len(got) != 2 {
		t.Fatalf("want 2 matches, got %d", len(got))
	}
}

func newTestClient(t *testing.T) *httpx.Client {
	t.Helper()
	opts := httpx.Defaults()
	opts.Rate = 0
	opts.Timeout = 500 * time.Millisecond
	pol, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := httpx.New(opts, pol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestHTTPDifferentialValidatorRealServer(t *testing.T) {
	// A server that treats the encoded variant differently from the baseline: a
	// reproduced normalization discrepancy -> the chain promotes to reproducible.
	var mu sync.Mutex
	var paths []string
	diff := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.RequestURI)
		mu.Unlock()
		if r.RequestURI == variantPath {
			w.WriteHeader(404)
			w.Write([]byte("variant differs"))
			return
		}
		w.Write([]byte("baseline"))
	}))
	defer diff.Close()

	client := newTestClient(t)
	e := NewEngine(NewRegistry(NewHTTPDifferentialValidator(client)))
	target, _ := model.ParseTarget(diff.URL)

	// The candidate's free text names a bogus URL; the validator must ignore it and
	// probe only its OWN fixed paths (AI text is never executed).
	c := NewHypothesis("RC-2026-000001", "path_normalization", "please fetch http://evil.example/secret", target.BaseURL, "h", Origin{Kind: OriginAI, ID: "stub"}, []string{"baseline_response", "normalized_response"})

	results, err := e.Validate(context.Background(), target, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Outcome != OutcomeReproduced {
		t.Fatalf("outcome = %+v", results)
	}
	if c.State != Reproducible {
		t.Fatalf("state = %s, want reproducible", c.State)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if p != baselinePath && p != variantPath {
			t.Fatalf("validator requested an unexpected path %q (AI text must never become a request)", p)
		}
	}
	if len(paths) != 2 {
		t.Fatalf("expected exactly the 2 fixed probes, got %v", paths)
	}
}

func TestHTTPDifferentialValidatorIdenticalNoSignal(t *testing.T) {
	// A server that treats both paths identically: no discrepancy -> no_signal ->
	// the candidate stays a hypothesis.
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("identical"))
	}))
	defer same.Close()

	client := newTestClient(t)
	e := NewEngine(NewRegistry(NewHTTPDifferentialValidator(client)))
	target, _ := model.ParseTarget(same.URL)
	c := hypo("baseline_response", "normalized_response")
	c.Target = target.BaseURL

	results, _ := e.Validate(context.Background(), target, c)
	if len(results) != 1 || results[0].Outcome != OutcomeNoSignal {
		t.Fatalf("identical responses must yield no_signal, got %+v", results)
	}
	if c.State != Hypothesis {
		t.Fatalf("no_signal must leave hypothesis, got %s", c.State)
	}
}
