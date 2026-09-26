package research

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// newHTTPFixtureServer builds the tiny local target S10-E5 explores: a
// fixed observation endpoint ("/state"), two fixed read-only action
// endpoints ("/" and "/health"), and one endpoint that issues a redirect
// ("/redirect") to prove HTTPCollector/HTTPExecutor never follow one.
// Nothing about these paths is configurable at request time — they exist
// only to give the real HTTPCollector/HTTPExecutor something real to talk
// to.
func newHTTPFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("stateful"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("root"))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/elsewhere", http.StatusFound)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// TestS10E5RealHTTPExplorationEndToEnd is the first non-mock proof this
// conversation's audit has been asking for: state authority (HTTPStateProjector
// via stateauth.HTTPFixtureRegistry), action authority
// (actionauth.ActionPolicy.Select over two fixed read-only GET actions),
// scope continuity, real request metering (BudgetedRoundTripper), and
// recovery all exercised together against a REAL local HTTP server, not a
// fake Collector/Executor.
func TestS10E5RealHTTPExplorationEndToEnd(t *testing.T) {
	ts := newHTTPFixtureServer(t)

	collector, err := NewHTTPCollector(ts.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(ts.URL, map[string]string{
		"get-root":   "/",
		"get-health": "/health",
	})
	if err != nil {
		t.Fatal(err)
	}
	httpReq := actionauth.StateRequirements{ProjectorID: stateauth.HTTPStateProjector{}.ID()}
	policy := actionauth.NewActionPolicy(
		actionauth.NewRegistry(
			actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root", Reversible: true}, Requirements: httpReq},
			actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-health", Reversible: true}, Requirements: httpReq},
		),
		actionauth.NewRecoveryRegistry("reset"),
	)
	budget := ExplorationBudget{
		MaxStates: 10, MaxTransitions: 10, MaxDepth: 10, MaxRequests: 50,
		MaxVisitsPerState: 10, MaxBranching: 1, MaxWallTime: 30 * time.Second,
	}
	exp, err := NewExplorer(
		ExplorationScope{TargetID: "e5-fixture", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h1"},
		collector,
		stateauth.HTTPFixtureRegistry(),
		policy,
		executor,
		budget,
		actionauth.RecoveryPlanRef{RegistryKey: "reset"},
		5*time.Second,
		20,
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	baseline, err := exp.Baseline(ctx)
	if err != nil {
		t.Fatalf("Baseline against a real HTTP server must succeed: %v", err)
	}
	if baseline.Facts()["status"] != "200" || baseline.Facts()["content_type"] != "text/plain" {
		t.Fatalf("baseline facts = %v, want status=200 content_type=text/plain", baseline.Facts())
	}

	seenActions := map[string]bool{}
	for i := 0; i < 2; i++ {
		tr, err := exp.Step(ctx)
		if err != nil {
			t.Fatalf("step %d against a real HTTP server must succeed: %v", i, err)
		}
		seenActions[tr.Action.ID().RegistryKey] = true
		if !tr.ScopeConsistent() {
			t.Fatalf("step %d: transition must be scope-consistent", i)
		}
	}
	if !seenActions["get-root"] || !seenActions["get-health"] {
		t.Fatalf("seenActions = %v, want both get-root and get-health exercised across two real steps", seenActions)
	}

	// A third step has nothing left to try from this exact (unchanging,
	// read-only-probed) state.
	if _, err := exp.Step(ctx); !errors.Is(err, ErrNoApplicableAction) {
		t.Fatalf("third step = %v, want ErrNoApplicableAction (both real actions already tried from this state)", err)
	}
	if stopped, _ := exp.Stopped(); stopped {
		t.Fatal("ErrNoApplicableAction must not stop the explorer")
	}

	outcome, err := exp.Recover(ctx)
	if err != nil {
		t.Fatalf("recovery against a real HTTP server must succeed: %v", err)
	}
	if !stateauth.Recovered(outcome) {
		t.Fatal("stateauth.Recovered(outcome) must be true: the fixture's read-only actions never mutate /state, so recovery is trivially satisfied")
	}

	if got := len(exp.History()); got != 2 {
		t.Fatalf("History() has %d entries, want 2 (one per real step)", got)
	}
}

// TestHTTPCollectorNeverFollowsRedirects is the direct regression test for
// the audit's explicit ask: a target that responds with a redirect must be
// observed AS a redirect (its own status code), never silently followed to
// wherever Location points — especially since that could be a host outside
// this Explorer's own scope entirely.
func TestHTTPCollectorNeverFollowsRedirects(t *testing.T) {
	ts := newHTTPFixtureServer(t)
	collector, err := NewHTTPCollector(ts.URL, "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	scope := ExplorationScope{TargetID: "e5-fixture"}
	ctx := ContextWithRequestMeter(context.Background(), newBoundedRequestMeter(10))
	artifact, err := collector.Collect(ctx, scope)
	if err != nil {
		t.Fatalf("collecting a redirect response must still succeed (observed, not followed): %v", err)
	}
	fp, err := stateauth.HTTPFixtureRegistry().Project(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if fp.Facts()["status"] != "302" {
		t.Fatalf("Facts()[status] = %q, want 302 — the redirect itself must be observed, never followed to example.invalid", fp.Facts()["status"])
	}
}

// TestHTTPExecutorRefusesUnregisteredAction proves HTTPExecutor's fixed
// action map really is the only thing it will ever run — a BoundAction for
// a key it wasn't constructed with (which should be structurally
// unreachable via a real ActionPolicy.Select, but is checked here directly
// as defense in depth) is refused, never treated as "any GET the caller
// names".
func TestHTTPExecutorRefusesUnregisteredAction(t *testing.T) {
	ts := newHTTPFixtureServer(t)
	executor, err := NewHTTPExecutor(ts.URL, map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	policy := actionauth.NewActionPolicy(
		actionauth.NewRegistry(actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root"}, Requirements: actionauth.StateRequirements{ProjectorID: "http-v1"}}),
		actionauth.NewRecoveryRegistry(),
	)
	// A BoundAction can only ever be produced by Select against a real
	// Fingerprint; we build one here purely to exercise Execute's own
	// defense-in-depth lookup against a key it was never configured with.
	fp, err := stateauth.HTTPFixtureRegistry().Project(stateauth.StateArtifact{ScopeHash: "s", Raw: mustMarshalHTTPArtifact(t)})
	if err != nil {
		t.Fatal(err)
	}
	bogus, ok := policy.Select("s", fp, nil)
	_ = ok // "get-root" would bind fine; we mutate the key below to simulate a mismatch
	if bogus.ID().RegistryKey != "get-root" {
		t.Skip("policy did not select get-root as expected; nothing to test")
	}
	// executor only knows "get-root" — reconstruct with a different map to
	// prove the lookup is real, not merely never exercised.
	otherExecutor, err := NewHTTPExecutor(ts.URL, map[string]string{"get-health": "/health"})
	if err != nil {
		t.Fatal(err)
	}
	if err := otherExecutor.Execute(context.Background(), bogus); err == nil {
		t.Fatal("Execute must refuse a BoundAction naming a key this executor was never configured with")
	}
	_ = executor
}

func mustMarshalHTTPArtifact(t *testing.T) []byte {
	t.Helper()
	raw, err := stateauth.MarshalHTTPArtifact(stateauth.HTTPArtifact{Status: 200, ContentType: "text/plain", Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
