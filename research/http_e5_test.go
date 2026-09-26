package research

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
	mux.HandleFunc("/huge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 64*1024)
		for written := 0; written < maxHTTPBodyBytes+1024; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
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

	scope := ExplorationScope{TargetID: "e5-fixture", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h1"}
	// NewHTTPProfile binds this scope to ts.URL once, building both the
	// Collector and the Executor from the SAME origin — see http_profile.go
	// for why that matters (a Collector for one target and an Executor for
	// a different one can never end up wired into the same Explorer).
	profile, err := NewHTTPProfile(scope, ts.URL, "/state", map[string]string{
		"get-root":   "/",
		"get-health": "/health",
	})
	if err != nil {
		t.Fatal(err)
	}
	httpReq := actionauth.StateRequirements{ProjectorID: stateauth.HTTPStateProjector{}.ID()}
	policy := actionauth.NewActionPolicy(
		actionauth.NewRegistry(
			actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/")}, Requirements: httpReq},
			actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-health", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/health")}, Requirements: httpReq},
		),
		actionauth.NewRecoveryRegistry("reset"),
	)
	budget := ExplorationBudget{
		MaxStates: 10, MaxTransitions: 10, MaxDepth: 10, MaxRequests: 50,
		MaxVisitsPerState: 10, MaxBranching: 1, MaxWallTime: 30 * time.Second,
	}
	exp, err := NewExplorer(
		profile.Scope(),
		profile.Collector(),
		stateauth.HTTPFixtureRegistry(),
		policy,
		profile.Executor(),
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

// TestHTTPCollectorRejectsOversizedBody is the direct regression test for
// the audit's body-size-cap ask: a target that returns more than
// maxHTTPBodyBytes must make Collect fail, never silently truncate the body
// into a misleading Fact, and never let an unbounded read exhaust memory. A
// LimitReader-based cap was already part of the original HTTPCollector
// implementation — this test exists so that guarantee is proven, not merely
// asserted in a doc comment.
func TestHTTPCollectorRejectsOversizedBody(t *testing.T) {
	ts := newHTTPFixtureServer(t)
	collector, err := NewHTTPCollector(ts.URL, "/huge")
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithRequestMeter(context.Background(), newBoundedRequestMeter(10))
	if _, err := collector.Collect(ctx, ExplorationScope{TargetID: "e5-fixture"}); err == nil {
		t.Fatal("a response body over maxHTTPBodyBytes must make Collect fail, never succeed with a truncated body")
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

// TestHTTPExecutorRefusesSpecIDMismatch is the direct regression test for
// S10/E7's "executable semantics binding" freeze blocker: a BoundAction
// whose registered SpecID does NOT match HTTPActionSpecID(path) for the
// path this Executor's own fixed map actually resolves for that
// RegistryKey must be refused BEFORE any request reaches the network —
// proving Execute independently re-verifies SpecID rather than trusting
// whatever the registry/policy side declared.
func TestHTTPExecutorRefusesSpecIDMismatch(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	executor, err := NewHTTPExecutor(ts.URL, map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	policy := actionauth.NewActionPolicy(
		actionauth.NewRegistry(actionauth.Registration{
			Action:       actionauth.RegisteredAction{Key: "get-root", Safety: actionauth.ActionStrictReadOnly, SpecID: "a-spec-id-that-does-not-match-this-executors-own-path"},
			Requirements: actionauth.StateRequirements{ProjectorID: "http-v1"},
		}),
		actionauth.NewRecoveryRegistry(),
	)
	fp, err := stateauth.HTTPFixtureRegistry().Project(stateauth.StateArtifact{ScopeHash: "s", Raw: mustMarshalHTTPArtifact(t)})
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := policy.Select("s", fp, nil)
	if !ok || bound.ID().RegistryKey != "get-root" {
		t.Fatalf("setup: expected Select to bind get-root, got %+v ok=%v", bound.ID(), ok)
	}

	if err := executor.Execute(context.Background(), bound); err == nil {
		t.Fatal("Execute must refuse a BoundAction whose SpecID does not match this executor's own canonical spec for the resolved path")
	}
	if hits != 0 {
		t.Fatalf("server received %d requests, want 0 — a SpecID mismatch must be refused before any request reaches the network", hits)
	}
}

func mustMarshalHTTPArtifact(t *testing.T) []byte {
	t.Helper()
	raw, err := stateauth.MarshalHTTPArtifact(stateauth.HTTPArtifact{Status: 200, ContentType: "text/plain", Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestExplorerMaxWallTimeCancelsHangingRealRequest is the direct regression
// test for the audit's wall-time-enforcement ask: Explorer's MaxWallTime
// must bound the ACTIVE network call, not merely be checked between calls.
// The fixture's "/slow" endpoint hangs for 5 seconds (or until its own
// request context is cancelled); against a 50ms MaxWallTime, Baseline must
// fail promptly — via the context deadline explorer.go now derives — not
// after waiting out the server's full delay.
func TestExplorerMaxWallTimeCancelsHangingRealRequest(t *testing.T) {
	ts := newHTTPFixtureServer(t)
	scope := ExplorationScope{TargetID: "e5-fixture"}
	profile, err := NewHTTPProfile(scope, ts.URL, "/slow", map[string]string{"get-root": "/"})
	if err != nil {
		t.Fatal(err)
	}
	httpReq := actionauth.StateRequirements{ProjectorID: stateauth.HTTPStateProjector{}.ID()}
	policy := actionauth.NewActionPolicy(
		actionauth.NewRegistry(actionauth.Registration{Action: actionauth.RegisteredAction{Key: "get-root"}, Requirements: httpReq}),
		actionauth.NewRecoveryRegistry("reset"),
	)
	budget := ExplorationBudget{
		MaxStates: 10, MaxTransitions: 10, MaxDepth: 10, MaxRequests: 50,
		MaxVisitsPerState: 10, MaxBranching: 1, MaxWallTime: 50 * time.Millisecond,
	}
	exp, err := NewExplorer(
		profile.Scope(), profile.Collector(), stateauth.HTTPFixtureRegistry(), policy, profile.Executor(),
		budget, actionauth.RecoveryPlanRef{RegistryKey: "reset"}, 5*time.Second, 20,
	)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = exp.Baseline(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Baseline against a hanging endpoint must fail once MaxWallTime elapses")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Baseline took %v, want it cut short by MaxWallTime=50ms, well before the server's 5s delay", elapsed)
	}
}
