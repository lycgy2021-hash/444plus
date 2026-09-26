package research

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// This file is E7's freeze-gate battery. Every "candidate under test" is
// produced through the REAL E6 pipeline (StateMachineProducer.Produce
// against a real transition observed over real HTTP) — never hand-built —
// so a rejection test is proving the validator actually distrusts a real
// Candidate's own claims, not merely a struct literal contrived to fail.

// e7Fixture is a small stateful local HTTP target: /state reports a
// mutable status (200 by default), /deny sets it to 403 UNLESS breaks() has
// been turned off (simulating "the bug got fixed between the original
// observation and a later replay"), and /slow hangs for wall-time tests.
type e7Fixture struct {
	ts       *httptest.Server
	status   *int32
	denyHits *int32
	breaks   *int32
}

func newE7Fixture(t *testing.T) *e7Fixture {
	t.Helper()
	f := &e7Fixture{status: new(int32), denyHits: new(int32), breaks: new(int32)}
	atomic.StoreInt32(f.status, http.StatusOK)
	atomic.StoreInt32(f.breaks, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(int(atomic.LoadInt32(f.status)))
		w.Write([]byte("state"))
	})
	mux.HandleFunc("/deny", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(f.denyHits, 1)
		if atomic.LoadInt32(f.breaks) == 1 {
			atomic.StoreInt32(f.status, http.StatusForbidden)
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	})
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *e7Fixture) reset()               { atomic.StoreInt32(f.status, http.StatusOK) }
func (f *e7Fixture) setDenyBreaks(b bool) { atomic.StoreInt32(f.breaks, boolToInt32(b)) }
func (f *e7Fixture) denyHitCount() int    { return int(atomic.LoadInt32(f.denyHits)) }

func boolToInt32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

func e7ReplayTarget() ReplayTarget {
	return ReplayTarget{TargetID: "e7-target", BuildID: "e7-build", Protocol: "http", HarnessID: "e7-harness"}
}

// e7BuildOriginalCandidate drives ONE real transition against f (baseline
// collect -> execute "deny" -> result collect, all real HTTP) and runs it
// through the REAL E6 producer to get a genuine Candidate — exactly what a
// real Explorer session followed by StateMachineProducer.Produce would
// leave behind. The rule declares "deny must not change status away from
// 200", so as long as f.breaks() is on (the default), this is VIOLATED and
// exactly one Candidate is produced.
func e7BuildOriginalCandidate(t *testing.T, f *e7Fixture, sessionID string) (*Candidate, *TransitionRuleRegistry, TransitionRule) {
	t.Helper()
	scope := e7ReplayTarget().Scope(sessionID)
	collector, err := NewHTTPCollector(f.ts.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(f.ts.URL, map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	projector := stateauth.HTTPFixtureRegistry()
	meter := newBoundedRequestMeter(10)
	ctx := context.Background()

	before, beforeRaw, err := collectAndProject(ctx, collector, projector, scope, meter)
	if err != nil {
		t.Fatalf("baseline collect: %v", err)
	}
	actionRegistry := actionauth.NewRegistry(actionauth.Registration{
		Action:       actionauth.RegisteredAction{Key: "deny"},
		Requirements: actionauth.StateRequirements{ProjectorID: before.ProjectorID()},
	})
	policy := actionauth.NewActionPolicy(actionRegistry, actionauth.NewRecoveryRegistry())
	boundAction, ok := policy.Select(scope.Hash(), before, nil)
	if !ok {
		t.Fatal("ActionPolicy.Select: expected a match for 'deny'")
	}
	if err := executor.Execute(ContextWithRequestMeter(ctx, meter), boundAction); err != nil {
		t.Fatalf("execute deny: %v", err)
	}
	after, afterRaw, err := collectAndProject(ctx, collector, projector, scope, meter)
	if err != nil {
		t.Fatalf("result collect: %v", err)
	}

	now := time.Now().UTC()
	tr := StateTransition{
		ScopeHash:              scope.Hash(),
		BeforeFingerprint:      before,
		Action:                 boundAction,
		AfterFingerprint:       after,
		EvidenceRefs:           []string{"orig-evidence"},
		TransitionArtifactHash: transitionArtifactHash(scope.Hash(), beforeRaw, boundAction.ID(), afterRaw, now),
		Timestamp:              now,
	}
	rule := TransitionRule{
		RuleID:            "deny-must-not-change-status",
		ActionID:          boundAction.ID(),
		ProjectorID:       before.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "200"},
		ExpectationSource: ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "e7-test-config"},
	}
	registry, err := NewTransitionRuleRegistry(rule)
	if err != nil {
		t.Fatalf("NewTransitionRuleRegistry: %v", err)
	}
	candidates := NewStateMachineProducer(registry).Produce(TransitionCase{Transition: tr, Scope: scope})
	if len(candidates) != 1 {
		t.Fatalf("setup: expected exactly 1 real candidate, got %d", len(candidates))
	}
	return candidates[0], registry, rule
}

func e7NewValidator(t *testing.T, f *e7Fixture, registry *TransitionRuleRegistry, target ReplayTarget, budget ReplayBudget) *StateMachineReplayValidator {
	t.Helper()
	collector, err := NewHTTPCollector(f.ts.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(f.ts.URL, map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewStateMachineReplayValidator(target, registry, collector, stateauth.HTTPFixtureRegistry(), executor, budget)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func e7DefaultBudget() ReplayBudget {
	return ReplayBudget{MaxRequests: 10, MaxWallTime: 10 * time.Second}
}

func artifactRef(o Observation, kind string) (string, bool) {
	for _, a := range o.Artifacts {
		if a.Kind == kind {
			return a.Ref, true
		}
	}
	return "", false
}

// --- authority/shape rejections: never even attempted ----------------------

func TestE7NonStateMachineOriginRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c.Origin = Origin{Kind: OriginFuzz}
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayUnsupportedOrigin {
		t.Fatalf("Replay with non-OriginStateMachine candidate: err = %v, want %v", err, ErrReplayUnsupportedOrigin)
	}
}

func TestE7MissingRuleIDRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c.Refs["rule_id"] = ""
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayMissingRuleID {
		t.Fatalf("Replay with empty rule_id: err = %v, want %v", err, ErrReplayMissingRuleID)
	}
}

func TestE7UnknownRuleIDRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c.Refs["rule_id"] = "no-such-rule-was-ever-registered"
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayUnknownRule {
		t.Fatalf("Replay with unknown rule_id: err = %v, want %v", err, ErrReplayUnknownRule)
	}
}

func TestE7ActionMismatchRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c.Refs["action_registry_key"] = "not-the-real-action"
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayActionMismatch {
		t.Fatalf("Replay with mismatched action_registry_key: err = %v, want %v", err, ErrReplayActionMismatch)
	}
}

func TestE7ProjectorMismatchRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c.Refs["projector_id"] = "not-the-real-projector"
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayProjectorMismatch {
		t.Fatalf("Replay with mismatched projector_id: err = %v, want %v", err, ErrReplayProjectorMismatch)
	}
}

func TestE7TargetMismatchRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	differentTarget := ReplayTarget{TargetID: "a-different-target", BuildID: "e7-build", Protocol: "http", HarnessID: "e7-harness"}
	v := e7NewValidator(t, f, registry, differentTarget, e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayTargetMismatch {
		t.Fatalf("Replay against a differently-targeted validator: err = %v, want %v", err, ErrReplayTargetMismatch)
	}
}

func TestE7EmptySessionIDRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, ""); err != ErrReplaySessionIDRequired {
		t.Fatalf("Replay with empty sessionID: err = %v, want %v", err, ErrReplaySessionIDRequired)
	}
}

// --- no state preparation ---------------------------------------------------

// TestE7PreconditionNotMetProducesNoSignalWithoutExecutingAction: the fresh
// baseline (still 403 from the ORIGINAL run — f.reset() deliberately NOT
// called) does not satisfy fact_transition's own precondition
// (BeforeValue="200"). Replay must stop with OutcomeNoSignal and must NEVER
// execute "deny" to try to force the precondition to hold — proven by the
// fixture's own deny-hit counter staying at exactly 1 (the original run),
// never 2.
func TestE7PreconditionNotMetProducesNoSignalWithoutExecutingAction(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session") // leaves f.status at 403
	if got := f.denyHitCount(); got != 1 {
		t.Fatalf("setup: denyHitCount = %d, want 1 (only the original run)", got)
	}
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	res, err := v.Replay(context.Background(), c, "replay-session")
	if err != nil {
		t.Fatalf("Replay (precondition not met) returned an error: %v", err)
	}
	if res.Outcome != OutcomeNoSignal {
		t.Fatalf("Replay (precondition not met) Outcome = %q, want %q", res.Outcome, OutcomeNoSignal)
	}
	if got := f.denyHitCount(); got != 1 {
		t.Fatalf("denyHitCount after replay = %d, want still 1 — Replay must never execute an action to force a precondition to hold", got)
	}
}

// --- satisfied -> no_signal --------------------------------------------------

// TestE7SatisfiedProducesNoSignal: the fresh baseline is reset to 200
// (matching the precondition), and the underlying bug is "fixed" (deny no
// longer changes status) — so a fresh replay observes the rule HOLD.
func TestE7SatisfiedProducesNoSignal(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()
	f.setDenyBreaks(false)
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())
	res, err := v.Replay(context.Background(), c, "replay-session")
	if err != nil {
		t.Fatalf("Replay (satisfied) returned an error: %v", err)
	}
	if res.Outcome != OutcomeNoSignal {
		t.Fatalf("Replay (satisfied) Outcome = %q, want %q", res.Outcome, OutcomeNoSignal)
	}
}

// --- violated again -> reproduced, with independent evidence ---------------

// TestE7ViolatedProducesReproducedWithIndependentEvidence is the core E7
// proof: a FRESH session (a different sessionID from the original),
// against the SAME ReplayTarget, independently re-collects, re-executes,
// and re-collects — and the rule is violated again. It also proves the
// replay's OWN case artifact hash is a DIFFERENT value from the original
// Candidate's case_artifact_hash (a different Transition/Scope, even though
// both were judged against the identical Rule), and that the Candidate is
// NEVER promoted by Replay itself.
func TestE7ViolatedProducesReproducedWithIndependentEvidence(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, rule := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset() // a genuinely fresh baseline, not reusing the old after-state
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), e7DefaultBudget())

	res, err := v.Replay(context.Background(), c, "replay-session-DIFFERENT-FROM-original")
	if err != nil {
		t.Fatalf("Replay (violated again) returned an error: %v", err)
	}
	if res.Outcome != OutcomeReproduced {
		t.Fatalf("Replay (violated again) Outcome = %q, want %q", res.Outcome, OutcomeReproduced)
	}
	if res.Validator != "state_machine_replay_v1" {
		t.Fatalf("ValidationResult.Validator = %q, want %q", res.Validator, "state_machine_replay_v1")
	}

	var summary *Observation
	for i := range res.Evidence {
		if res.Evidence[i].Kind == "replay_summary" {
			summary = &res.Evidence[i]
		}
	}
	if summary == nil {
		t.Fatal("ValidationResult.Evidence has no replay_summary observation")
	}
	replayRuleID, _ := artifactRef(*summary, "rule_id")
	if replayRuleID != rule.RuleID {
		t.Fatalf("replay_summary rule_id = %q, want %q", replayRuleID, rule.RuleID)
	}
	replayCaseHash, ok := artifactRef(*summary, "replay_case_artifact_hash")
	if !ok || replayCaseHash == "" {
		t.Fatal("replay_summary has no replay_case_artifact_hash")
	}
	if replayCaseHash == c.Refs["case_artifact_hash"] {
		t.Fatalf("replay_case_artifact_hash must NEVER equal the original Candidate's own case_artifact_hash (different Transition, different Scope) — got %q for both", replayCaseHash)
	}

	// Replay never Promotes: the Candidate must still be exactly Hypothesis.
	if c.State != Hypothesis {
		t.Fatalf("Candidate.State after Replay = %q, want %q — Replay must NEVER promote", c.State, Hypothesis)
	}
}

// --- pure outcome-mapping rule table (no I/O) -------------------------------

func TestE7ReplayOutcomeMapping(t *testing.T) {
	cases := []struct {
		assessment  TransitionAssessment
		wantOutcome Outcome
		wantSignal  bool
	}{
		{TransitionSatisfied, OutcomeNoSignal, true},
		{TransitionNotApplicable, OutcomeNoSignal, true},
		{TransitionViolated, OutcomeReproduced, true},
		{TransitionInsufficientEvidence, "", false},
		{TransitionAssessment("something_unrecognized"), "", false},
	}
	for _, c := range cases {
		outcome, signal := replayOutcomeFor(c.assessment)
		if outcome != c.wantOutcome || signal != c.wantSignal {
			t.Errorf("replayOutcomeFor(%q) = (%q, %v), want (%q, %v)", c.assessment, outcome, signal, c.wantOutcome, c.wantSignal)
		}
	}
}

// --- budget / timeout -------------------------------------------------------

// TestE7RequestBudgetExhaustedIsError: a full replay needs 3 real HTTP
// requests (baseline collect, execute, result collect). MaxRequests=2 must
// exhaust on the third, and Replay must report it as an error — never a
// signal either way.
func TestE7RequestBudgetExhaustedIsError(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()
	v := e7NewValidator(t, f, registry, e7ReplayTarget(), ReplayBudget{MaxRequests: 2, MaxWallTime: 10 * time.Second})
	if _, err := v.Replay(context.Background(), c, "replay-session"); err == nil {
		t.Fatal("Replay with MaxRequests=2 (a full replay needs 3) = nil error, want an error")
	}
}

// TestE7WallTimeTimeoutIsError drives the baseline collection against a
// hanging endpoint with a tiny MaxWallTime — Replay must fail quickly
// (within a couple of seconds), never wait out the target's full delay.
func TestE7WallTimeTimeoutIsError(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()

	// A validator pointed at /slow for its observation path — a hanging
	// target, exactly like TestExplorerMaxWallTimeCancelsHangingRealRequest.
	slowCollector, err := NewHTTPCollector(f.ts.URL, "/slow")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(f.ts.URL, map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, slowCollector, stateauth.HTTPFixtureRegistry(), executor, ReplayBudget{MaxRequests: 10, MaxWallTime: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = v.Replay(context.Background(), c, "replay-session")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Replay against a hanging endpoint with a 50ms MaxWallTime = nil error, want an error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Replay took %v to fail, want it cut short well under the endpoint's 5s hang", elapsed)
	}
}

// --- construction validation -------------------------------------------------

func TestNewStateMachineReplayValidatorRejectsNilDependenciesOrInvalidBudget(t *testing.T) {
	f := newE7Fixture(t)
	collector, err := NewHTTPCollector(f.ts.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(f.ts.URL, map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	registry := e6MustRegistry(t) // empty but valid
	projector := stateauth.HTTPFixtureRegistry()
	validBudget := e7DefaultBudget()

	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), nil, collector, projector, executor, validBudget); err == nil {
		t.Fatal("nil rules registry must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, nil, projector, executor, validBudget); err == nil {
		t.Fatal("nil collector must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, collector, nil, executor, validBudget); err == nil {
		t.Fatal("nil projector must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, collector, projector, nil, validBudget); err == nil {
		t.Fatal("nil executor must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, collector, projector, executor, ReplayBudget{MaxRequests: 0, MaxWallTime: time.Second}); err == nil {
		t.Fatal("MaxRequests=0 must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, collector, projector, executor, ReplayBudget{MaxRequests: 1, MaxWallTime: 0}); err == nil {
		t.Fatal("MaxWallTime=0 must be rejected")
	}
}
