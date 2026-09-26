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
// Where a test needs a candidate with a deliberately BROKEN binding (never
// producible by StateMachineProducer itself), it says so explicitly and
// builds one directly — same-package field access, not a bypass Replay
// itself would ever see through Refs.

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

func (f *e7Fixture) setStatus(code int)   { atomic.StoreInt32(f.status, int32(code)) }
func (f *e7Fixture) reset()               { f.setStatus(http.StatusOK) }
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

// e7DenyOnlyPolicy is the TRUSTED ActionPolicy a real Explorer session for
// this target would use: exactly one registered action ("deny"), applicable
// to any state under the given ProjectorID, with the given declared safety.
// Both the original candidate's own transition AND a replay validator's
// action-authority check must go through a policy built this way — never
// one Replay invents for itself.
func e7DenyOnlyPolicy(projectorID stateauth.ProjectorID, safety actionauth.ActionSafety) *actionauth.ActionPolicy {
	registry := actionauth.NewRegistry(actionauth.Registration{
		Action:       actionauth.RegisteredAction{Key: "deny", Safety: safety, SpecID: HTTPActionSpecID("/deny")},
		Requirements: actionauth.StateRequirements{ProjectorID: projectorID},
	})
	return actionauth.NewActionPolicy(registry, actionauth.NewRecoveryRegistry())
}

// e7BuildOriginalCandidateWithSafety drives ONE real transition against f
// (baseline collect -> execute "deny" -> result collect, all real HTTP,
// authorized by e7DenyOnlyPolicy(safety) — the SAME policy a real Explorer
// session would use) and runs it through the REAL E6 producer to get a
// genuine Candidate. The rule declares "deny must not change status away
// from 200", so as long as f.breaks() is on (the default), this is
// VIOLATED and exactly one Candidate is produced.
func e7BuildOriginalCandidateWithSafety(t *testing.T, f *e7Fixture, sessionID string, safety actionauth.ActionSafety) (*Candidate, *TransitionRuleRegistry, *actionauth.ActionPolicy, TransitionRule) {
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
	policy := e7DenyOnlyPolicy(before.ProjectorID(), safety)
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
	return candidates[0], registry, policy, rule
}

// e7BuildOriginalCandidate is the common case: "deny" declared
// ActionStrictReadOnly, exactly as a rule author would need for it to ever
// be replayable.
func e7BuildOriginalCandidate(t *testing.T, f *e7Fixture, sessionID string) (*Candidate, *TransitionRuleRegistry, *actionauth.ActionPolicy, TransitionRule) {
	return e7BuildOriginalCandidateWithSafety(t, f, sessionID, actionauth.ActionStrictReadOnly)
}

// e7StatusKeyedPolicy registers TWO actions on the SAME projector, each
// applicable only for a specific "status" fact value: "deny" when
// status=="200", "aaa-other-action" when status=="403". Used ONLY by the
// E7-A action-authority tests below, where the point is that the SAME
// policy (same PolicyID) can legitimately select a DIFFERENT action for a
// DIFFERENT fresh baseline — never that the policy itself changed.
func e7StatusKeyedPolicy(projectorID stateauth.ProjectorID) *actionauth.ActionPolicy {
	registry := actionauth.NewRegistry(
		actionauth.Registration{
			Action:       actionauth.RegisteredAction{Key: "deny", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/deny")},
			Requirements: actionauth.StateRequirements{ProjectorID: projectorID, Facts: map[string]string{"status": "200"}},
		},
		actionauth.Registration{
			Action:       actionauth.RegisteredAction{Key: "aaa-other-action", Safety: actionauth.ActionStrictReadOnly, SpecID: HTTPActionSpecID("/deny")},
			Requirements: actionauth.StateRequirements{ProjectorID: projectorID, Facts: map[string]string{"status": "403"}},
		},
	)
	return actionauth.NewActionPolicy(registry, actionauth.NewRecoveryRegistry())
}

// e7BuildActionAuthorityTestCandidate is a dedicated fixture for the E7-A
// tests: it uses ExpectFactEquals (deliberately NOT ExpectFactTransition,
// which has its own precondition gate that would otherwise interfere with
// testing action-authority divergence specifically) and
// e7StatusKeyedPolicy, so the SAME PolicyID can be reused for a replay
// attempt whose fresh baseline has a genuinely DIFFERENT "status" than the
// original — making Select pick a different, equally-applicable action,
// never because the policy itself changed.
func e7BuildActionAuthorityTestCandidate(t *testing.T, f *e7Fixture, sessionID string) (*Candidate, *TransitionRuleRegistry, *actionauth.ActionPolicy, TransitionRule) {
	t.Helper()
	scope := e7ReplayTarget().Scope(sessionID)
	collector, err := NewHTTPCollector(f.ts.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(f.ts.URL, map[string]string{"deny": "/deny", "aaa-other-action": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	projector := stateauth.HTTPFixtureRegistry()
	meter := newBoundedRequestMeter(10)
	ctx := context.Background()

	before, beforeRaw, err := collectAndProject(ctx, collector, projector, scope, meter) // status=200
	if err != nil {
		t.Fatalf("baseline collect: %v", err)
	}
	policy := e7StatusKeyedPolicy(before.ProjectorID())
	boundAction, ok := policy.Select(scope.Hash(), before, nil)
	if !ok || boundAction.ID().RegistryKey != "deny" {
		t.Fatalf("setup: expected Select to pick 'deny' for status=200, got %+v ok=%v", boundAction.ID(), ok)
	}
	if err := executor.Execute(ContextWithRequestMeter(ctx, meter), boundAction); err != nil {
		t.Fatalf("execute deny: %v", err)
	}
	after, afterRaw, err := collectAndProject(ctx, collector, projector, scope, meter) // status=403
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
		RuleID:            "deny-must-keep-status-200",
		ActionID:          boundAction.ID(),
		ProjectorID:       before.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectFactEquals, Fact: "status", AfterValue: "200"}, // violated: after=403
		ExpectationSource: ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "e7-action-authority-test"},
	}
	registry, err := NewTransitionRuleRegistry(rule)
	if err != nil {
		t.Fatalf("NewTransitionRuleRegistry: %v", err)
	}
	candidates := NewStateMachineProducer(registry).Produce(TransitionCase{Transition: tr, Scope: scope})
	if len(candidates) != 1 {
		t.Fatalf("setup: expected exactly 1 real candidate, got %d", len(candidates))
	}
	return candidates[0], registry, policy, rule
}

func e7NewValidator(t *testing.T, f *e7Fixture, registry *TransitionRuleRegistry, policy *actionauth.ActionPolicy, target ReplayTarget, budget ReplayBudget) *StateMachineReplayValidator {
	t.Helper()
	collector, err := NewHTTPCollector(f.ts.URL, "/state")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewHTTPExecutor(f.ts.URL, map[string]string{"deny": "/deny", "aaa-other-action": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewStateMachineReplayValidator(target, registry, policy, collector, stateauth.HTTPFixtureRegistry(), executor, budget)
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
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c.Origin = Origin{Kind: OriginFuzz}
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayUnsupportedOrigin {
		t.Fatalf("Replay with non-OriginStateMachine candidate: err = %v, want %v", err, ErrReplayUnsupportedOrigin)
	}
}

// TestE7MissingBindingRejected: a Candidate that claims OriginStateMachine
// but was never actually produced by StateMachineProducer (so it has no
// stateMachineBinding at all) — never reachable through the real E6
// pipeline, but Replay must still refuse it cleanly rather than panic or
// silently proceed.
func TestE7MissingBindingRejected(t *testing.T) {
	f := newE7Fixture(t)
	_, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c := NewHypothesis("RC-test-1", "state_transition_expectation_violation", "title", "target", "rationale",
		Origin{Kind: OriginStateMachine}, nil, Provenance{})
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayMissingBinding {
		t.Fatalf("Replay with no StateMachineBinding: err = %v, want %v", err, ErrReplayMissingBinding)
	}
}

// TestE7EmptyRuleIDInBindingRejected: same idea, one level deeper — a
// binding that exists but carries an empty RuleID. Also never reachable via
// StateMachineProducer.Produce (which only ever sets ruleID from an
// already-validated, non-empty rule.RuleID), kept as a real defensive check.
func TestE7EmptyRuleIDInBindingRejected(t *testing.T) {
	f := newE7Fixture(t)
	_, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	c := NewHypothesis("RC-test-2", "state_transition_expectation_violation", "title", "target", "rationale",
		Origin{Kind: OriginStateMachine}, nil, Provenance{})
	c.stateMachineBinding = &StateMachineBinding{} // present, but empty RuleID
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayMissingRuleID {
		t.Fatalf("Replay with an empty-RuleID binding: err = %v, want %v", err, ErrReplayMissingRuleID)
	}
}

func TestE7UnknownRuleIDRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, _, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	emptyRegistry := e6MustRegistry(t) // a validator with NO rule registered under this RuleID at all
	v := e7NewValidator(t, f, emptyRegistry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayUnknownRule {
		t.Fatalf("Replay against a registry with no matching RuleID: err = %v, want %v", err, ErrReplayUnknownRule)
	}
}

// TestE7ActionMismatchRejected: the validator's OWN registry has since
// diverged from the one that produced the candidate — same RuleID, but a
// DIFFERENT ActionID. This is what "the candidate's bound identity vs. the
// resolved rule" actually checks; Refs plays no part in it. The SAME policy
// is reused, so this isolates the TransitionRuleRegistry divergence
// specifically, never a PolicyID mismatch.
func TestE7ActionMismatchRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, _, policy, rule := e7BuildOriginalCandidate(t, f, "original-session")
	divergedRule := rule
	divergedRule.ActionID = actionauth.ActionID{RegistryKey: "a-different-action"}
	divergedRegistry := e6MustRegistry(t, divergedRule)
	v := e7NewValidator(t, f, divergedRegistry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayActionMismatch {
		t.Fatalf("Replay against a registry whose rule now names a different ActionID: err = %v, want %v", err, ErrReplayActionMismatch)
	}
}

// TestE7ProjectorMismatchRejected: same idea, but the diverged rule now
// names a different ProjectorID.
func TestE7ProjectorMismatchRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, _, policy, rule := e7BuildOriginalCandidate(t, f, "original-session")
	divergedRule := rule
	divergedRule.ProjectorID = "a-different-projector"
	divergedRegistry := e6MustRegistry(t, divergedRule)
	v := e7NewValidator(t, f, divergedRegistry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayProjectorMismatch {
		t.Fatalf("Replay against a registry whose rule now names a different ProjectorID: err = %v, want %v", err, ErrReplayProjectorMismatch)
	}
}

func TestE7TargetMismatchRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	differentTarget := ReplayTarget{TargetID: "a-different-target", BuildID: "e7-build", Protocol: "http", HarnessID: "e7-harness"}
	v := e7NewValidator(t, f, registry, policy, differentTarget, e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayTargetMismatch {
		t.Fatalf("Replay against a differently-targeted validator: err = %v, want %v", err, ErrReplayTargetMismatch)
	}
}

// TestE7PolicyMismatchRejected (E7-E): this validator's OWN ActionPolicy
// has a DIFFERENT canonical registry content — and therefore a different
// PolicyID — than the one the candidate's action was originally bound
// under, even though it registers the exact same "deny" key. This is
// checked BEFORE any I/O: denyHitCount must stay at exactly 1 (the
// original run only).
func TestE7PolicyMismatchRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()

	// Same Key, but a DIFFERENT declared Safety -> a different PolicyID.
	differentPolicy := e7DenyOnlyPolicy(stateauth.HTTPStateProjector{}.ID(), actionauth.ActionReversible)

	v := e7NewValidator(t, f, registry, differentPolicy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayPolicyMismatch {
		t.Fatalf("Replay against a validator whose ActionPolicy has diverged: err = %v, want %v", err, ErrReplayPolicyMismatch)
	}
	if got := f.denyHitCount(); got != 1 {
		t.Fatalf("denyHitCount after a PolicyID mismatch = %d, want 1 (only the original run) — this check must happen before any I/O", got)
	}
}

// TestE7NonReadOnlyActionRejected (E7-D): the action's Safety, as declared
// on the SAME (matching-PolicyID) trusted policy both the original
// candidate and this replay validator use, is ActionReversible — not
// ActionStrictReadOnly. v1 implements no verified-recovery flow, so Replay
// refuses outright, reading Safety from the FRESH BoundAction Select
// itself produced — never from anything a TransitionRule declares.
func TestE7NonReadOnlyActionRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidateWithSafety(t, f, "original-session", actionauth.ActionReversible)
	f.reset()
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayActionNotReadOnly {
		t.Fatalf("Replay against an ActionReversible (not ActionStrictReadOnly) action: err = %v, want %v", err, ErrReplayActionNotReadOnly)
	}
}

func TestE7EmptySessionIDRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, ""); err != ErrReplaySessionIDRequired {
		t.Fatalf("Replay with empty sessionID: err = %v, want %v", err, ErrReplaySessionIDRequired)
	}
}

// --- E7-B: Candidate.Refs is never trusted for authority --------------------

// TestE7RefsMutationDoesNotAffectReplayResolution is the direct proof for
// E7-B: an external caller can freely rewrite every replay-relevant Refs
// entry after E6 produced the Candidate, and Replay's actual resolution
// (which rule, which action, which projector, which target) is completely
// unaffected — because it reads exclusively from the immutable
// StateMachineBinding, never from Refs.
func TestE7RefsMutationDoesNotAffectReplayResolution(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, rule := e7BuildOriginalCandidate(t, f, "original-session")

	// Corrupt every replay-relevant Refs entry an attacker-controlled caller
	// might try to retarget.
	c.Refs["rule_id"] = "some-other-trusted-rule-id"
	c.Refs["action_registry_key"] = "not-the-real-action"
	c.Refs["action_variant_id"] = "not-the-real-variant"
	c.Refs["projector_id"] = "not-the-real-projector"
	c.Refs["replay_target_hash"] = "not-the-real-target-hash"
	c.Refs["case_artifact_hash"] = "not-the-real-case-hash"
	c.Refs["policy_id"] = "not-the-real-policy-id"
	c.Refs["action_spec_id"] = "not-the-real-spec-id"

	f.reset() // genuinely fresh baseline
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	res, err := v.Replay(context.Background(), c, "replay-session-after-refs-corruption")
	if err != nil {
		t.Fatalf("Replay after Refs corruption returned an error: %v — resolution must be unaffected by Refs", err)
	}
	if res.Outcome != OutcomeReproduced {
		t.Fatalf("Replay after Refs corruption: Outcome = %q, want %q — the REAL binding must still resolve rule %q correctly", res.Outcome, OutcomeReproduced, rule.RuleID)
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
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session") // leaves f.status at 403
	if got := f.denyHitCount(); got != 1 {
		t.Fatalf("setup: denyHitCount = %d, want 1 (only the original run)", got)
	}
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
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
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()
	f.setDenyBreaks(false)
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	res, err := v.Replay(context.Background(), c, "replay-session")
	if err != nil {
		t.Fatalf("Replay (satisfied) returned an error: %v", err)
	}
	if res.Outcome != OutcomeNoSignal {
		t.Fatalf("Replay (satisfied) Outcome = %q, want %q", res.Outcome, OutcomeNoSignal)
	}
}

// --- E7-A: action authority stays with ActionPolicy, never the Rule --------

// TestE7ActionPolicySelectsDifferentActionProducesNoSignal is the core E7-A
// guarantee: the SAME trusted policy (SAME PolicyID as the one that
// authorized the original action) is reused for replay, but the fresh
// baseline's OWN facts (status is still 403, left over from the original
// run — deliberately NOT reset) make it select "aaa-other-action" instead
// of "deny". Replay must never fall back to forcing "deny" — it reports
// OutcomeNoSignal and executes NOTHING.
func TestE7ActionPolicySelectsDifferentActionProducesNoSignal(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildActionAuthorityTestCandidate(t, f, "original-session") // leaves f.status at 403

	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	res, err := v.Replay(context.Background(), c, "replay-session")
	if err != nil {
		t.Fatalf("Replay (policy selects a different action) returned an error: %v", err)
	}
	if res.Outcome != OutcomeNoSignal {
		t.Fatalf("Replay (policy selects a different action) Outcome = %q, want %q", res.Outcome, OutcomeNoSignal)
	}
	if got := f.denyHitCount(); got != 1 {
		t.Fatalf("denyHitCount after replay = %d, want 1 (only the original run) — Replay must never execute rule.ActionID when the policy selected something else", got)
	}
}

// TestE7ActionPolicySelectFailsProducesNoSignal: the SAME trusted policy
// (SAME PolicyID) has nothing applicable for a fresh baseline whose status
// matches NEITHER of its two Facts-gated registrations — Replay must not
// fall back to the rule's own ActionID.
func TestE7ActionPolicySelectFailsProducesNoSignal(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildActionAuthorityTestCandidate(t, f, "original-session")
	f.setStatus(http.StatusInternalServerError) // matches neither "200" nor "403"

	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	res, err := v.Replay(context.Background(), c, "replay-session")
	if err != nil {
		t.Fatalf("Replay (policy has nothing applicable) returned an error: %v", err)
	}
	if res.Outcome != OutcomeNoSignal {
		t.Fatalf("Replay (policy has nothing applicable) Outcome = %q, want %q", res.Outcome, OutcomeNoSignal)
	}
	if got := f.denyHitCount(); got != 1 {
		t.Fatalf("denyHitCount after replay = %d, want 1 (only the original run)", got)
	}
}

// --- violated again -> reproduced, with independent evidence ---------------

// TestE7ViolatedProducesReproducedWithIndependentEvidence is the core E7
// proof: a FRESH session (a different sessionID from the original),
// against the SAME ReplayTarget, independently re-collects, re-authorizes
// through the SAME trusted ActionPolicy, re-executes, and re-collects — and
// the rule is violated again. It also proves the replay's OWN case
// artifact hash is a DIFFERENT value from the original Candidate's
// case_artifact_hash, that the evidence carries the full identity chain
// (rule_id/policy_id/action_safety alongside fresh fingerprints), and that
// the Candidate is NEVER promoted by Replay itself.
func TestE7ViolatedProducesReproducedWithIndependentEvidence(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, rule := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset() // a genuinely fresh baseline, not reusing the old after-state
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())

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
	if len(res.Evidence) == 0 {
		t.Fatal("OutcomeReproduced must carry non-empty Evidence, not just a rationale string")
	}

	var beforeObs, afterObs, summary *Observation
	for i := range res.Evidence {
		switch res.Evidence[i].Kind {
		case "replay_before_fingerprint":
			beforeObs = &res.Evidence[i]
		case "replay_after_fingerprint":
			afterObs = &res.Evidence[i]
		case "replay_summary":
			summary = &res.Evidence[i]
		}
	}
	if beforeObs == nil || afterObs == nil {
		t.Fatal("OutcomeReproduced Evidence must include both a fresh before- and after-fingerprint observation")
	}
	if _, ok := artifactRef(*beforeObs, "state_fingerprint_hash"); !ok {
		t.Fatal("replay_before_fingerprint carries no state_fingerprint_hash")
	}
	if summary == nil {
		t.Fatal("ValidationResult.Evidence has no replay_summary observation")
	}
	binding, _ := c.StateMachineBinding()
	if binding.SpecID() == "" {
		t.Fatal("StateMachineBinding.SpecID() must be non-empty for a real HTTPExecutor-backed action")
	}
	for _, check := range []struct{ kind, want string }{
		{"rule_id", rule.RuleID},
		{"projector_id", string(rule.ProjectorID)},
		{"action_registry_key", rule.ActionID.RegistryKey},
		{"policy_id", binding.PolicyID()},
		{"action_spec_id", binding.SpecID()},
		{"action_safety", string(actionauth.ActionStrictReadOnly)},
		{"assessment", string(TransitionViolated)},
	} {
		got, ok := artifactRef(*summary, check.kind)
		if !ok || got != check.want {
			t.Fatalf("replay_summary[%s] = %q (ok=%v), want %q", check.kind, got, ok, check.want)
		}
	}
	requestCount, ok := artifactRef(*summary, "request_count")
	if !ok || requestCount == "" {
		t.Fatal("replay_summary has no request_count")
	}
	replayCaseHash, ok := artifactRef(*summary, "replay_case_artifact_hash")
	if !ok || replayCaseHash == "" {
		t.Fatal("replay_summary has no replay_case_artifact_hash")
	}
	if replayCaseHash == binding.CaseArtifactHash() {
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
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), ReplayBudget{MaxRequests: 2, MaxWallTime: 10 * time.Second})
	if _, err := v.Replay(context.Background(), c, "replay-session"); err == nil {
		t.Fatal("Replay with MaxRequests=2 (a full replay needs 3) = nil error, want an error")
	}
}

// TestE7WallTimeTimeoutIsError drives the baseline collection against a
// hanging endpoint with a tiny MaxWallTime — Replay must fail quickly
// (within a couple of seconds), never wait out the target's full delay.
func TestE7WallTimeTimeoutIsError(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
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
	v, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, policy, slowCollector, stateauth.HTTPFixtureRegistry(), executor, ReplayBudget{MaxRequests: 10, MaxWallTime: 50 * time.Millisecond})
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
	policy := actionauth.NewActionPolicy(actionauth.NewRegistry(), actionauth.NewRecoveryRegistry())
	validBudget := e7DefaultBudget()

	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), nil, policy, collector, projector, executor, validBudget); err == nil {
		t.Fatal("nil rules registry must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, nil, collector, projector, executor, validBudget); err == nil {
		t.Fatal("nil policy must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, policy, nil, projector, executor, validBudget); err == nil {
		t.Fatal("nil collector must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, policy, collector, nil, executor, validBudget); err == nil {
		t.Fatal("nil projector must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, policy, collector, projector, nil, validBudget); err == nil {
		t.Fatal("nil executor must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, policy, collector, projector, executor, ReplayBudget{MaxRequests: 0, MaxWallTime: time.Second}); err == nil {
		t.Fatal("MaxRequests=0 must be rejected")
	}
	if _, err := NewStateMachineReplayValidator(e7ReplayTarget(), registry, policy, collector, projector, executor, ReplayBudget{MaxRequests: 1, MaxWallTime: 0}); err == nil {
		t.Fatal("MaxWallTime=0 must be rejected")
	}
}
