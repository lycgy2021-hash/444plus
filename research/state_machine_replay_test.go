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

// e7DenyOnlyPolicy is the TRUSTED ActionPolicy a real Explorer session for
// this target would use: exactly one registered action ("deny"), applicable
// to any state under the given ProjectorID. Both the original candidate's
// own transition AND a replay validator's action-authority check must go
// through a policy built this way — never one Replay invents for itself.
func e7DenyOnlyPolicy(projectorID stateauth.ProjectorID) *actionauth.ActionPolicy {
	registry := actionauth.NewRegistry(actionauth.Registration{
		Action:       actionauth.RegisteredAction{Key: "deny"},
		Requirements: actionauth.StateRequirements{ProjectorID: projectorID},
	})
	return actionauth.NewActionPolicy(registry, actionauth.NewRecoveryRegistry())
}

// e7BuildOriginalCandidate drives ONE real transition against f (baseline
// collect -> execute "deny" -> result collect, all real HTTP, authorized by
// the SAME e7DenyOnlyPolicy a real Explorer session would use) and runs it
// through the REAL E6 producer to get a genuine Candidate — exactly what a
// real Explorer session followed by StateMachineProducer.Produce would
// leave behind. The rule declares "deny must not change status away from
// 200" and ReadOnlyAction: true (this fixture's "deny" has no real-world
// consequence — see TransitionRule.ReadOnlyAction's own doc), so as long as
// f.breaks() is on (the default), this is VIOLATED and exactly one
// Candidate is produced.
func e7BuildOriginalCandidate(t *testing.T, f *e7Fixture, sessionID string) (*Candidate, *TransitionRuleRegistry, *actionauth.ActionPolicy, TransitionRule) {
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
	policy := e7DenyOnlyPolicy(before.ProjectorID())
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
		ReadOnlyAction:    true,
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
// resolved rule" actually checks; Refs plays no part in it.
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

// TestE7NonReadOnlyActionRejected (E7-C): a rule not attested ReadOnlyAction
// is refused outright — v1 implements no verified-recovery flow.
func TestE7NonReadOnlyActionRejected(t *testing.T) {
	f := newE7Fixture(t)
	c, _, policy, rule := e7BuildOriginalCandidate(t, f, "original-session")
	notReadOnlyRule := rule
	notReadOnlyRule.ReadOnlyAction = false
	registry := e6MustRegistry(t, notReadOnlyRule)
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayActionNotReadOnly {
		t.Fatalf("Replay against a non-ReadOnlyAction rule: err = %v, want %v", err, ErrReplayActionNotReadOnly)
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
// guarantee: even though the resolved rule names "deny", if the TRUSTED
// ActionPolicy given to this validator would select a DIFFERENT action for
// the fresh baseline (here, "aaa-other-action", which sorts first and is
// equally applicable), Replay must never fall back to forcing "deny" — it
// reports OutcomeNoSignal and executes NOTHING.
func TestE7ActionPolicySelectsDifferentActionProducesNoSignal(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset() // satisfy the precondition so we actually reach the action-authority step

	projectorID := stateauth.HTTPStateProjector{}.ID()
	multiActionRegistry := actionauth.NewRegistry(
		actionauth.Registration{Action: actionauth.RegisteredAction{Key: "aaa-other-action"}, Requirements: actionauth.StateRequirements{ProjectorID: projectorID}},
		actionauth.Registration{Action: actionauth.RegisteredAction{Key: "deny"}, Requirements: actionauth.StateRequirements{ProjectorID: projectorID}},
	)
	divergedPolicy := actionauth.NewActionPolicy(multiActionRegistry, actionauth.NewRecoveryRegistry())

	v := e7NewValidator(t, f, registry, divergedPolicy, e7ReplayTarget(), e7DefaultBudget())
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

// TestE7ActionPolicySelectFailsProducesNoSignal: the trusted ActionPolicy
// has nothing applicable at all for the fresh baseline (an empty registry)
// — Replay must not fall back to the rule's own ActionID.
func TestE7ActionPolicySelectFailsProducesNoSignal(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, _, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()

	emptyPolicy := actionauth.NewActionPolicy(actionauth.NewRegistry(), actionauth.NewRecoveryRegistry())
	v := e7NewValidator(t, f, registry, emptyPolicy, e7ReplayTarget(), e7DefaultBudget())
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
// case_artifact_hash, and that the Candidate is NEVER promoted by Replay
// itself.
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
	binding, _ := c.StateMachineBinding()
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
