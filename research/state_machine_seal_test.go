package research

import (
	"context"
	"testing"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/model"
	"gopoc/internal/stateauth"
)

// This file is S10-E8, the Integration Seal: proof that a real,
// OutcomeReproduced S10/E7 replay result actually flows through the
// EXISTING, already-frozen Engine.Validate/shouldPromote/Promote pipeline
// (research/validator.go, unchanged by this stage) and advances a real
// Candidate from Hypothesis to Reproducible — never through any new
// authority layer. StateMachineReplayValidator.Supports/Validate (added in
// state_machine_replay.go) are the ONLY new code this stage adds: a pure
// Origin check and a thin translation from the Engine's (ctx, model.Target,
// *Candidate) call shape to Replay's own (ctx, *Candidate, sessionID) one.
// Every authority decision (which rule, which action, same PolicyID, strict
// read-only, fresh session, no state preparation) is still made exactly
// where S10/E7 already made it — this stage never re-implements or
// second-guesses any of it.

// TestS10E8HypothesisReachesReproducibleThroughTheRealEngine is the core
// end-to-end proof: a real OriginStateMachine Candidate, produced by the
// real E6 pipeline against a real HTTP transition, is handed to a
// completely generic *Engine (research/validator.go, the same Engine every
// other Validator in this package already uses) wired with nothing but this
// one StateMachineReplayValidator. Engine.Validate — with NO S10/E7-specific
// code of its own — independently replays the hypothesis against a fresh
// session and, because the rule is violated again with Evidence satisfying
// the Candidate's own RequiredEvidence, promotes it to Reproducible.
func TestS10E8HypothesisReachesReproducibleThroughTheRealEngine(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, rule := e7BuildOriginalCandidate(t, f, "original-session")
	if c.State != Hypothesis {
		t.Fatalf("setup: Candidate.State = %q, want %q", c.State, Hypothesis)
	}
	f.reset() // a genuinely fresh baseline for the independent replay

	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	engine := NewEngine(NewRegistry(v))

	results, err := engine.Validate(context.Background(), model.Target{}, c)
	if err != nil {
		t.Fatalf("Engine.Validate returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Engine.Validate returned %d results, want exactly 1 (this validator)", len(results))
	}
	if results[0].Outcome != OutcomeReproduced {
		t.Fatalf("ValidationResult.Outcome = %q, want %q", results[0].Outcome, OutcomeReproduced)
	}

	if c.State != Reproducible {
		t.Fatalf("Candidate.State after Engine.Validate = %q, want %q — the Engine's OWN generic shouldPromote/Promote must have advanced it", c.State, Reproducible)
	}
	if len(c.Evidence) == 0 {
		t.Fatal("Candidate.Evidence must be non-empty after promotion — attachEvidence must have run")
	}
	if len(c.History) != 1 {
		t.Fatalf("Candidate.History has %d entries, want exactly 1 (the one promotion)", len(c.History))
	}
	entry := c.History[0]
	if entry.From != Hypothesis || entry.To != Reproducible {
		t.Fatalf("History[0] = %s->%s, want %s->%s", entry.From, entry.To, Hypothesis, Reproducible)
	}
	if entry.By != v.Name() {
		t.Fatalf("History[0].By = %q, want %q — the promotion must be attributed to the replay validator, never to an LLM or a human", entry.By, v.Name())
	}
	if len(entry.EvidenceRefs) == 0 {
		t.Fatal("History[0].EvidenceRefs must be non-empty — a promotion without cited evidence is exactly what Promote refuses")
	}

	// The rule's own identity must be independently confirmed, never assumed:
	// resolve it again through the SAME trusted registry Replay itself used.
	resolved, ok := registry.LookupByRuleID(rule.RuleID)
	if !ok || resolved.RuleID != rule.RuleID {
		t.Fatalf("setup sanity: rule %q must resolve from the SAME registry the validator used", rule.RuleID)
	}
}

// TestS10E8DoesNotPromoteWhenReplayFindsNothing is the negative half: a
// fresh replay that finds the rule SATISFIED (never reproduced) must leave
// the Candidate at exactly Hypothesis — the Engine's generic
// shouldPromote never fires on OutcomeNoSignal, and this stage adds no
// alternate path that could promote on anything less than a genuine
// OutcomeReproduced.
func TestS10E8DoesNotPromoteWhenReplayFindsNothing(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()
	f.setDenyBreaks(false) // the underlying bug is "fixed": deny no longer changes status

	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	engine := NewEngine(NewRegistry(v))

	results, err := engine.Validate(context.Background(), model.Target{}, c)
	if err != nil {
		t.Fatalf("Engine.Validate returned an error: %v", err)
	}
	if len(results) != 1 || results[0].Outcome != OutcomeNoSignal {
		t.Fatalf("results = %+v, want exactly one OutcomeNoSignal result", results)
	}
	if c.State != Hypothesis {
		t.Fatalf("Candidate.State = %q, want %q — a satisfied replay must never promote", c.State, Hypothesis)
	}
	if len(c.History) != 0 {
		t.Fatalf("Candidate.History has %d entries, want 0", len(c.History))
	}
}

// TestS10E8DoesNotPromoteWhenReplayIsRejectedBeforeAnyIO covers the
// authority-rejection path: a Candidate whose bound identity has diverged
// from this validator's own trusted registry (E7-A's own
// ErrReplayActionMismatch case) makes Replay return an error, which
// Engine.Validate treats as "this validator contributed no facts" — never a
// promotion, and never a panic or a silently swallowed authority failure.
func TestS10E8DoesNotPromoteWhenReplayIsRejectedBeforeAnyIO(t *testing.T) {
	f := newE7Fixture(t)
	c, _, policy, rule := e7BuildOriginalCandidate(t, f, "original-session")
	divergedRule := rule
	divergedRule.ActionID = actionauth.ActionID{RegistryKey: "a-different-action"}
	divergedRegistry := e6MustRegistry(t, divergedRule)

	v := e7NewValidator(t, f, divergedRegistry, policy, e7ReplayTarget(), e7DefaultBudget())
	engine := NewEngine(NewRegistry(v))

	results, err := engine.Validate(context.Background(), model.Target{}, c)
	if err != nil {
		t.Fatalf("Engine.Validate returned an error: %v — a per-validator error must be absorbed, not propagated", err)
	}
	if len(results) != 0 {
		t.Fatalf("results = %+v, want none — a validator that errors contributes no ValidationResult", results)
	}
	if c.State != Hypothesis {
		t.Fatalf("Candidate.State = %q, want %q — a rejected replay must never promote", c.State, Hypothesis)
	}
}

// TestS10E8ValidatorSupportsOnlyStateMachineOrigin proves Supports is the
// pure, no-I/O Origin check it claims to be, matching every other
// Validator's own Supports in this package.
func TestS10E8ValidatorSupportsOnlyStateMachineOrigin(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())

	if !v.Supports(c) {
		t.Fatal("Supports must be true for a real OriginStateMachine Candidate")
	}
	other := NewHypothesis("RC-test-seal", "some_type", "t", "target", "r", Origin{Kind: OriginFuzz}, nil, Provenance{})
	if v.Supports(other) {
		t.Fatal("Supports must be false for a non-OriginStateMachine Candidate")
	}
	if v.Supports(nil) {
		t.Fatal("Supports must be false for a nil Candidate")
	}
}

// --- "same-target physical binding": NewHTTPStateMachineReplayValidator ---

// TestNewHTTPStateMachineReplayValidatorRejectsOriginMismatch is the direct
// proof for the first S10/E8 hardening item: a ReplayTarget whose OriginID
// does NOT match the real network origin an HTTPProfile's Collector/
// Executor were actually built from must be refused at CONSTRUCTION time —
// before any Replay attempt, and therefore before any I/O.
func TestNewHTTPStateMachineReplayValidatorRejectsOriginMismatch(t *testing.T) {
	f := newE7Fixture(t)
	profile, err := NewHTTPProfile(ExplorationScope{}, f.ts.URL, "/state", map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	registry := e6MustRegistry(t) // empty but valid; construction fails on OriginID before this even matters
	policy := actionauth.NewActionPolicy(mustActionRegistry(t), actionauth.NewRecoveryRegistry())

	target := e7ReplayTarget()
	target.OriginID = "http://this-is-not-the-real-fixture-origin.invalid"
	if _, err := NewHTTPStateMachineReplayValidator(target, registry, policy, profile, stateauth.HTTPFixtureRegistry(), e7DefaultBudget()); err == nil {
		t.Fatal("construction must fail when target.OriginID does not match the profile's own OriginID")
	}

	emptyOrigin := e7ReplayTarget() // OriginID left at its zero value
	if _, err := NewHTTPStateMachineReplayValidator(emptyOrigin, registry, policy, profile, stateauth.HTTPFixtureRegistry(), e7DefaultBudget()); err == nil {
		t.Fatal("construction must fail when target.OriginID is empty")
	}

	if _, err := NewHTTPStateMachineReplayValidator(e7ReplayTarget(), registry, policy, nil, stateauth.HTTPFixtureRegistry(), e7DefaultBudget()); err == nil {
		t.Fatal("construction must fail when profile is nil")
	}
}

// TestNewHTTPStateMachineReplayValidatorAcceptsMatchingOriginAndReplays
// proves the positive case end-to-end: a ReplayTarget whose OriginID
// correctly names the SAME real origin an HTTPProfile was built from
// constructs successfully, and a real replay through it still reaches
// OutcomeReproduced — this construction path changes nothing about
// Replay's own behavior, only what is checked before it ever runs.
func TestNewHTTPStateMachineReplayValidatorAcceptsMatchingOriginAndReplays(t *testing.T) {
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, "original-session")
	f.reset()

	profile, err := NewHTTPProfile(ExplorationScope{}, f.ts.URL, "/state", map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	target := e7ReplayTarget()
	target.OriginID = profile.OriginID()

	v, err := NewHTTPStateMachineReplayValidator(target, registry, policy, profile, stateauth.HTTPFixtureRegistry(), e7DefaultBudget())
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Replay(context.Background(), c, "replay-session-via-http-profile")
	if err != nil {
		t.Fatalf("Replay through NewHTTPStateMachineReplayValidator returned an error: %v", err)
	}
	if res.Outcome != OutcomeReproduced {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, OutcomeReproduced)
	}
}

// --- "fresh-session inequality proof": OriginalScopeHash -------------------

// TestReplayRejectsSessionIDEqualToTheOriginalOne is the direct, structural
// proof for the second S10/E8 hardening item: replaying under the EXACT
// SAME sessionID the original candidate's own transition used must be
// refused BEFORE any I/O, because the freshly built scope hashes IDENTICAL
// to binding.OriginalScopeHash() — proving "fresh session" is checked, not
// merely produced by a generator that happens to avoid collisions.
func TestReplayRejectsSessionIDEqualToTheOriginalOne(t *testing.T) {
	const originalSessionID = "original-session"
	f := newE7Fixture(t)
	c, registry, policy, _ := e7BuildOriginalCandidate(t, f, originalSessionID)
	f.reset()

	v := e7NewValidator(t, f, registry, policy, e7ReplayTarget(), e7DefaultBudget())
	if _, err := v.Replay(context.Background(), c, originalSessionID); err != ErrReplaySessionNotFresh {
		t.Fatalf("Replay reusing the ORIGINAL sessionID: err = %v, want %v", err, ErrReplaySessionNotFresh)
	}
	if got := f.denyHitCount(); got != 1 {
		t.Fatalf("denyHitCount after a non-fresh-session rejection = %d, want 1 (only the original run) — this check must happen before any I/O", got)
	}
}

// TestStateMachineBindingCarriesOriginalScopeHash proves E6's Produce
// actually records the field the freshness check above depends on.
func TestStateMachineBindingCarriesOriginalScopeHash(t *testing.T) {
	f := newE7Fixture(t)
	c, _, _, _ := e7BuildOriginalCandidate(t, f, "original-session")
	binding, ok := c.StateMachineBinding()
	if !ok {
		t.Fatal("candidate must carry a StateMachineBinding")
	}
	if binding.OriginalScopeHash() == "" {
		t.Fatal("StateMachineBinding.OriginalScopeHash() must be non-empty for a real E6-produced candidate")
	}
	wantScope := e7ReplayTarget().Scope("original-session")
	if binding.OriginalScopeHash() != wantScope.Hash() {
		t.Fatalf("OriginalScopeHash() = %q, want %q (the original transition's own scope hash)", binding.OriginalScopeHash(), wantScope.Hash())
	}
}

// --- "original HTTP origin -> replay HTTP origin": strict origin binding ---

// TestReplayRejectsCandidateFromADifferentPhysicalOrigin is the direct
// proof for the LAST S10/E8 hardening item: a Candidate whose ORIGINAL
// TransitionCase declared one real HTTP origin (fixture server A) must be
// refused when replayed through a strict-origin-binding validator whose
// OWN real origin is a DIFFERENT server (B) — even though target.Hash()
// (TargetID/BuildID/Protocol/HarnessID — abstract labels) and the
// validator's own target/profile self-consistency check (target.OriginID
// == profile.OriginID(), both B) both agree with EACH OTHER. Proving "same
// logical target labels + internally consistent replay wiring" is NOT the
// same claim as "same physical HTTP origin as the original candidate" —
// exactly the gap ErrReplayOriginMismatch closes. Checked before any I/O:
// neither fixture's deny-hit counter moves.
func TestReplayRejectsCandidateFromADifferentPhysicalOrigin(t *testing.T) {
	serverA := newE7Fixture(t) // where the ORIGINAL candidate's transition actually ran
	c, registry, policy, _ := e7BuildOriginalCandidate(t, serverA, "original-session")
	serverA.reset()

	serverB := newE7Fixture(t) // a genuinely DIFFERENT real origin
	profileB, err := NewHTTPProfile(ExplorationScope{}, serverB.ts.URL, "/state", map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	targetB := e7ReplayTarget() // SAME abstract labels (TargetID/BuildID/Protocol/HarnessID) as the original
	targetB.OriginID = profileB.OriginID()

	v, err := NewHTTPStateMachineReplayValidator(targetB, registry, policy, profileB, stateauth.HTTPFixtureRegistry(), e7DefaultBudget())
	if err != nil {
		t.Fatalf("construction must succeed — targetB and profileB are self-consistent with EACH OTHER: %v", err)
	}

	if _, err := v.Replay(context.Background(), c, "replay-session-against-server-b"); err != ErrReplayOriginMismatch {
		t.Fatalf("Replay against a validator whose real origin differs from the original candidate's own: err = %v, want %v", err, ErrReplayOriginMismatch)
	}
	if got := serverA.denyHitCount(); got != 1 {
		t.Fatalf("serverA denyHitCount = %d, want 1 (only the original run)", got)
	}
	if got := serverB.denyHitCount(); got != 0 {
		t.Fatalf("serverB denyHitCount = %d, want 0 — the origin mismatch must be caught before any request ever reaches serverB", got)
	}
}

// TestReplayRejectsMissingOriginBindingUnderStrictValidator proves the
// other half: a strict-origin-binding validator refuses a candidate whose
// original TransitionCase never declared an OriginID at all (predates
// origin binding, or was produced by a caller that never set it) — it
// never treats "no evidence" as "matches anything".
func TestReplayRejectsMissingOriginBindingUnderStrictValidator(t *testing.T) {
	f := newE7Fixture(t)
	scope := e7ReplayTarget().Scope("original-session")
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
		t.Fatal(err)
	}
	policy := e7DenyOnlyPolicy(before.ProjectorID(), actionauth.ActionStrictReadOnly)
	boundAction, ok := policy.Select(scope.Hash(), before, nil)
	if !ok {
		t.Fatal("expected a match for 'deny'")
	}
	if err := executor.Execute(ContextWithRequestMeter(ctx, meter), boundAction); err != nil {
		t.Fatal(err)
	}
	after, afterRaw, err := collectAndProject(ctx, collector, projector, scope, meter)
	if err != nil {
		t.Fatal(err)
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
		RuleID:            "deny-must-not-change-status-no-origin",
		ActionID:          boundAction.ID(),
		ProjectorID:       before.ProjectorID(),
		Expectation:       TransitionExpectation{Kind: ExpectFactTransition, Fact: "status", BeforeValue: "200", AfterValue: "200"},
		ExpectationSource: ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "e7-test-config"},
	}
	registry, err := NewTransitionRuleRegistry(rule)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately NO OriginID on this TransitionCase — simulates a
	// candidate produced before origin binding existed.
	candidates := NewStateMachineProducer(registry).Produce(TransitionCase{Transition: tr, Scope: scope})
	if len(candidates) != 1 {
		t.Fatalf("setup: expected exactly 1 candidate, got %d", len(candidates))
	}
	c := candidates[0]

	f.reset()
	profile, err := NewHTTPProfile(ExplorationScope{}, f.ts.URL, "/state", map[string]string{"deny": "/deny"})
	if err != nil {
		t.Fatal(err)
	}
	target := e7ReplayTarget()
	target.OriginID = profile.OriginID()
	v, err := NewHTTPStateMachineReplayValidator(target, registry, policy, profile, stateauth.HTTPFixtureRegistry(), e7DefaultBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Replay(context.Background(), c, "replay-session"); err != ErrReplayMissingOriginBinding {
		t.Fatalf("Replay of an origin-less candidate under a strict validator: err = %v, want %v", err, ErrReplayMissingOriginBinding)
	}
}
