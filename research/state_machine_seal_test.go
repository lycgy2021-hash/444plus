package research

import (
	"context"
	"testing"

	"gopoc/internal/actionauth"
	"gopoc/internal/model"
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
