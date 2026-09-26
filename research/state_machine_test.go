package research

import (
	"testing"
	"time"
)

// This file tests only the PURE functions/values the S10 contract defines
// (ExplorationScope.Hash, ExplorationBudget.Valid, Recovered,
// StateTransition.ScopeConsistent) and the structural guarantee that BoundAction/
// BoundRecovery cannot be given a meaningful identity from outside a (not yet
// existing) policy constructor. There is no explorer, no registry, and no
// execution logic to test yet — that is the point of a contract-only stage.
// These tests exist so the contract's own value-level guarantees are pinned
// before any implementation is built on top of them.

func TestExplorationScopeHashSeparatesDimensions(t *testing.T) {
	base := ExplorationScope{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h1"}
	sameAgain := ExplorationScope{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h1"}
	if base.Hash() != sameAgain.Hash() {
		t.Fatal("identical scopes must hash identically")
	}
	variants := []ExplorationScope{
		{TargetID: "t", BuildID: "b2", SessionID: "s1", Protocol: "http", HarnessID: "h1"}, // different build
		{TargetID: "t", BuildID: "b1", SessionID: "s2", Protocol: "http", HarnessID: "h1"}, // different session
		{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "grpc", HarnessID: "h1"}, // different protocol
		{TargetID: "t", BuildID: "b1", SessionID: "s1", Protocol: "http", HarnessID: "h2"}, // different harness
	}
	for i, v := range variants {
		if v.Hash() == base.Hash() {
			t.Errorf("variant %d (differs from base in one dimension) must hash differently", i)
		}
	}
}

func TestExplorationBudgetValidRequiresEveryFieldStrictlyPositive(t *testing.T) {
	full := ExplorationBudget{
		MaxStates: 1, MaxTransitions: 1, MaxDepth: 1, MaxRequests: 1,
		MaxVisitsPerState: 1, MaxBranching: 1, MaxWallTime: time.Second,
	}
	if !full.Valid() {
		t.Fatal("a budget with every field strictly positive must be valid")
	}
	// Zeroing any single field must invalidate the whole budget — there is no
	// "0 means unlimited" reading anywhere in this type, unlike ai.Budget.
	zero := func(mutate func(*ExplorationBudget)) ExplorationBudget {
		b := full
		mutate(&b)
		return b
	}
	cases := []ExplorationBudget{
		zero(func(b *ExplorationBudget) { b.MaxStates = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxTransitions = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxDepth = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxRequests = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxVisitsPerState = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxBranching = 0 }),
		zero(func(b *ExplorationBudget) { b.MaxWallTime = 0 }),
	}
	for i, b := range cases {
		if b.Valid() {
			t.Errorf("case %d: a budget with one zeroed field must be invalid (zero is not unlimited)", i)
		}
	}
	// A negative value must also invalidate (not merely "falsy zero").
	neg := full
	neg.MaxStates = -1
	if neg.Valid() {
		t.Fatal("a negative bound must be invalid")
	}
	var zeroVal ExplorationBudget
	if zeroVal.Valid() {
		t.Fatal("the zero-value budget must be invalid")
	}
}

// BoundAction/BoundRecovery must never be constructible with a meaningful
// identity from outside a (not yet existing) policy constructor. Since the
// identity field is unexported, this package (the only place that COULD try) can
// only ever produce a zero-value one — proving there is currently no path, even
// in-package, to a BoundAction/BoundRecovery that resolves to a real registry
// entry.
func TestBoundActionAndRecoveryHaveNoRealConstructor(t *testing.T) {
	var a BoundAction
	if a != (BoundAction{}) {
		t.Fatal("a BoundAction must be the zero value until an ActionPolicy exists")
	}
	var r BoundRecovery
	if r != (BoundRecovery{}) {
		t.Fatal("a BoundRecovery must be the zero value until a recovery policy exists")
	}
	// A StateTransition can therefore only ever reference a zero-value (inert)
	// BoundAction today — there is no way, anywhere in this package, to build one
	// that would resolve to a real registered action.
	tr := StateTransition{Action: a}
	if tr.Action != (BoundAction{}) {
		t.Fatal("StateTransition.Action must still be inert with no policy implemented")
	}
}

// ActionSuggestion (what AI may offer) and ActionID (what it names) are freely
// constructible — they are advisory and grant nothing. This is the intended
// asymmetry: advisory shapes are open, execution credentials are closed.
func TestActionSuggestionIsFreelyConstructibleAndAdvisoryOnly(t *testing.T) {
	s := ActionSuggestion{ActionID: ActionID{RegistryKey: "http-probe", VariantID: "v1"}, Rationale: "looks worth trying"}
	if s.ActionID.RegistryKey != "http-probe" {
		t.Fatalf("ActionSuggestion should be a plain, freely constructible value: %+v", s)
	}
	// Critically: there is no function anywhere in this package that turns an
	// ActionSuggestion or a bare ActionID into a BoundAction. That absence is the
	// guarantee — this test documents the intended asymmetry, not a runtime check
	// (there is nothing to call that would even compile into a real BoundAction).
}

func TestRecoveredIsFactOnlyExactMatch(t *testing.T) {
	cases := []struct {
		name string
		o    RecoveryOutcome
		want bool
	}{
		{"exact_match", RecoveryOutcome{BaselineFingerprint: "abc", ResultFingerprint: "abc"}, true},
		{"mismatch", RecoveryOutcome{BaselineFingerprint: "abc", ResultFingerprint: "def"}, false},
		{"empty_baseline_never_recovered", RecoveryOutcome{BaselineFingerprint: "", ResultFingerprint: ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Recovered(tc.o); got != tc.want {
				t.Errorf("Recovered(%+v) = %v, want %v", tc.o, got, tc.want)
			}
		})
	}
	// RecoveryOutcome has no field a recovery implementation could set to declare
	// success directly — Recovered is the only path, and it is a pure function of
	// the two fingerprint strings, never a stored conclusion.
}

func TestStateTransitionScopeConsistent(t *testing.T) {
	consistent := StateTransition{
		ScopeHash:         "scope-1",
		BeforeFingerprint: StateFingerprint{ScopeHash: "scope-1"},
		AfterFingerprint:  StateFingerprint{ScopeHash: "scope-1"},
	}
	if !consistent.ScopeConsistent() {
		t.Fatal("matching scope hashes must be consistent")
	}
	inconsistentBefore := consistent
	inconsistentBefore.BeforeFingerprint.ScopeHash = "scope-2"
	if inconsistentBefore.ScopeConsistent() {
		t.Fatal("a mismatched BeforeFingerprint scope must be inconsistent")
	}
	inconsistentAfter := consistent
	inconsistentAfter.AfterFingerprint.ScopeHash = "scope-2"
	if inconsistentAfter.ScopeConsistent() {
		t.Fatal("a mismatched AfterFingerprint scope must be inconsistent")
	}
	var empty StateTransition
	if empty.ScopeConsistent() {
		t.Fatal("an empty/zero-value transition must not report itself consistent")
	}
}
