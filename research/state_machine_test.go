package research

import (
	"testing"
	"time"

	"gopoc/internal/actionauth"
	"gopoc/internal/stateauth"
)

// This file tests only the PURE functions/values the S10 contract defines
// that actually live in package research (ExplorationScope.Hash,
// ExplorationBudget.Valid, StateTransition.ScopeConsistent, actionauth's
// zero-value-only capabilities). There is no explorer, no registry, and no
// execution logic to test yet — that is the point of a contract-only stage.
//
// The richer stateauth.Fingerprint tests (constructor-derived hashing,
// immutability, StateProjector interface shape and determinism) and the
// stateauth.Recovered tests now live in internal/stateauth's own test file,
// because — as of v7 — this package can no longer construct a non-zero
// stateauth.Fingerprint at all: newFingerprint is unexported to stateauth,
// not to research. That inability is itself proof the authority boundary
// works, not a gap in this file.

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

// --- actionauth capability boundary: compiler-enforced, and now bound to
// scope+state so a stale capability can never be replayed. ---

func TestBoundActionAndRecoveryAreOpaqueFromResearch(t *testing.T) {
	var a actionauth.BoundAction
	if a != (actionauth.BoundAction{}) {
		t.Fatal("a BoundAction must be the zero value until actionauth's own ActionPolicy exists")
	}
	var r actionauth.BoundRecovery
	if r != (actionauth.BoundRecovery{}) {
		t.Fatal("a BoundRecovery must be the zero value until actionauth's own recovery policy exists")
	}
	// A StateTransition can therefore only ever reference an inert BoundAction
	// today — there is no way, from package research, to build one that would
	// resolve to a real registered action.
	tr := StateTransition{Action: a}
	if tr.Action != (actionauth.BoundAction{}) {
		t.Fatal("StateTransition.Action must still be inert with no policy implemented")
	}
	// The zero-value capability must never validate for anything — proving
	// ValidFor is a real re-check, not a rubber stamp on an empty capability.
	if a.ValidFor("some-scope", "some-state") {
		t.Fatal("a zero-value BoundAction must never validate for any scope/state")
	}
	if r.ValidFor("some-scope") {
		t.Fatal("a zero-value BoundRecovery must never validate for any scope")
	}
}

// ActionSuggestion (what AI may offer) and actionauth.ActionID (what it names)
// are freely constructible — they are advisory and grant nothing. This is the
// intended asymmetry: advisory shapes are open, execution credentials are
// closed (and, unlike the credentials, live in a different package on purpose).
func TestActionSuggestionIsFreelyConstructibleAndAdvisoryOnly(t *testing.T) {
	s := ActionSuggestion{ActionID: actionauth.ActionID{RegistryKey: "http-probe", VariantID: "v1"}, Rationale: "looks worth trying"}
	if s.ActionID.RegistryKey != "http-probe" {
		t.Fatalf("ActionSuggestion should be a plain, freely constructible value: %+v", s)
	}
	// Critically: there is no function anywhere that turns an ActionSuggestion or
	// a bare ActionID into a BoundAction. That absence is the guarantee.
}

// --- stateauth.Fingerprint boundary, as seen from research: opaque. ---

// TestFingerprintIsOpaqueFromResearch proves research cannot construct a
// non-zero stateauth.Fingerprint at all — there is no exported constructor,
// and the unexported one lives in a package research does not control. This
// is the state-authority analogue of TestBoundActionAndRecoveryAreOpaqueFromResearch
// above, and it is the direct evidence for boundary 7's claim: "internally
// consistent is still not the same guarantee as authoritative" is closed by a
// package boundary, not by review discipline, because research literally has
// no path to a real Fingerprint value.
func TestFingerprintIsOpaqueFromResearch(t *testing.T) {
	// Fingerprint contains a map field, so its zero value is checked
	// field-by-field rather than with `!=` (unlike actionauth.BoundAction,
	// which has no map field and so is directly comparable).
	var fp stateauth.Fingerprint
	if fp.ScopeHash() != "" || fp.RawStateArtifactHash() != "" || fp.StateFingerprintHash() != "" || fp.ProjectorID() != "" {
		t.Fatalf("a zero-value Fingerprint must expose only empty/zero fields, got %+v", fp)
	}
	if len(fp.Facts()) != 0 {
		t.Fatalf("a zero-value Fingerprint must expose no facts, got %v", fp.Facts())
	}

	// A StateTransition/RecoveryPlan can therefore only ever reference an inert
	// Fingerprint today, exactly as they can only reference an inert BoundAction.
	tr := StateTransition{BeforeFingerprint: fp, AfterFingerprint: fp}
	if tr.ScopeConsistent() {
		t.Fatal("an all-zero-value transition must not report itself scope-consistent (ScopeHash is empty)")
	}
	plan := RecoveryPlan{Baseline: fp}
	if plan.Baseline.ScopeHash() != "" {
		t.Fatalf("RecoveryPlan.Baseline must still be inert with no StateProjector implemented: %+v", plan.Baseline)
	}
}

func TestStateTransitionScopeConsistentRejectsMismatch(t *testing.T) {
	// research cannot construct two Fingerprints with distinct, non-empty
	// ScopeHash values to prove the TRUE branch here (that requires a real
	// stateauth.StateProjector, which does not exist yet) — proving the FALSE
	// branches with only the zero value available is still the security-relevant
	// half of this contract: ScopeConsistent must never claim consistency it
	// cannot actually verify.
	var empty StateTransition
	if empty.ScopeConsistent() {
		t.Fatal("an empty/zero-value transition must not report itself consistent")
	}
	withScope := StateTransition{ScopeHash: "scope-1"}
	if withScope.ScopeConsistent() {
		t.Fatal("a non-empty ScopeHash against zero-value (empty-scope) fingerprints must not be consistent")
	}
}
