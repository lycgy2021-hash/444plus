package research

import (
	"testing"
	"time"

	"gopoc/internal/actionauth"
)

// This file tests only the PURE functions/values the S10 contract defines
// (ExplorationScope.Hash, ExplorationBudget.Valid, Recovered,
// StateTransition.ScopeConsistent, StateFingerprint's immutability). There is
// no explorer, no registry, and no execution logic to test yet — that is the
// point of a contract-only stage. These tests exist so the contract's own
// value-level guarantees are pinned before any implementation is built on top
// of them.

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

// BoundAction/BoundRecovery now live in a SEPARATE package (internal/actionauth)
// specifically so this is enforced by the Go compiler, not by convention within
// one package: there is no identifier this file could even write to construct
// one with a real identity — actionauth.BoundAction{id: ...} would not compile
// here, because `id` is unexported in actionauth and this file is in package
// research. The only value reachable from here is the zero value.
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

func TestStateFingerprintIsImmutable(t *testing.T) {
	facts := map[string]string{"role": "user"}
	fp := NewStateFingerprint("scope-1", "raw-hash", "fp-hash", facts)

	// Mutating the caller's original map after construction must not affect the
	// fingerprint (facts were copied in).
	facts["role"] = "admin"
	if fp.Facts()["role"] != "user" {
		t.Fatalf("fingerprint must not be affected by mutating the caller's original map, got %v", fp.Facts())
	}

	// Mutating the map RETURNED by Facts() must not affect the fingerprint either
	// (the getter returns a copy) — this is the tamper path that would have
	// desynchronized Facts from StateFingerprintHash.
	got := fp.Facts()
	got["role"] = "admin"
	got["injected"] = "true"
	if fp.Facts()["role"] != "user" || len(fp.Facts()) != 1 {
		t.Fatalf("Facts() must return a fresh copy each call, got %v after mutating a prior copy", fp.Facts())
	}

	if fp.ScopeHash() != "scope-1" || fp.RawStateArtifactHash() != "raw-hash" || fp.StateFingerprintHash() != "fp-hash" {
		t.Fatalf("getters did not return constructed values: %+v", fp)
	}
}

func TestRecoveredRequiresSameScopeAndSameFingerprint(t *testing.T) {
	fpIn := func(scope, hash string) StateFingerprint { return NewStateFingerprint(scope, "raw", hash, nil) }
	cases := []struct {
		name string
		o    RecoveryOutcome
		want bool
	}{
		{
			name: "same_scope_same_fingerprint",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fpIn("s1", "abc"), Result: fpIn("s1", "abc")},
			want: true,
		},
		{
			name: "same_scope_different_fingerprint",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fpIn("s1", "abc"), Result: fpIn("s1", "def")},
			want: false,
		},
		{
			// The critical case this round's audit exists for: two fingerprints
			// whose hash strings happen to match, but neither actually belongs to
			// the outcome's own declared scope (e.g. after crossing a disk/replay/
			// worker boundary and being paired with the wrong scope). A bare string
			// comparison of the hashes alone would wrongly call this recovered.
			name: "matching_hash_but_wrong_scope",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fpIn("s2", "abc"), Result: fpIn("s3", "abc")},
			want: false,
		},
		{
			name: "baseline_scope_mismatch_only",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fpIn("s2", "abc"), Result: fpIn("s1", "abc")},
			want: false,
		},
		{
			name: "empty_outcome_scope",
			o:    RecoveryOutcome{ScopeHash: "", Baseline: fpIn("", "abc"), Result: fpIn("", "abc")},
			want: false,
		},
		{
			name: "empty_baseline_hash_never_recovered",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fpIn("s1", ""), Result: fpIn("s1", "")},
			want: false,
		},
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
	// the recorded fingerprints (including their own scope), never a stored
	// conclusion.
}

func TestStateTransitionScopeConsistent(t *testing.T) {
	fp := func(scope string) StateFingerprint { return NewStateFingerprint(scope, "raw", "hash", nil) }
	consistent := StateTransition{
		ScopeHash:         "scope-1",
		BeforeFingerprint: fp("scope-1"),
		AfterFingerprint:  fp("scope-1"),
	}
	if !consistent.ScopeConsistent() {
		t.Fatal("matching scope hashes must be consistent")
	}
	inconsistentBefore := consistent
	inconsistentBefore.BeforeFingerprint = fp("scope-2")
	if inconsistentBefore.ScopeConsistent() {
		t.Fatal("a mismatched BeforeFingerprint scope must be inconsistent")
	}
	inconsistentAfter := consistent
	inconsistentAfter.AfterFingerprint = fp("scope-2")
	if inconsistentAfter.ScopeConsistent() {
		t.Fatal("a mismatched AfterFingerprint scope must be inconsistent")
	}
	var empty StateTransition
	if empty.ScopeConsistent() {
		t.Fatal("an empty/zero-value transition must not report itself consistent")
	}
}
