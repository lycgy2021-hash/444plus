package research

import (
	"strconv"
	"testing"
	"time"

	"gopoc/internal/actionauth"
)

// This file tests only the PURE functions/values the S10 contract defines
// (ExplorationScope.Hash, ExplorationBudget.Valid, Recovered,
// StateTransition.ScopeConsistent, StateFingerprint's constructor-only hashing
// and immutability, actionauth's zero-value-only capabilities). There is no
// explorer, no registry, and no execution logic to test yet — that is the
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

// --- StateFingerprint: immutable AND internally consistent (two different
// guarantees — see boundary 6's doc). ---

func TestStateFingerprintHashesAreConstructorDerivedNeverCallerSupplied(t *testing.T) {
	// Same facts (any key order), same raw bytes -> identical fingerprint hashes.
	f1 := newStateFingerprint("scope-1", []byte("raw-bytes"), map[string]string{"role": "user", "stage": "login"})
	f2 := newStateFingerprint("scope-1", []byte("raw-bytes"), map[string]string{"stage": "login", "role": "user"})
	if f1.StateFingerprintHash() != f2.StateFingerprintHash() {
		t.Fatal("identical facts (any map iteration/insertion order) must hash identically")
	}
	if f1.RawStateArtifactHash() != f2.RawStateArtifactHash() {
		t.Fatal("identical raw artifact bytes must hash identically")
	}

	// A single changed fact value must change StateFingerprintHash but NOT
	// RawStateArtifactHash (the two hashes are independent, per different inputs).
	f3 := newStateFingerprint("scope-1", []byte("raw-bytes"), map[string]string{"role": "admin", "stage": "login"})
	if f3.StateFingerprintHash() == f1.StateFingerprintHash() {
		t.Fatal("a changed fact value must change StateFingerprintHash")
	}
	if f3.RawStateArtifactHash() != f1.RawStateArtifactHash() {
		t.Fatal("changing facts must not change RawStateArtifactHash (independent inputs)")
	}

	// Different raw bytes, same facts -> different RawStateArtifactHash but the
	// SAME StateFingerprintHash (it depends only on facts).
	f4 := newStateFingerprint("scope-1", []byte("different-raw-bytes"), map[string]string{"role": "user", "stage": "login"})
	if f4.RawStateArtifactHash() == f1.RawStateArtifactHash() {
		t.Fatal("different raw bytes must change RawStateArtifactHash")
	}
	if f4.StateFingerprintHash() != f1.StateFingerprintHash() {
		t.Fatal("StateFingerprintHash must depend only on facts, not on raw bytes")
	}

	// There is no constructor parameter through which a caller could supply
	// either hash directly — this test documents that absence: the ONLY inputs
	// newStateFingerprint accepts are scopeHash, rawArtifact bytes, and facts.
}

func TestStateFingerprintIsImmutable(t *testing.T) {
	facts := map[string]string{"role": "user"}
	fp := newStateFingerprint("scope-1", []byte("raw-artifact"), facts)

	// Mutating the caller's original map after construction must not affect the
	// fingerprint (facts were copied in) — and, since the hash was computed from
	// the copy at construction time, this also can't desynchronize the hash.
	facts["role"] = "admin"
	if fp.Facts()["role"] != "user" {
		t.Fatalf("fingerprint must not be affected by mutating the caller's original map, got %v", fp.Facts())
	}

	// Mutating the map RETURNED by Facts() must not affect the fingerprint either
	// (the getter returns a copy).
	got := fp.Facts()
	got["role"] = "admin"
	got["injected"] = "true"
	if fp.Facts()["role"] != "user" || len(fp.Facts()) != 1 {
		t.Fatalf("Facts() must return a fresh copy each call, got %v after mutating a prior copy", fp.Facts())
	}

	if fp.ScopeHash() != "scope-1" {
		t.Fatalf("ScopeHash getter did not return the constructed value: %+v", fp)
	}
}

func TestRecoveredRequiresSameScopeAndSameFingerprint(t *testing.T) {
	fp := func(scope string, facts map[string]string) StateFingerprint {
		return newStateFingerprint(scope, []byte("raw"), facts)
	}
	sameFacts := map[string]string{"stage": "idle"}
	diffFacts := map[string]string{"stage": "busy"}

	cases := []struct {
		name string
		o    RecoveryOutcome
		want bool
	}{
		{
			name: "same_scope_same_fingerprint",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fp("s1", sameFacts), Result: fp("s1", sameFacts)},
			want: true,
		},
		{
			name: "same_scope_different_fingerprint",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fp("s1", sameFacts), Result: fp("s1", diffFacts)},
			want: false,
		},
		{
			// The critical case this audit closed: two fingerprints whose hash
			// happens to match (same facts), but NEITHER actually belongs to the
			// outcome's own declared scope. A bare hash-string comparison alone
			// would wrongly call this recovered.
			name: "matching_hash_but_wrong_scope",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fp("s2", sameFacts), Result: fp("s3", sameFacts)},
			want: false,
		},
		{
			name: "baseline_scope_mismatch_only",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: fp("s2", sameFacts), Result: fp("s1", sameFacts)},
			want: false,
		},
		{
			name: "empty_outcome_scope",
			o:    RecoveryOutcome{ScopeHash: "", Baseline: fp("", sameFacts), Result: fp("", sameFacts)},
			want: false,
		},
		{
			// A zero-value (never constructed) StateFingerprint has an empty hash —
			// Recovered's defense-in-depth check must reject it even if ScopeHash
			// superficially lines up.
			name: "uninitialized_fingerprint_never_recovered",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: StateFingerprint{}, Result: StateFingerprint{}},
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
	fp := func(scope string) StateFingerprint { return newStateFingerprint(scope, []byte("raw"), nil) }
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

// --- StateProjector: the ONLY authoritative source of Facts. ---

// stateProjectorStub is a TEST-ONLY mock proving the StateProjector interface
// is usable and that a real implementation would be deterministic — it is NOT
// a production projector (none exists yet; see StateProjector's own doc). Using
// it here does not pre-empt "no implementation exists yet": nothing in the
// non-test source calls it or anything like it.
type stateProjectorStub struct{}

func (stateProjectorStub) ID() ProjectorID { return "stub-v1" }

func (stateProjectorStub) Project(a StateArtifact) (StateFingerprint, error) {
	return newStateFingerprint(a.ScopeHash, a.Raw, map[string]string{"len": strconv.Itoa(len(a.Raw))}), nil
}

func TestStateProjectorInterfaceShapeAndDeterminism(t *testing.T) {
	var p StateProjector = stateProjectorStub{}
	if p.ID() != "stub-v1" {
		t.Fatalf("ID() = %q", p.ID())
	}
	fp1, err := p.Project(StateArtifact{ScopeHash: "s1", Raw: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if fp1.ScopeHash() != "s1" {
		t.Fatalf("projected fingerprint scope = %q, want s1", fp1.ScopeHash())
	}
	// Determinism: the same raw artifact must always project to the same
	// fingerprint — this is the whole point of routing Facts through a
	// StateProjector instead of letting a caller assert them directly.
	fp2, err := p.Project(StateArtifact{ScopeHash: "s1", Raw: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if fp1.StateFingerprintHash() != fp2.StateFingerprintHash() {
		t.Fatal("a StateProjector must be deterministic: identical raw input must project identically")
	}
	// Different raw input must (in this stub) project differently.
	fp3, _ := p.Project(StateArtifact{ScopeHash: "s1", Raw: []byte("goodbye")})
	if fp3.StateFingerprintHash() == fp1.StateFingerprintHash() {
		t.Fatal("different raw input should project to a different fingerprint in this stub")
	}
}
