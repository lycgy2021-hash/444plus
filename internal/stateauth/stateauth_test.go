package stateauth

import (
	"strconv"
	"testing"
)

// This package is contract-only: no ActionPolicy-equivalent registry and no
// concrete StateProjector implementation exist yet. These tests pin two
// things: (1) newFingerprint itself is deterministic and produces a genuinely
// immutable, internally-consistent value — that can only be tested from
// INSIDE this package, since newFingerprint is unexported specifically so no
// other package (including research) can call it; and (2) the pure functions
// that operate on Fingerprint values (Recovered) behave correctly given
// controlled inputs only this package can construct.

func TestFingerprintHashesAreConstructorDerivedNeverCallerSupplied(t *testing.T) {
	// Same facts (any key order), same raw bytes -> identical fingerprint hashes.
	f1 := newFingerprint("scope-1", []byte("raw-bytes"), "proj-1", map[string]string{"role": "user", "stage": "login"})
	f2 := newFingerprint("scope-1", []byte("raw-bytes"), "proj-1", map[string]string{"stage": "login", "role": "user"})
	if f1.StateFingerprintHash() != f2.StateFingerprintHash() {
		t.Fatal("identical facts (any map iteration/insertion order) must hash identically")
	}
	if f1.RawStateArtifactHash() != f2.RawStateArtifactHash() {
		t.Fatal("identical raw artifact bytes must hash identically")
	}

	// A single changed fact value must change StateFingerprintHash but NOT
	// RawStateArtifactHash (the two hashes are independent, per different inputs).
	f3 := newFingerprint("scope-1", []byte("raw-bytes"), "proj-1", map[string]string{"role": "admin", "stage": "login"})
	if f3.StateFingerprintHash() == f1.StateFingerprintHash() {
		t.Fatal("a changed fact value must change StateFingerprintHash")
	}
	if f3.RawStateArtifactHash() != f1.RawStateArtifactHash() {
		t.Fatal("changing facts must not change RawStateArtifactHash (independent inputs)")
	}

	// Different raw bytes, same facts -> different RawStateArtifactHash but the
	// SAME StateFingerprintHash (it depends only on facts).
	f4 := newFingerprint("scope-1", []byte("different-raw-bytes"), "proj-1", map[string]string{"role": "user", "stage": "login"})
	if f4.RawStateArtifactHash() == f1.RawStateArtifactHash() {
		t.Fatal("different raw bytes must change RawStateArtifactHash")
	}
	if f4.StateFingerprintHash() != f1.StateFingerprintHash() {
		t.Fatal("StateFingerprintHash must depend only on facts, not on raw bytes")
	}

	// There is no constructor parameter through which a caller could supply
	// either hash directly — this test documents that absence: the ONLY inputs
	// newFingerprint accepts are scopeHash, rawArtifact bytes, projectorID, and
	// facts.
	if f1.ProjectorID() != "proj-1" {
		t.Fatalf("ProjectorID getter did not return the constructed value: %+v", f1)
	}
}

func TestFingerprintIsImmutable(t *testing.T) {
	facts := map[string]string{"role": "user"}
	fp := newFingerprint("scope-1", []byte("raw-artifact"), "proj-1", facts)

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
	fp := func(scope string, facts map[string]string) Fingerprint {
		return newFingerprint(scope, []byte("raw"), "proj-1", facts)
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
			// The critical case an earlier audit round closed: two fingerprints
			// whose hash happens to match (same facts), but NEITHER actually
			// belongs to the outcome's own declared scope. A bare hash-string
			// comparison alone would wrongly call this recovered.
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
			// A zero-value (never constructed) Fingerprint has an empty hash —
			// Recovered's defense-in-depth check must reject it even if ScopeHash
			// superficially lines up.
			name: "uninitialized_fingerprint_never_recovered",
			o:    RecoveryOutcome{ScopeHash: "s1", Baseline: Fingerprint{}, Result: Fingerprint{}},
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

// --- StateProjector: the ONLY authoritative source of Facts. ---

// stateProjectorStub is a TEST-ONLY mock proving the StateProjector interface
// is usable and that a real implementation would be deterministic — it is NOT
// a production projector (none exists yet; see StateProjector's own doc). It
// can only live HERE, inside package stateauth, because its Project method
// must call newFingerprint — which is exactly the point: a type implementing
// this interface from any other package could never do that.
type stateProjectorStub struct{}

func (stateProjectorStub) ID() ProjectorID { return "stub-v1" }

func (stateProjectorStub) Project(a StateArtifact) (Fingerprint, error) {
	return newFingerprint(a.ScopeHash, a.Raw, "stub-v1", map[string]string{"len": strconv.Itoa(len(a.Raw))}), nil
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
	if fp1.ProjectorID() != "stub-v1" {
		t.Fatalf("projected fingerprint ProjectorID = %q, want stub-v1", fp1.ProjectorID())
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

// TestFingerprintHasNoConstructorOutsideThisFile documents, rather than tests
// at runtime (Go's type system already enforces it at compile time), the
// contract's central claim: newFingerprint is unexported, so this is the ONLY
// file in the ONLY package that can ever call it. Any other package —
// research, a future AI-glue file, a future Explorer — can only ever obtain
// the zero-value Fingerprint{}. (Fingerprint contains a map field, so its
// zero value is checked field-by-field rather than with `!=`.)
func TestFingerprintHasNoConstructorOutsideThisFile(t *testing.T) {
	var zero Fingerprint
	if zero.ScopeHash() != "" || zero.RawStateArtifactHash() != "" || zero.StateFingerprintHash() != "" || zero.ProjectorID() != "" || len(zero.Facts()) != 0 {
		t.Fatalf("Fingerprint's zero value must be entirely empty, got %+v", zero)
	}
}
