package actionauth

import (
	"testing"

	"gopoc/internal/stateauth"
)

// fp is a tiny helper for building a Fingerprint via the only path this
// package can: stateauth.RawLenProjector, which is the real (if minimal)
// production projector. actionauth cannot construct a stateauth.Fingerprint
// directly — proving, from actionauth's own tests, that Select really is
// state-dependent on something actionauth itself has no authority over.
func fp(t *testing.T, scopeHash string, raw []byte) stateauth.Fingerprint {
	t.Helper()
	f, err := stateauth.RawLenProjector{}.Project(stateauth.StateArtifact{ScopeHash: scopeHash, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// rawLenReq is a StateRequirements matching any Fingerprint produced by
// stateauth.RawLenProjector, regardless of its raw_len value — the
// declarative equivalent of "always applies", used throughout these tests.
func rawLenReq() StateRequirements {
	return StateRequirements{ProjectorID: stateauth.RawLenProjector{}.ID()}
}

func TestSelectPicksApplicableActionDeterministicallyBySortedKey(t *testing.T) {
	reg := NewRegistry(
		Registration{Action: RegisteredAction{Key: "zeta"}, Requirements: rawLenReq()},
		Registration{Action: RegisteredAction{Key: "alpha"}, Requirements: rawLenReq()},
	)
	policy := NewActionPolicy(reg, NewRecoveryRegistry("reset"))
	state := fp(t, "scope-1", []byte("AAAA"))

	a, ok := policy.Select("scope-1", state, nil)
	if !ok {
		t.Fatal("Select must find an applicable action when at least one Requirements matches the state")
	}
	if a.ID().RegistryKey != "alpha" {
		t.Fatalf("Select() picked %q, want the lexically-first applicable key \"alpha\" — selection must be deterministic, not map-iteration order", a.ID().RegistryKey)
	}
	if a.ID().VariantID != "" {
		t.Fatalf("Select() must never populate VariantID in v1, got %q", a.ID().VariantID)
	}
	if !a.ValidFor("scope-1", state.StateFingerprintHash()) {
		t.Fatal("a selected action must validate for exactly the scope/state Select was called with")
	}

	// Calling Select again with the same inputs must select the SAME action —
	// this is the whole point: (scope, state, registry, exclude) always
	// determines the same outcome.
	again, ok := policy.Select("scope-1", state, nil)
	if !ok || again.ID().RegistryKey != "alpha" {
		t.Fatal("Select must be deterministic across repeated calls with identical inputs")
	}
}

func TestSelectSkipsUnmatchedAndExcludedActions(t *testing.T) {
	otherProjector := StateRequirements{ProjectorID: "some-other-projector"}
	reg := NewRegistry(
		Registration{Action: RegisteredAction{Key: "unmatched"}, Requirements: otherProjector},
		Registration{Action: RegisteredAction{Key: "alpha"}, Requirements: rawLenReq()},
		Registration{Action: RegisteredAction{Key: "beta"}, Requirements: rawLenReq()},
	)
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	state := fp(t, "scope-1", []byte("AAAA"))

	// "unmatched" is registered for a different ProjectorID and never applies.
	a, ok := policy.Select("scope-1", state, nil)
	if !ok || a.ID().RegistryKey != "alpha" {
		t.Fatalf("expected alpha (the first applicable, non-excluded key), got %+v ok=%v", a.ID(), ok)
	}

	// Excluding "alpha" (e.g. already tried from this exact state) must fall
	// through to the next applicable candidate, "beta".
	b, ok := policy.Select("scope-1", state, map[string]bool{"alpha": true})
	if !ok || b.ID().RegistryKey != "beta" {
		t.Fatalf("expected beta once alpha is excluded, got %+v ok=%v", b.ID(), ok)
	}

	// Excluding everything applicable leaves nothing to select.
	if _, ok := policy.Select("scope-1", state, map[string]bool{"alpha": true, "beta": true}); ok {
		t.Fatal("Select must fail once every applicable action has been excluded")
	}
}

func TestMatchesRequiresExactProjectorIDAndFactSubset(t *testing.T) {
	state := fp(t, "scope-1", []byte("AAAA")) // RawLenProjector -> Facts{"raw_len":"4"}

	if matches(StateRequirements{ProjectorID: "rawlen-v1", Facts: map[string]string{"raw_len": "4"}}, state) != true {
		t.Fatal("a requirement whose ProjectorID and listed fact both match must match")
	}
	if matches(StateRequirements{ProjectorID: "rawlen-v1", Facts: map[string]string{"raw_len": "5"}}, state) {
		t.Fatal("a requirement whose listed fact disagrees with the state must not match")
	}
	if matches(StateRequirements{ProjectorID: "rawlen-v1", Facts: map[string]string{"nonexistent_fact": "x"}}, state) {
		t.Fatal("a requirement listing a fact the state does not have must not match")
	}
	if matches(StateRequirements{ProjectorID: "some-other-projector"}, state) {
		t.Fatal("a requirement for a different ProjectorID must never match, regardless of Facts")
	}
	if matches(StateRequirements{}, state) {
		t.Fatal("a zero-value StateRequirements (no ProjectorID) must match nothing — fail-closed")
	}
	// An empty Facts map with the right ProjectorID means "any facts" (a
	// subset match against zero required keys is vacuously satisfied).
	if !matches(StateRequirements{ProjectorID: "rawlen-v1"}, state) {
		t.Fatal("a requirement with the right ProjectorID and no Facts constraints must match")
	}
}

func TestSelectRequiresNonEmptyScopeAndValidFingerprint(t *testing.T) {
	reg := NewRegistry(Registration{Action: RegisteredAction{Key: "alpha"}, Requirements: rawLenReq()})
	policy := NewActionPolicy(reg, NewRecoveryRegistry())

	if _, ok := policy.Select("", fp(t, "scope-1", []byte("A")), nil); ok {
		t.Fatal("Select with an empty scope hash must fail")
	}
	// A zero-value Fingerprint has an empty StateFingerprintHash.
	if _, ok := policy.Select("scope-1", stateauth.Fingerprint{}, nil); ok {
		t.Fatal("Select with a zero-value (never-projected) Fingerprint must fail")
	}
}

func TestSelectNeverConsultsAnAdvisorySuggestion(t *testing.T) {
	// This test exists to document, not merely assert, v1's cleanest design
	// choice: Select's signature has no parameter through which an
	// AI-authored suggestion (or anything resembling one) could be passed at
	// all — there is nothing to wire in, and nothing to accidentally start
	// consulting later without a deliberate signature change reviewers would
	// have to notice. Requirements being plain data (not a closure) also means
	// there is no hidden side channel (a global, an env var, a clock) through
	// which an external actor could influence which key applicable() returns.
	reg := NewRegistry(Registration{Action: RegisteredAction{Key: "safe-action"}, Requirements: rawLenReq()})
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	state := fp(t, "scope-1", []byte("A"))
	a, ok := policy.Select("scope-1", state, nil)
	if !ok || a.ID().RegistryKey != "safe-action" {
		t.Fatalf("Select must pick the one applicable registered action regardless of any external suggestion, got %+v ok=%v", a.ID(), ok)
	}
}

func TestBindRecoveryRequiresRegisteredRecoveryAndNonEmptyHashes(t *testing.T) {
	policy := NewActionPolicy(NewRegistry(), NewRecoveryRegistry("reset-session"))

	r, ok := policy.BindRecovery(RecoveryPlanRef{RegistryKey: "reset-session"}, "scope-1", "baseline-1")
	if !ok {
		t.Fatal("binding a registered recovery with non-empty scope/baseline must succeed")
	}
	if r.Ref() != (RecoveryPlanRef{RegistryKey: "reset-session"}) {
		t.Fatalf("Ref() = %+v, want the bound RecoveryPlanRef", r.Ref())
	}
	if r.BaselineFingerprintHash() != "baseline-1" {
		t.Fatalf("BaselineFingerprintHash() = %q, want baseline-1", r.BaselineFingerprintHash())
	}
	if !r.ValidFor("scope-1") {
		t.Fatal("a freshly bound recovery must validate for the exact scope it was bound with")
	}
	if r.ValidFor("scope-2") {
		t.Fatal("a bound recovery must NOT validate for a different scope")
	}

	if _, ok := policy.BindRecovery(RecoveryPlanRef{RegistryKey: "unregistered-recovery"}, "scope-1", "baseline-1"); ok {
		t.Fatal("binding an unregistered recovery must fail")
	}
	if _, ok := policy.BindRecovery(RecoveryPlanRef{RegistryKey: "reset-session"}, "", "baseline-1"); ok {
		t.Fatal("binding with an empty scope hash must fail")
	}
	if _, ok := policy.BindRecovery(RecoveryPlanRef{RegistryKey: "reset-session"}, "scope-1", ""); ok {
		t.Fatal("binding with an empty baseline hash must fail")
	}
}

func TestNilAndZeroValuePolicyNeverSelectOrBind(t *testing.T) {
	var nilPolicy *ActionPolicy
	if _, ok := nilPolicy.Select("scope-1", fp(t, "scope-1", []byte("A")), nil); ok {
		t.Fatal("a nil *ActionPolicy must never select an action")
	}
	if _, ok := nilPolicy.BindRecovery(RecoveryPlanRef{RegistryKey: "anything"}, "s", "f"); ok {
		t.Fatal("a nil *ActionPolicy must never bind a recovery")
	}

	empty := NewActionPolicy(nil, nil)
	if _, ok := empty.Select("scope-1", fp(t, "scope-1", []byte("A")), nil); ok {
		t.Fatal("a policy with a nil registry must never select an action")
	}
	if _, ok := empty.BindRecovery(RecoveryPlanRef{RegistryKey: "anything"}, "s", "f"); ok {
		t.Fatal("a policy with a nil recovery registry must never bind")
	}
}

func TestRegistrationWithEmptyRequirementsFailsClosed(t *testing.T) {
	// A Registration given with a zero-value Requirements (no ProjectorID)
	// must match NOTHING — fail-closed — never silently default to "always
	// applicable".
	reg := NewRegistry(Registration{Action: RegisteredAction{Key: "no-requirements"}})
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	if _, ok := policy.Select("scope-1", fp(t, "scope-1", []byte("A")), nil); ok {
		t.Fatal("a Registration with empty Requirements must never be selected")
	}
}

func TestNewRegistryDeepCopiesRequirementsAndIsUnaffectedByLaterMutation(t *testing.T) {
	facts := map[string]string{"raw_len": "4"}
	regs := []Registration{
		{Action: RegisteredAction{Key: "alpha"}, Requirements: StateRequirements{ProjectorID: "rawlen-v1", Facts: facts}},
	}
	reg := NewRegistry(regs...)
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	state := fp(t, "scope-1", []byte("AAAA")) // RawLenProjector -> Facts{"raw_len":"4"}

	a, ok := policy.Select("scope-1", state, nil)
	if !ok || a.ID().RegistryKey != "alpha" {
		t.Fatalf("expected an initial match against alpha, got %+v ok=%v", a.ID(), ok)
	}

	// Mutate BOTH the original Facts map and the original regs slice after
	// construction — an "immutable registry" that a live reference could
	// still edit through would not actually be immutable.
	facts["raw_len"] = "999"
	regs[0].Action.Key = "renamed"

	b, ok := policy.Select("scope-1", state, nil)
	if !ok || b.ID().RegistryKey != "alpha" {
		t.Fatalf("mutating the caller's original Facts map/regs slice after NewRegistry must not affect Select, got %+v ok=%v", b.ID(), ok)
	}
}

func TestRegistryHasNoWayToAddAfterConstruction(t *testing.T) {
	reg := NewRegistry(Registration{Action: RegisteredAction{Key: "http-probe"}, Requirements: rawLenReq()})
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	state := fp(t, "scope-1", []byte("A"))
	// There is no exported method on Registry that adds an entry — this test
	// documents that absence by construction: only http-probe, given at
	// NewRegistry time, was ever registered, and excluding it must leave
	// nothing else to select, ever.
	if _, ok := policy.Select("scope-1", state, map[string]bool{"http-probe": true}); ok {
		t.Fatal("an action never passed to NewRegistry must never be selectable, at any point in this registry's lifetime")
	}
}

// --- PolicyID / Safety: S10/E7 needs these to prove a replay used the
// SAME action-authority semantics as the original, and to read the ONE
// trustworthy safety signal for an action — see BoundAction.Safety/
// PolicyID's own doc.

func TestActionPolicyIDStableForIdenticalRegistryContent(t *testing.T) {
	build := func() *ActionPolicy {
		return NewActionPolicy(
			NewRegistry(Registration{Action: RegisteredAction{Key: "alpha", Safety: ActionStrictReadOnly}, Requirements: rawLenReq()}),
			NewRecoveryRegistry("reset"),
		)
	}
	p1, p2 := build(), build()
	if p1.PolicyID() == "" {
		t.Fatal("PolicyID() must not be empty for a non-empty registry")
	}
	if p1.PolicyID() != p2.PolicyID() {
		t.Fatalf("two ActionPolicy values built from identically-shaped registries must share a PolicyID: %q != %q", p1.PolicyID(), p2.PolicyID())
	}
}

func TestActionPolicyIDChangesWhenRegistryContentChanges(t *testing.T) {
	base := NewActionPolicy(
		NewRegistry(Registration{Action: RegisteredAction{Key: "alpha", Safety: ActionStrictReadOnly}, Requirements: rawLenReq()}),
		NewRecoveryRegistry("reset"),
	)
	variants := []*ActionPolicy{
		NewActionPolicy(NewRegistry(Registration{Action: RegisteredAction{Key: "alpha", Safety: ActionReversible}, Requirements: rawLenReq()}), NewRecoveryRegistry("reset")),                                           // different Safety
		NewActionPolicy(NewRegistry(Registration{Action: RegisteredAction{Key: "beta", Safety: ActionStrictReadOnly}, Requirements: rawLenReq()}), NewRecoveryRegistry("reset")),                                        // different Key
		NewActionPolicy(NewRegistry(Registration{Action: RegisteredAction{Key: "alpha", Safety: ActionStrictReadOnly}, Requirements: StateRequirements{ProjectorID: "other-projector"}}), NewRecoveryRegistry("reset")), // different ProjectorID
	}
	for i, v := range variants {
		if v.PolicyID() == base.PolicyID() {
			t.Errorf("variant %d (differs from base) must have a different PolicyID, got the same %q", i, v.PolicyID())
		}
	}
}

func TestActionPolicyIDUnaffectedByRecoveryRegistry(t *testing.T) {
	reg := NewRegistry(Registration{Action: RegisteredAction{Key: "alpha", Safety: ActionStrictReadOnly}, Requirements: rawLenReq()})
	p1 := NewActionPolicy(reg, NewRecoveryRegistry("reset"))
	p2 := NewActionPolicy(reg, NewRecoveryRegistry("a-completely-different-recovery-key"))
	if p1.PolicyID() != p2.PolicyID() {
		t.Fatalf("PolicyID must depend only on the action registry, never the recovery registry: %q != %q", p1.PolicyID(), p2.PolicyID())
	}
}

func TestSelectStampsSafetyAndPolicyIDFromMatchedRegistration(t *testing.T) {
	reg := NewRegistry(
		Registration{Action: RegisteredAction{Key: "readonly-action", Safety: ActionStrictReadOnly}, Requirements: rawLenReq()},
		Registration{Action: RegisteredAction{Key: "reversible-action", Safety: ActionReversible}, Requirements: StateRequirements{ProjectorID: "no-such-projector"}}, // never applicable to our fp
	)
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	state := fp(t, "scope-1", []byte("A"))

	bound, ok := policy.Select("scope-1", state, nil)
	if !ok || bound.ID().RegistryKey != "readonly-action" {
		t.Fatalf("Select() = %+v, ok=%v, want readonly-action", bound.ID(), ok)
	}
	if bound.Safety() != ActionStrictReadOnly {
		t.Fatalf("BoundAction.Safety() = %q, want %q (read from the matched Registration, not supplied by the caller)", bound.Safety(), ActionStrictReadOnly)
	}
	if bound.PolicyID() != policy.PolicyID() {
		t.Fatalf("BoundAction.PolicyID() = %q, want %q (this policy's own PolicyID)", bound.PolicyID(), policy.PolicyID())
	}
}

func TestZeroValueBoundActionHasEmptySafetyAndPolicyID(t *testing.T) {
	var zero BoundAction
	if zero.Safety() != "" || zero.PolicyID() != "" || zero.SpecID() != "" {
		t.Fatalf("zero-value BoundAction: Safety()=%q PolicyID()=%q SpecID()=%q, want all empty", zero.Safety(), zero.PolicyID(), zero.SpecID())
	}
}

// --- SpecID / ActionPolicySemanticsVersion: S10/E7's final two freeze
// blockers — PolicyID must also cover "what actually executes" (SpecID) and
// must be forced to change if the matching/selection SEMANTICS this file
// implements ever change, even with byte-identical registry data — see
// RegisteredAction.SpecID and ActionPolicySemanticsVersion's own doc.

func TestSelectStampsSpecIDFromMatchedRegistration(t *testing.T) {
	reg := NewRegistry(Registration{Action: RegisteredAction{Key: "http-probe", Safety: ActionStrictReadOnly, SpecID: "spec-abc"}, Requirements: rawLenReq()})
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	state := fp(t, "scope-1", []byte("A"))

	bound, ok := policy.Select("scope-1", state, nil)
	if !ok {
		t.Fatal("Select must find the applicable action")
	}
	if bound.SpecID() != "spec-abc" {
		t.Fatalf("BoundAction.SpecID() = %q, want %q (read from the matched Registration, not supplied by the caller)", bound.SpecID(), "spec-abc")
	}
}

func TestActionPolicyIDChangesWhenSpecIDChanges(t *testing.T) {
	base := NewActionPolicy(
		NewRegistry(Registration{Action: RegisteredAction{Key: "alpha", Safety: ActionStrictReadOnly, SpecID: "spec-v1"}, Requirements: rawLenReq()}),
		NewRecoveryRegistry("reset"),
	)
	changed := NewActionPolicy(
		NewRegistry(Registration{Action: RegisteredAction{Key: "alpha", Safety: ActionStrictReadOnly, SpecID: "spec-v2"}, Requirements: rawLenReq()}),
		NewRecoveryRegistry("reset"),
	)
	if base.PolicyID() == changed.PolicyID() {
		t.Fatalf("PolicyID must change when SpecID changes — a different executable spec is a different action-authority semantics, got the same %q for both", base.PolicyID())
	}
}

func TestActionPolicySemanticsVersionIsFoldedIntoPolicyID(t *testing.T) {
	// This test documents, rather than exercises a second version (there is
	// only one today), that ActionPolicySemanticsVersion is a real,
	// non-empty component of the hashed input — proven indirectly: changing
	// canonicalHash's semantics-version line would change every PolicyID,
	// which is exactly why the constant exists. We assert its current,
	// frozen value here so a future accidental edit to it is caught as a
	// test failure, not a silent behavior change.
	if ActionPolicySemanticsVersion != "action-policy-v1" {
		t.Fatalf("ActionPolicySemanticsVersion = %q, want the frozen v1 value %q — bump only via a deliberate, reviewed v2", ActionPolicySemanticsVersion, "action-policy-v1")
	}
}
