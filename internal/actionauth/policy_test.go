package actionauth

import "testing"

func TestBindRequiresRegisteredActionAndNonEmptyHashes(t *testing.T) {
	reg := NewRegistry(RegisteredAction{Key: "http-probe", Reversible: true})
	policy := NewActionPolicy(reg, NewRecoveryRegistry("reset-session"))

	a, ok := policy.Bind(ActionID{RegistryKey: "http-probe"}, "scope-1", "state-1")
	if !ok {
		t.Fatal("binding a registered action with non-empty scope/state must succeed")
	}
	if a.ID() != (ActionID{RegistryKey: "http-probe"}) {
		t.Fatalf("ID() = %+v, want the bound ActionID", a.ID())
	}
	if !a.ValidFor("scope-1", "state-1") {
		t.Fatal("a freshly bound action must validate for the exact scope/state it was bound with")
	}
	if a.ValidFor("scope-2", "state-1") || a.ValidFor("scope-1", "state-2") {
		t.Fatal("a bound action must NOT validate for a different scope or state")
	}

	if _, ok := policy.Bind(ActionID{RegistryKey: "unregistered-action"}, "scope-1", "state-1"); ok {
		t.Fatal("binding an unregistered action must fail")
	}
	if _, ok := policy.Bind(ActionID{RegistryKey: "http-probe"}, "", "state-1"); ok {
		t.Fatal("binding with an empty scope hash must fail")
	}
	if _, ok := policy.Bind(ActionID{RegistryKey: "http-probe"}, "scope-1", ""); ok {
		t.Fatal("binding with an empty state hash must fail")
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

func TestNilAndZeroValuePolicyNeverBind(t *testing.T) {
	var nilPolicy *ActionPolicy
	if _, ok := nilPolicy.Bind(ActionID{RegistryKey: "anything"}, "s", "f"); ok {
		t.Fatal("a nil *ActionPolicy must never bind")
	}
	if _, ok := nilPolicy.BindRecovery(RecoveryPlanRef{RegistryKey: "anything"}, "s", "f"); ok {
		t.Fatal("a nil *ActionPolicy must never bind a recovery")
	}

	empty := NewActionPolicy(nil, nil)
	if _, ok := empty.Bind(ActionID{RegistryKey: "anything"}, "s", "f"); ok {
		t.Fatal("a policy with a nil registry must never bind")
	}
	if _, ok := empty.BindRecovery(RecoveryPlanRef{RegistryKey: "anything"}, "s", "f"); ok {
		t.Fatal("a policy with a nil recovery registry must never bind")
	}
}

func TestRegistryHasNoWayToAddAfterConstruction(t *testing.T) {
	reg := NewRegistry(RegisteredAction{Key: "http-probe"})
	policy := NewActionPolicy(reg, NewRecoveryRegistry())
	// There is no exported method on Registry that adds an entry — this test
	// documents that absence by construction: only http-probe, given at
	// NewRegistry time, was ever registered.
	if _, ok := policy.Bind(ActionID{RegistryKey: "http-probe-v2"}, "scope-1", "state-1"); ok {
		t.Fatal("an action never passed to NewRegistry must never bind, at any point in this registry's lifetime")
	}
}
