package actionauth

import "testing"

// This package is contract-only: no ActionPolicy, no registry, no execution
// exists yet. These tests only pin that BoundAction/BoundRecovery have no
// constructor even from WITHIN this package (their identity/scope/state fields
// are never set anywhere in this file), so the only value obtainable today, from
// any caller anywhere, is the zero value — and that the zero value never
// validates for anything via ValidFor.
func TestBoundTypesAreZeroValueOnly(t *testing.T) {
	var a BoundAction
	if a != (BoundAction{}) {
		t.Fatal("BoundAction must be the zero value until an ActionPolicy constructor is added here")
	}
	if a.ID() != (ActionID{}) {
		t.Fatal("a zero-value BoundAction must expose a zero-value ActionID")
	}
	if a.ValidFor("any-scope", "any-state") {
		t.Fatal("a zero-value BoundAction must never validate for any scope/state (nothing to match)")
	}

	var r BoundRecovery
	if r != (BoundRecovery{}) {
		t.Fatal("BoundRecovery must be the zero value until a recovery policy constructor is added here")
	}
	if r.Ref() != (RecoveryPlanRef{}) {
		t.Fatal("a zero-value BoundRecovery must expose a zero-value RecoveryPlanRef")
	}
	if r.BaselineFingerprintHash() != "" {
		t.Fatal("a zero-value BoundRecovery must expose an empty baseline hash")
	}
	if r.ValidFor("any-scope") {
		t.Fatal("a zero-value BoundRecovery must never validate for any scope")
	}
}

// ActionID/RecoveryPlanRef/RegisteredAction are advisory/descriptive and freely
// constructible — only the Bound* types are capability-gated.
func TestAdvisoryTypesAreFreelyConstructible(t *testing.T) {
	id := ActionID{RegistryKey: "http-probe", VariantID: "v1"}
	ref := RecoveryPlanRef{RegistryKey: "reset-session"}
	reg := RegisteredAction{Key: "http-probe", Reversible: true}
	if id.RegistryKey == "" || ref.RegistryKey == "" || !reg.Reversible {
		t.Fatalf("advisory types should construct plainly: %+v %+v %+v", id, ref, reg)
	}
}
