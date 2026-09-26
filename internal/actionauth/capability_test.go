package actionauth

import "testing"

// This package is contract-only: no ActionPolicy, no registry, no execution
// exists yet. This test only pins that BoundAction/BoundRecovery have no
// constructor even from WITHIN this package (their identity fields are never
// set anywhere in this file), so the only value obtainable today, from any
// caller anywhere, is the zero value.
func TestBoundTypesAreZeroValueOnly(t *testing.T) {
	var a BoundAction
	if a != (BoundAction{}) {
		t.Fatal("BoundAction must be the zero value until an ActionPolicy constructor is added here")
	}
	var r BoundRecovery
	if r != (BoundRecovery{}) {
		t.Fatal("BoundRecovery must be the zero value until a recovery policy constructor is added here")
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
