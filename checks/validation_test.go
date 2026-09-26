package checks

import (
	"context"
	"testing"

	"gopoc/internal/model"
	"gopoc/internal/registry"
)

type stubChecker struct{ id string }

func (s stubChecker) ID() string   { return s.id }
func (s stubChecker) Name() string { return "stub" }
func (s stubChecker) Metadata() model.Metadata {
	return model.Metadata{ID: s.id, Name: "stub", Product: "stub", Severity: "low", References: []string{}}
}
func (s stubChecker) Capabilities() model.Capability { return model.CapPassive }
func (s stubChecker) Check(context.Context, model.Target) model.Finding {
	return model.Finding{ID: s.id}
}

func TestWithValidationAttachesKnownRecordOnly(t *testing.T) {
	known := withValidation(stubChecker{id: "CVE-2024-23897"})
	m := known.Metadata()
	if m.Validation == nil || m.Validation.Tier != model.ValidationLive {
		t.Fatalf("known checker got no live validation record: %+v", m.Validation)
	}
	if m.ID != "CVE-2024-23897" || m.Name != "stub" {
		t.Errorf("wrapper must not change any other Metadata field: %+v", m)
	}

	unknown := withValidation(stubChecker{id: "CVE-9999-99999"})
	if v := unknown.Metadata().Validation; v != nil {
		t.Errorf("unrecorded checker ID must report nil Validation, not a guess: %+v", v)
	}
}

// TestAllBuiltinCheckersHaveAValidationRecord guards against silently adding
// a new checker to Builtin() without recording its validation status —
// exactly the kind of gap this mechanism exists to close.
func TestAllBuiltinCheckersHaveAValidationRecord(t *testing.T) {
	reg, err := Builtin(nil, model.ModePassive, model.CanaryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	checkers, err := reg.Select(registry.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checkers {
		if c.Metadata().Validation == nil {
			t.Errorf("%s: registered in Builtin() with no validationRecords entry", c.ID())
		}
	}
}
