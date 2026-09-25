package engine

import (
	"context"
	"testing"

	"gopoc/internal/model"
	"gopoc/internal/policy"
)

// confirmFixture returns a caller-supplied finding so the engine's
// confirmed-requires-confirmation invariant can be driven directly.
type confirmFixture struct{ finding model.Finding }

func (c confirmFixture) ID() string   { return "TEST-1" }
func (c confirmFixture) Name() string { return "TEST-1" }
func (c confirmFixture) Metadata() model.Metadata {
	return model.Metadata{ID: "TEST-1", Name: "TEST-1"}
}
func (c confirmFixture) Capabilities() model.Capability { return model.CapPassive | model.CapHTTPGet }
func (c confirmFixture) Check(context.Context, model.Target) model.Finding {
	return c.finding
}

func runConfirmFixture(t *testing.T, verdict model.Verdict, conf *model.Confirmation) model.Finding {
	t.Helper()
	p, err := policy.New(model.ModePassive, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := confirmFixture{finding: model.Finding{
		ID: "TEST-1", Name: "TEST-1", Verdict: verdict, Confidence: 99,
		Evidence: model.Evidence{Confirmation: conf},
	}}
	e := Engine{Workers: 1, Policy: p}
	findings, err := e.Run(context.Background(), []model.Target{{Host: "127.0.0.1", BaseURL: "http://127.0.0.1/"}}, []model.Checker{c})
	if err != nil {
		t.Fatal(err)
	}
	return findings[0]
}

// The engine must reject a confirmed verdict lacking a passing confirmation, so
// no checker can mint confirmed from a bare status code or version match.
func TestConfirmedRequiresPassingConfirmation(t *testing.T) {
	if f := runConfirmFixture(t, model.VerdictConfirmed, nil); f.Verdict != model.VerdictError || f.Reason != "confirmation_missing" {
		t.Fatalf("bare confirmed not rejected: %+v", f)
	}
	weak := &model.Confirmation{PositiveNeeded: 2, PositivePasses: 1, NegativeNeeded: 1, NegativePasses: 1, DiffMatched: true, RepeatOK: false}
	if f := runConfirmFixture(t, model.VerdictConfirmed, weak); f.Verdict != model.VerdictError || f.Reason != "confirmation_missing" {
		t.Fatalf("weak confirmed not rejected: %+v", f)
	}
	strong := &model.Confirmation{PositiveNeeded: 2, PositivePasses: 2, NegativeNeeded: 1, NegativePasses: 1, DiffMatched: true, RepeatOK: true}
	if !strong.Passed() {
		t.Fatal("strong confirmation should pass")
	}
	if f := runConfirmFixture(t, model.VerdictConfirmed, strong); f.Verdict != model.VerdictConfirmed {
		t.Fatalf("valid confirmed wrongly rejected: %+v", f)
	}
	if f := runConfirmFixture(t, model.VerdictLikely, nil); f.Verdict != model.VerdictLikely {
		t.Fatalf("likely must pass through: %+v", f)
	}
}
