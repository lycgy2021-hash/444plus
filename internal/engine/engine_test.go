package engine

import (
	"context"
	"sync/atomic"
	"testing"

	"gopoc/internal/model"
	"gopoc/internal/policy"
)

type fakeChecker struct {
	id       string
	caps     model.Capability
	calls    atomic.Int32
	panicNow bool
}

func (c *fakeChecker) ID() string                     { return c.id }
func (c *fakeChecker) Name() string                   { return c.id }
func (c *fakeChecker) Capabilities() model.Capability { return c.caps }
func (c *fakeChecker) Metadata() model.Metadata       { return model.Metadata{ID: c.id} }
func (c *fakeChecker) Check(ctx context.Context, target model.Target) model.Finding {
	c.calls.Add(1)
	if c.panicNow {
		panic("fixture panic")
	}
	return model.Finding{ID: "incorrect-plugin-id", Verdict: model.VerdictLikely, Confidence: 80}
}

func TestPolicyGatingOrderAndPanicIsolation(t *testing.T) {
	p, _ := policy.New(model.ModePassive, []string{"allowed.test"})
	a, _ := model.ParseTarget("http://allowed.test")
	b, _ := model.ParseTarget("http://denied.test")
	allowed := &fakeChecker{id: "allowed", caps: model.CapHTTPGet}
	blocked := &fakeChecker{id: "blocked", caps: model.CapCommandExecution}
	panics := &fakeChecker{id: "panics", caps: model.CapPassive, panicNow: true}
	e := Engine{Workers: 4, Policy: p}
	results, err := e.Run(context.Background(), []model.Target{a, b}, []model.Checker{allowed, blocked, panics})
	if err != nil || len(results) != 6 {
		t.Fatalf("run failed: %v %+v", err, results)
	}
	if allowed.calls.Load() != 1 || blocked.calls.Load() != 0 || panics.calls.Load() != 1 {
		t.Fatal("policy did not prevent checker execution")
	}
	for i, f := range results {
		if f.ID != []string{"allowed", "blocked", "panics"}[i%3] || f.Target != []model.Target{a, b}[i/3].BaseURL || f.CheckedAt.IsZero() {
			t.Fatalf("wrong identity/order: %+v", f)
		}
		if i != 0 && f.Verdict != model.VerdictUnknown && f.Verdict != model.VerdictError {
			t.Fatalf("failure became a finding: %+v", f)
		}
	}
	if results[1].Reason != "policy_blocked" || results[2].Reason != "checker_panic" {
		t.Fatalf("missing failure reasons: %+v", results)
	}
}

func TestCancellationAccountsForAllJobs(t *testing.T) {
	p, _ := policy.New(model.ModePassive, nil)
	target, _ := model.ParseTarget("http://localhost")
	c := &fakeChecker{id: "test", caps: model.CapHTTPGet}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, err := (Engine{Workers: 2, Policy: p}).Run(ctx, []model.Target{target, target, target}, []model.Checker{c})
	if err != context.Canceled || len(f) != 3 || c.calls.Load() != 0 {
		t.Fatalf("incorrect cancellation: %v %+v", err, f)
	}
	for _, result := range f {
		if result.Reason != "cancelled" {
			t.Fatal(result)
		}
	}
}
