package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gopoc/internal/assesscache"
	"gopoc/internal/model"
	"gopoc/internal/policy"
)

type Engine struct {
	Workers int
	Policy  *policy.Policy
}

type job struct {
	index  int
	target model.Target
	check  model.Checker
}

// Run preserves target/checker order regardless of worker completion order.
// Cancellation retains one explicit unknown result for every unfinished job.
func (e Engine) Run(ctx context.Context, targets []model.Target, checks []model.Checker) ([]model.Finding, error) {
	if e.Workers < 1 || e.Workers > 1024 || e.Policy == nil {
		return nil, fmt.Errorf("engine requires a policy and 1–1024 workers")
	}
	// One shared assessment cache per scan, so a product's many CVE checkers reuse
	// a single fingerprint/version/exposure assessment instead of re-probing.
	if assesscache.From(ctx) == nil {
		ctx = assesscache.With(ctx, assesscache.New())
	}
	results := make([]model.Finding, len(targets)*len(checks))
	jobs := make(chan job)
	var wg sync.WaitGroup
	for range min(e.Workers, len(results)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results[j.index] = e.runOne(ctx, j)
			}
		}()
	}
	for i, target := range targets {
		for k, check := range checks {
			jobs <- job{index: i*len(checks) + k, target: target, check: check}
		}
	}
	close(jobs)
	wg.Wait()
	return results, ctx.Err()
}

func (e Engine) runOne(ctx context.Context, j job) (f model.Finding) {
	start := time.Now()
	f = model.Finding{ID: j.check.ID(), Name: j.check.Name(), Target: j.target.BaseURL, Verdict: model.VerdictUnknown}
	defer func() {
		if recovered := recover(); recovered != nil {
			f.Verdict, f.Confidence, f.Reason = model.VerdictError, 0, "checker_panic"
			f.Evidence.Message = fmt.Sprintf("checker panicked: %v", recovered)
		}
		f.ID, f.Name, f.Target = j.check.ID(), j.check.Name(), j.target.BaseURL
		f.CheckedAt, f.DurationMS = start.UTC(), time.Since(start).Milliseconds()
	}()
	if err := ctx.Err(); err != nil {
		f.Verdict, f.Reason, f.Evidence.Message = model.VerdictError, "cancelled", err.Error()
		return f
	}
	if err := e.Policy.CheckTarget(j.target); err != nil {
		f.Reason, f.Evidence.Message = "policy_blocked", err.Error()
		return f
	}
	if err := e.Policy.CheckCapabilities(j.check.Capabilities()); err != nil {
		f.Reason, f.Evidence.Message = "policy_blocked", err.Error()
		return f
	}
	f = j.check.Check(ctx, j.target)
	// Framework-wide invariant: a confirmed verdict must be backed by a passing
	// confirmation (produced only by detect.Confirm). This blocks any checker from
	// minting confirmed from a bare status code or version match.
	if f.Verdict == model.VerdictConfirmed && !f.Evidence.Confirmation.Passed() {
		// A contract violation is a program error, not "target status unknown".
		f.Verdict, f.Confidence, f.Reason = model.VerdictError, 0, "confirmation_missing"
		f.Evidence.Message = "confirmed verdict rejected: no passing confirmation evidence (checkers must earn confirmed via detect.Confirm)"
	}
	if ctx.Err() != nil && f.Verdict != model.VerdictConfirmed {
		f.Verdict, f.Confidence, f.Reason = model.VerdictError, 0, "cancelled"
		f.Evidence.Message = ctx.Err().Error()
	}
	switch f.Verdict {
	case model.VerdictConfirmed, model.VerdictLikely, model.VerdictDetected, model.VerdictNotFound, model.VerdictUnknown, model.VerdictError:
	default:
		f.Verdict, f.Confidence, f.Reason = model.VerdictError, 0, "invalid_finding"
		f.Evidence.Message = "Checker returned an invalid verdict or confidence"
	}
	if f.Confidence < 0 || f.Confidence > 100 {
		f.Verdict, f.Confidence, f.Reason = model.VerdictError, 0, "invalid_finding"
		f.Evidence.Message = "Checker returned an invalid verdict or confidence"
	}
	return f
}
