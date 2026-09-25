package detect

import (
	"context"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// Feature reports whether a response exhibits the vulnerability's own behavior,
// with a short matcher label and detail. It must inspect body/headers/behavior,
// never status code alone. It is applied to the positive probe (must match) and
// to every negative control (must not match).
type Feature func(httpx.Response) (matched bool, matcher, detail string)

// ConfirmProbe is one HTTP request in a confirmation.
type ConfirmProbe struct {
	Kind        string // observation label, e.g. "canary_probe", "restore"
	Method      string // "GET" (default) or "POST"
	Path        string
	ContentType string
	Body        []byte
}

// ConfirmPolicy fixes how strict confirmation is. Confirm is the only way to earn
// a confirmed verdict, so these are framework-wide guarantees, not per-checker.
type ConfirmPolicy struct {
	MinPositiveMatches int  // positive probe must match this many times
	MinNegativePasses  int  // at least this many negatives must be clean controls
	RequireDiff        bool // positive must differ observably from a passing negative
	RequireRepeat      bool // re-issue the positive probe MinPositiveMatches times
}

func DefaultConfirmPolicy() ConfirmPolicy {
	return ConfirmPolicy{MinPositiveMatches: 2, MinNegativePasses: 1, RequireDiff: true, RequireRepeat: true}
}

// ConfirmSpec is a checker's confirmation plan. Positive and Negatives are HTTP
// probes; Feature is the vulnerability matcher. Version/banner evidence can never
// be a Positive here — Confirm only accepts live request/response behavior.
type ConfirmSpec struct {
	Positive  ConfirmProbe
	Negatives []ConfirmProbe
	Feature   Feature
	// ControlValid decides whether a negative response is a usable control at all
	// (a 5xx or a truncated body makes the control inconclusive, not a pass).
	// Defaults to usableControlStatus && !truncated.
	ControlValid func(httpx.Response) bool
	Policy       ConfirmPolicy
}

// ConfirmResult carries the outcome plus the positive probe's observed status so
// callers can pick likely/not_found when confirmation does not hold.
type ConfirmResult struct {
	Confirmed       bool
	Confirmation    *model.Confirmation
	Observations    []model.Observation
	PositiveStatus  int
	PositiveMatched bool
	PositiveErr     error
}

func usableControlStatus(status int) bool {
	return status >= 200 && status < 300 || status == 400 || status == 401 || status == 403 || status == 404 || status == 410
}

func doProbe(ctx context.Context, client httpx.Probe, target model.Target, p ConfirmProbe) (httpx.Response, error) {
	if p.Method == "POST" {
		return client.Post(ctx, target, p.Path, p.ContentType, p.Body)
	}
	return client.Get(ctx, target, p.Path)
}

// Confirm runs the positive probe (repeated per policy) and the negative controls
// and returns whether the contract holds. A checker maps Confirmed==true to the
// confirmed verdict and must attach the returned Confirmation to its evidence;
// the engine rejects any confirmed verdict without a passing Confirmation.
func Confirm(ctx context.Context, client httpx.Probe, target model.Target, spec ConfirmSpec) ConfirmResult {
	pol := spec.Policy
	controlValid := spec.ControlValid
	if controlValid == nil {
		controlValid = func(r httpx.Response) bool { return !r.Truncated && usableControlStatus(r.StatusCode) }
	}
	runs := 1
	if pol.RequireRepeat {
		runs = pol.MinPositiveMatches
	}
	res := ConfirmResult{Confirmation: &model.Confirmation{PositiveNeeded: runs, NegativeNeeded: pol.MinNegativePasses}}
	conf := res.Confirmation

	var posResp httpx.Response
	for i := 0; i < runs; i++ {
		r, err := doProbe(ctx, client, target, spec.Positive)
		res.Observations = append(res.Observations, r.Observation(spec.Positive.Kind, err))
		matched, matcher, detail := false, "", ""
		if err == nil {
			matched, matcher, detail = spec.Feature(r)
		} else if res.PositiveErr == nil {
			res.PositiveErr = err
		}
		conf.Steps = append(conf.Steps, model.ConfirmStep{Role: "positive", Kind: spec.Positive.Kind, URL: r.URL, Status: r.StatusCode, Matched: matched, Matcher: matcher, Detail: detail})
		if i == 0 {
			res.PositiveStatus, res.PositiveMatched = r.StatusCode, matched
		}
		if matched {
			conf.PositivePasses++
			posResp = r
		}
	}

	for _, np := range spec.Negatives {
		r, err := doProbe(ctx, client, target, np)
		res.Observations = append(res.Observations, r.Observation(np.Kind, err))
		matched, matcher, detail := false, "", ""
		if err == nil {
			matched, matcher, detail = spec.Feature(r)
		}
		conf.Steps = append(conf.Steps, model.ConfirmStep{Role: "negative", Kind: np.Kind, URL: r.URL, Status: r.StatusCode, Matched: matched, Matcher: matcher, Detail: detail})
		// A clean control: reachable, a usable status, and NOT exhibiting the feature.
		if err == nil && !matched && controlValid(r) {
			conf.NegativePasses++
			if posResp.SHA256 != r.SHA256 || posResp.StatusCode != r.StatusCode {
				conf.DiffMatched = true
			}
		}
	}

	if !pol.RequireDiff {
		conf.DiffMatched = true
	}
	conf.RepeatOK = !pol.RequireRepeat || conf.PositivePasses == conf.PositiveNeeded
	res.Confirmed = conf.Passed() && conf.PositivePasses == conf.PositiveNeeded
	return res
}
