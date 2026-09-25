package sharepoint

import (
	"context"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// spAssessment is the shared SharePoint fingerprint/build/exposure result, reused
// across the ToolShell family's CVE checkers within one scan.
type spAssessment struct {
	isSharePoint bool
	build        SPBuild
	buildKnown   bool
	line         string
	affected     bool
	fix          SPBuild
	exposed      bool
	statusCode   int
	headers      map[string]string
	obs          []model.Observation
	err          error
}

func assess(ctx context.Context, client httpx.Probe, target model.Target) spAssessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "sharepoint"}, func() any {
			return doAssess(ctx, client, target)
		}).(spAssessment)
	}
	return doAssess(ctx, client, target)
}

func doAssess(ctx context.Context, client httpx.Probe, target model.Target) spAssessment {
	var a spAssessment
	r, err := client.Get(ctx, target, "/_layouts/15/start.aspx")
	a.statusCode, a.headers = r.StatusCode, r.Headers
	a.obs = append(a.obs, r.Observation("fingerprint", err))
	if err != nil {
		a.err = err
		return a
	}
	if !isSharePoint(r) {
		return a
	}
	a.isSharePoint = true
	a.build, a.buildKnown = buildFrom(r)
	if !a.buildKnown {
		return a
	}
	a.affected, a.line, a.fix = affectedBuild(a.build)
	if a.line == "" || !a.affected {
		return a // patched or unmapped: no need to probe the ToolShell endpoint
	}
	a.exposed, _ = exposureWithObs(ctx, client, target, &a.obs)
	return a
}

// exposureWithObs probes the ToolShell endpoint and appends the observation.
func exposureWithObs(ctx context.Context, client httpx.Probe, target model.Target, obs *[]model.Observation) (bool, model.Observation) {
	exposed, o := exposure(ctx, client, target)
	*obs = append(*obs, o)
	return exposed, o
}
