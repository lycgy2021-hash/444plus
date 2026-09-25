package fortinet

import (
	"context"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// fortiAssessment is the shared Fortinet fingerprint/version/exposure result,
// reused across this product's CVE checkers within one scan.
type fortiAssessment struct {
	product      string
	isFortinet   bool
	version      string
	versionKnown bool
	exposed      bool
	statusCode   int
	headers      map[string]string
	obs          []model.Observation
	err          error
}

func assess(ctx context.Context, client httpx.Probe, target model.Target) fortiAssessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "fortinet"}, func() any {
			return doAssess(ctx, client, target)
		}).(fortiAssessment)
	}
	return doAssess(ctx, client, target)
}

func doAssess(ctx context.Context, client httpx.Probe, target model.Target) fortiAssessment {
	var a fortiAssessment
	// Use Get (not Fingerprint) because the shared fingerprint cache drops the
	// body, and Fortinet detection is body-based.
	r, err := client.Get(ctx, target, "/")
	a.statusCode, a.headers = r.StatusCode, r.Headers
	a.obs = append(a.obs, r.Observation("fingerprint", err))
	if err != nil {
		a.err = err
		return a
	}
	a.product, a.isFortinet = fingerprint(string(r.Body))
	if !a.isFortinet || a.product == "Fortinet" {
		return a // unclassified: no version, no exposure probes
	}
	a.version, a.versionKnown = extractVersion(string(r.Body))
	exposed, expObs := exposure(ctx, client, target)
	a.exposed = exposed
	a.obs = append(a.obs, expObs...)
	return a
}
