package fortinet

import (
	"context"
	"fmt"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// advisoryChecker assesses one Fortinet advisory over the shared pipeline:
// fingerprint -> product scope -> version -> affected-range -> exposure. It caps
// at `likely`: these advisories are unauthenticated RCE/auth-bypass whose
// behavioral confirmation would be intrusive or destructive, so a default scan
// never returns confirmed for them.
type advisoryChecker struct {
	meta     model.Metadata
	products map[string]bool
	ranges   []AffectedRange
	client   httpx.Probe
}

func newAdvisory(id, name string, products []string, ranges []AffectedRange, client httpx.Probe) *advisoryChecker {
	set := map[string]bool{}
	for _, p := range products {
		set[p] = true
	}
	return &advisoryChecker{
		meta: model.Metadata{
			ID:         id,
			Name:       name,
			Product:    "fortinet",
			Severity:   "critical",
			References: []string{"https://www.fortiguard.com/psirt"},
		},
		products: set,
		ranges:   ranges,
		client:   client,
	}
}

func (c *advisoryChecker) ID() string   { return c.meta.ID }
func (c *advisoryChecker) Name() string { return c.meta.Name }
func (c *advisoryChecker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: this checker never sends an exploit request.
func (c *advisoryChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *advisoryChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{StatusCode: a.statusCode, Headers: a.headers, Observations: a.obs}
	if a.err != nil {
		f.Verdict, f.Reason = model.VerdictError, "request_failed"
		f.Evidence.Message = "Fingerprint request failed: " + a.err.Error()
		return f
	}
	if !a.isFortinet {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 60, "product_not_fortinet"
		f.Evidence.Message = "No Fortinet web-surface fingerprint; this advisory does not apply"
		return f
	}
	switch {
	case a.product == "Fortinet":
		f.Confidence, f.Reason = 30, "product_unclassified"
		f.Evidence.Message = "A Fortinet surface was detected but the specific product could not be classified; cannot map to this advisory"
		return f
	case !c.products[a.product]:
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 65, "product_out_of_scope"
		f.Evidence.Message = fmt.Sprintf("Detected %s, which is not in this advisory's affected products", a.product)
		return f
	}

	f.Evidence.Version = a.version
	if !a.versionKnown {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = fmt.Sprintf("%s detected but no version is exposed to unauthenticated clients; affected status is unknown", a.product)
		return f
	}
	isAff, fixed := affected(c.ranges, a.product, a.version)
	if !isAff {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 70, "version_not_affected"
		f.Evidence.Message = fmt.Sprintf("%s %s is outside this advisory's affected ranges", a.product, a.version)
		return f
	}

	base := fmt.Sprintf("%s %s is in this advisory's affected range (fixed in %s). Authentication bypass / privileged operations intentionally NOT attempted", a.product, a.version, fixed)
	if a.exposed {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 88, "affected_and_exposed"
		f.Evidence.Message = base + "; the administrative/portal surface is reachable from this position"
	} else {
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = base + "; management surface not confirmed reachable (version match only)"
	}
	return f
}
