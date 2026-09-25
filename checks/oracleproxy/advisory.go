package oracleproxy

import (
	"context"
	"fmt"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// advisoryChecker assesses one Oracle proxy advisory over the shared pipeline:
// front-end -> plug-in evidence -> version -> affected range -> routing. It caps
// at `likely`; the actual compromise is not attempted.
type advisoryChecker struct {
	meta     model.Metadata
	client   httpx.Probe
	affected []AffectedRange
}

func newAdvisory(id, name, family string, affected []AffectedRange, client httpx.Probe) *advisoryChecker {
	return &advisoryChecker{
		meta: model.Metadata{
			ID:         id,
			Name:       name,
			Product:    "oracle-proxy",
			Severity:   "critical",
			Family:     family,
			References: []string{"https://www.oracle.com/security-alerts/"},
		},
		client:   client,
		affected: affected,
	}
}

func (c *advisoryChecker) ID() string   { return c.meta.ID }
func (c *advisoryChecker) Name() string { return c.meta.Name }
func (c *advisoryChecker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: HTTP fingerprint plus stateless routing probes (GET).
func (c *advisoryChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *advisoryChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.obs}

	if !a.isProxy {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 60, "product_not_oracle_proxy"
		f.Evidence.Message = "No Oracle HTTP Server / WebLogic proxy plug-in evidence (a plain Apache/IIS is not an Oracle proxy); this CVE does not apply"
		return f
	}
	fe := a.frontend
	if a.version == "" {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = fmt.Sprintf("Oracle proxy detected (front-end %s) but no version is exposed to unauthenticated clients; affected status is unknown", fe)
		return f
	}
	f.Evidence.Version = a.version
	if !affectedForFrontend(c.affected, fe, a.version) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 75, "version_not_affected"
		f.Evidence.Message = fmt.Sprintf("Oracle proxy %s %s is outside this advisory's affected range", fe, a.version)
		return f
	}

	base := fmt.Sprintf("Oracle proxy front-end=%s version=%s is in this advisory's affected range (unauthenticated, remote, scope-changed, CVSS-critical). Exploit NOT attempted", fe, a.version)
	if a.routing {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 85, "weblogic_routing_confirmed"
		f.Evidence.Message = base + "; requests are confirmed forwarded to a WebLogic backend"
	} else {
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = base + "; active WebLogic routing was not confirmed (version/plug-in match only)"
	}
	return f
}
