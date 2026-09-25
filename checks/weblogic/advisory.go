package weblogic

import (
	"context"
	"fmt"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// advisoryChecker assesses one WebLogic CVE over the shared multi-protocol
// pipeline. Each advisory declares its affected base releases and which protocol
// surface its attack vector uses (requires); a version match is `detected`, and
// the surface being genuinely exposed raises it to `likely`. It never confirms:
// the actual deserialization/RCE is not sent.
type advisoryChecker struct {
	meta     model.Metadata
	client   httpx.Probe
	affected []string
	surface  string
	requires func(assessment) bool
}

func newAdvisory(id, name, family, surface string, affected []string, requires func(assessment) bool, client httpx.Probe) *advisoryChecker {
	return &advisoryChecker{
		meta: model.Metadata{
			ID:         id,
			Name:       name,
			Product:    "weblogic",
			Severity:   "critical",
			Family:     family,
			References: []string{"https://www.oracle.com/security-alerts/"},
		},
		client:   client,
		affected: affected,
		surface:  surface,
		requires: requires,
	}
}

func (c *advisoryChecker) ID() string   { return c.meta.ID }
func (c *advisoryChecker) Name() string { return c.meta.Name }
func (c *advisoryChecker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: HTTP fingerprint plus non-destructive protocol handshakes.
func (c *advisoryChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet | model.CapTCPProbe
}

func (c *advisoryChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.obs}

	if !a.isWebLogic {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 60, "product_not_weblogic"
		f.Evidence.Message = "No WebLogic fingerprint (HTTP or T3); this CVE does not apply"
		return f
	}
	f.Evidence.Version = a.version
	if a.version == "" {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = "WebLogic detected over HTTP but no version could be read (T3 handshake gave no HELO); affected status is unknown"
		return f
	}
	if !affected(a.version, c.affected) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 75, "version_not_affected"
		f.Evidence.Message = fmt.Sprintf("WebLogic %s is outside this advisory's affected base releases", a.version)
		return f
	}

	exposedList := strings.Join(a.exposed(), ", ")
	base := fmt.Sprintf("WebLogic %s is an affected base release (PSU patch level not remotely observable). Exposed protocols: %s. Exploit NOT attempted", a.version, exposedList)
	if c.requires(a) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 85, "dangerous_protocol_exposed"
		f.Evidence.Message = base + fmt.Sprintf("; the %s attack surface is reachable", c.surface)
	} else {
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = base + fmt.Sprintf("; the %s surface was not reached, so exploit prerequisites are not established", c.surface)
	}
	return f
}

// Protocol-surface predicates shared by advisories.
func requiresHTTP(a assessment) bool     { return a.http }
func requiresSOAP(a assessment) bool     { return a.soap }
func requiresT3orIIOP(a assessment) bool { return a.t3 || a.iiop }
