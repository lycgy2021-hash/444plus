package netscaler

import (
	"context"
	"fmt"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// advisoryChecker assesses one NetScaler CVE. A version match is `detected`; the
// affected service face (Gateway or AAA) being genuinely exposed raises it to
// `likely`. It never confirms: the memory-corruption bug is not triggered.
type advisoryChecker struct {
	meta     model.Metadata
	client   httpx.Probe
	affected []AffectedRange
}

func newAdvisory(id, name string, affected []AffectedRange, client httpx.Probe) *advisoryChecker {
	return &advisoryChecker{
		meta: model.Metadata{
			ID:         id,
			Name:       name,
			Product:    "netscaler",
			Severity:   "critical",
			References: []string{"https://support.citrix.com/"},
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

// Detection-only: HTTP fingerprint and service-face probes (GET).
func (c *advisoryChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *advisoryChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.obs}

	if !a.isNetScaler {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 60, "product_not_netscaler"
		f.Evidence.Message = "No NetScaler-specific evidence (a generic Citrix page is not NetScaler); this CVE does not apply"
		return f
	}
	if !a.hasVersion {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = "NetScaler detected but no version/build was exposed; affected status is unknown"
		return f
	}
	f.Evidence.Version = a.version.branch + " " + fmt.Sprintf("%d.%d", a.version.build[0], a.version.build[1])
	if !affected(a.version, c.affected) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 75, "version_not_affected"
		f.Evidence.Message = fmt.Sprintf("NetScaler %s is at or above the fix line; not affected", f.Evidence.Version)
		return f
	}

	faces := a.exposedFaces()
	base := fmt.Sprintf("NetScaler %s is affected. Exploit (memory corruption) NOT attempted", f.Evidence.Version)
	if a.gateway || a.aaa {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 85, "affected_service_exposed"
		f.Evidence.Message = base + "; the affected service face is exposed: " + faces
	} else {
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = base + "; no affected Gateway/AAA service face was found exposed (version match only)"
	}
	return f
}

func (a assessment) exposedFaces() string {
	var faces []string
	if a.gateway {
		faces = append(faces, "Gateway (VPN/ICA/CVPN/RDP)")
	}
	if a.aaa {
		faces = append(faces, "AAA vServer")
	}
	return strings.Join(faces, ", ")
}
