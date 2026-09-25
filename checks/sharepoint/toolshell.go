package sharepoint

import (
	"context"
	"fmt"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

const family = "ToolShell"

// familyChecker assesses one ToolShell CVE over the shared pipeline. role is a
// short label ("RCE" / "spoofing / auth-bypass") used only in messages. All
// family members share the assessment and cap at likely.
type familyChecker struct {
	meta   model.Metadata
	role   string
	client httpx.Probe
}

func newToolShell(id, name, role string, client httpx.Probe) *familyChecker {
	return &familyChecker{
		meta: model.Metadata{
			ID:         id,
			Name:       name,
			Product:    "sharepoint",
			Severity:   "critical",
			Family:     family,
			References: []string{"https://msrc.microsoft.com/update-guide/vulnerability/" + id},
		},
		role:   role,
		client: client,
	}
}

func (c *familyChecker) ID() string   { return c.meta.ID }
func (c *familyChecker) Name() string { return c.meta.Name }
func (c *familyChecker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: a plain GET fingerprint plus a benign existence check of the
// ToolShell endpoint. No exploit request is ever sent.
func (c *familyChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *familyChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{StatusCode: a.statusCode, Headers: a.headers, Observations: a.obs}
	if a.err != nil {
		f.Verdict, f.Reason = model.VerdictError, "request_failed"
		f.Evidence.Message = "Fingerprint request failed: " + a.err.Error()
		return f
	}
	if !a.isSharePoint {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 60, "product_not_sharepoint"
		f.Evidence.Message = "No SharePoint fingerprint (a plain IIS/ASP.NET server is not SharePoint); this advisory does not apply"
		return f
	}
	if a.buildKnown {
		f.Evidence.Version = fmt.Sprintf("%d.%d.%d.%d", a.build[0], a.build[1], a.build[2], a.build[3])
	}
	if !a.buildKnown || a.line == "" {
		f.Confidence, f.Reason = 40, "build_unknown"
		f.Evidence.Message = "SharePoint detected but no usable/mappable build number was exposed (MicrosoftSharePointTeamServices absent or ambiguous); patch status unknown"
		return f
	}
	if !a.affected {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 75, "patched"
		f.Evidence.Message = fmt.Sprintf("SharePoint %s build %s is at or above the ToolShell fix (%d.%d.%d.%d); not affected", a.line, f.Evidence.Version, a.fix[0], a.fix[1], a.fix[2], a.fix[3])
		return f
	}

	base := fmt.Sprintf("SharePoint %s build %s predates the ToolShell fix (%d.%d.%d.%d) [%s]. Exploitation (deserialization/code execution) intentionally NOT attempted", a.line, f.Evidence.Version, a.fix[0], a.fix[1], a.fix[2], a.fix[3], c.role)
	if a.exposed {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 85, "toolshell_surface_exposed"
		f.Evidence.Message = base + fmt.Sprintf("; the ToolShell entry point %s is reachable", toolShellPath)
	} else {
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_build"
		f.Evidence.Message = base + "; ToolShell endpoint not confirmed reachable (build match only)"
	}
	return f
}
