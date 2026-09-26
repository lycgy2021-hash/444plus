package papercut

import (
	"context"
	"fmt"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// CVE-2023-27350: improper access control in PaperCut MF/NG's SetupCompleted
// page lets an UNAUTHENTICATED caller reach the setup wizard as administrator,
// which chains to remote code execution (print-script engine). CVSS 9.8, CISA
// KEV, exploited by Cl0p/LockBit.
//
// Affected: 8.0 or later up to the fixes — < 20.1.7, 21.x < 21.2.11, 22.x <
// 22.0.9. Fixed: 20.1.7 / 21.2.11 / 22.0.9 (and 23.x+).
//
// Detection is read-only: a bare GET of /app?service=page/SetupCompleted renders
// the setup page (the access-control bypass) on an affected server and hands us
// the exact version; a fixed server redirects it away. We never POST, never walk
// the wizard, never enable print scripts, never execute anything — so this caps
// at `likely`. `confirmed` would require the RCE chain, which we do not run.
const cve20232735ID = "CVE-2023-27350"

// cve7350Fix maps a major branch to its first fixed (major,minor,patch). A major
// below 20 is affected outright (8.0–19.2.x); 23+ is not affected.
var cve7350Fix = map[int]pcVersion{
	20: {20, 1, 7},
	21: {21, 2, 11},
	22: {22, 0, 9},
}

func lessVersion(a, b pcVersion) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

func affectedCVE20232735(v pcVersion) bool {
	if v.major < 20 {
		return true // 8.0–19.2.x all affected
	}
	fix, ok := cve7350Fix[v.major]
	if !ok {
		return false // 23.x and later
	}
	return lessVersion(v, fix)
}

type checker struct {
	meta   model.Metadata
	client httpx.Probe
}

// NewCVE20232735 constructs the CVE-2023-27350 checker.
func NewCVE20232735(client httpx.Probe) *checker {
	return &checker{
		meta: model.Metadata{
			ID:       cve20232735ID,
			Name:     "PaperCut MF/NG SetupCompleted Access-Control Bypass (unauth RCE)",
			Product:  "papercut",
			Severity: "critical",
			References: []string{
				"https://www.papercut.com/kb/Main/PO-1216-and-PO-1219",
				"https://nvd.nist.gov/vuln/detail/CVE-2023-27350",
			},
		},
		client: client,
	}
}

func (c *checker) ID() string   { return c.meta.ID }
func (c *checker) Name() string { return c.meta.Name }
func (c *checker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only, read-only: fingerprint plus GET probes. No POST is ever sent,
// so the setup wizard is never advanced and no admin session is created.
func (c *checker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *checker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.observations, Version: a.version}

	if !a.isPaperCut {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 60, "product_not_papercut"
		f.Evidence.Message = "No PaperCut fingerprint (needs >=2 independent signals: the ?<build>papercut-mf asset param plus an app-server/login/product marker); this CVE does not apply"
		return f
	}

	f.Evidence.StatusCode = a.setupStatus

	// The exact version came from the SetupCompleted product span (affected servers).
	if a.hasVersion {
		if !affectedCVE20232735(a.ver) {
			f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 80, "version_not_affected"
			f.Evidence.Message = fmt.Sprintf("PaperCut %s is at or above the fix line (20.1.7 / 21.2.11 / 22.0.9); not affected", a.version)
			return f
		}
		if a.setupCompleted {
			f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 90, "setup_completed_bypass_exposed"
			f.Evidence.Message = fmt.Sprintf("PaperCut %s is affected by CVE-2023-27350 AND the SetupCompleted page is reachable UNAUTHENTICATED (HTTP 200, real setup page + version rendered) — the access-control bypass is exposed. Exploit / RCE / admin session was NOT attempted (read-only GET; no POST, no wizard step)", a.version)
			return f
		}
		// Version in range but the surface wasn't strongly confirmed as the rendered
		// bypass: report the version match only.
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = fmt.Sprintf("PaperCut %s is in the CVE-2023-27350 affected range, but the SetupCompleted bypass was not confirmed rendered (version match only). Exploit was NOT attempted", a.version)
		return f
	}

	// No exact version. A fixed server redirects SetupCompleted away — that patched
	// behavior is a not_found signal. Anything else (unreachable/ambiguous) is
	// unknown: PaperCut is present but we cannot read the version, so we must not
	// upgrade "looks like PaperCut" into a CVE finding.
	if isRedirect(a.setupStatus) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 75, "patched_setup_access_control"
		f.Evidence.Message = fmt.Sprintf("PaperCut detected; SetupCompleted redirected (HTTP %d) instead of rendering — the CVE-2023-27350 access-control fix is present. Not affected", a.setupStatus)
		return f
	}
	f.Confidence, f.Reason = 40, "version_unknown"
	f.Evidence.Message = "PaperCut detected but the exact version could not be read (SetupCompleted did not render a version span and did not show patched-redirect behavior); affected status is unknown"
	return f
}
