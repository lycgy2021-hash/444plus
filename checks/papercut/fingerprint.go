// Package papercut holds detection for PaperCut MF/NG print management. It ships
// exactly one rule: CVE-2023-27350, the unauthenticated access-control bypass on
// the SetupCompleted page (CVSS 9.8, CISA KEV). See docs/papercut-attack-surface.md.
//
// The check is detection-only and read-only (GET). The flaw IS an access-control
// bypass we can observe directly: on an AFFECTED server a bare
// `GET /app?service=page/SetupCompleted` renders the setup page (200) with the
// exact version; a FIXED server redirects it away (302). We never POST, never
// walk the wizard, never enable print scripts, never execute anything — so the
// verdict caps at `likely`, never `confirmed` (proving RCE would cross into the
// exploit chain).
package papercut

import (
	"regexp"

	"gopoc/internal/httpx"
)

const (
	// loginPath is the anonymous login page; its body carries product markers used
	// for identity on a configured (patched or not) server.
	loginPath = "/app?service=page/Login"
	// setupCompletedPath is the CVE-2023-27350 surface. Read-only: rendering it is
	// the bypass; we never POST to it.
	setupCompletedPath = "/app?service=page/SetupCompleted"
)

// PaperCut identity signals. Each is an independent, structural tell; the
// assessment requires at least TWO before it will call a target PaperCut, so a
// page that merely contains the word "PaperCut", a lone JSESSIONID, or port 9191
// alone can never identify the product.
var (
	// assetBuildRE matches the versioned static-asset cache-param, e.g.
	// `/css/style.css?64927papercut-mf`. Structural and hard to fake casually; the
	// `papercut-mf` literal appears on NG builds too, so it identifies PaperCut but
	// not MF-vs-NG. Group 1 is the build number.
	assetBuildRE = regexp.MustCompile(`\?(\d+)papercut-(?:mf|ng)\b`)
	// appServerRE is PaperCut's page-framework HTML comment, present on every
	// rendered page.
	appServerRE = regexp.MustCompile(`(?i)<!--\s*Application:\s*app-server\s*-->`)
	// copyrightRE is the product footer.
	copyrightRE = regexp.MustCompile(`(?i)PaperCut Software Pty Ltd`)
	// loginTitleRE matches the login page's product title or a structured product
	// meta/content attribute (not a bare "PaperCut" substring).
	loginTitleRE = regexp.MustCompile(`(?i)<title>\s*PaperCut Login|content="PaperCut`)
	// productBlockRE marks the SetupCompleted product/version block.
	productBlockRE = regexp.MustCompile(`class="product"`)
	// setupPageRE marks the SetupCompleted wizard page itself.
	setupPageRE = regexp.MustCompile(`(?i)Configuration Wizard\s*:\s*Setup Complete|<!--\s*Page:\s*SetupCompleted\s*-->`)
)

// countSignals returns how many DISTINCT PaperCut identity signals appear across
// the given response bodies. The assessment treats >= 2 as "this is PaperCut".
func countSignals(bodies ...[]byte) int {
	res := []*regexp.Regexp{assetBuildRE, appServerRE, copyrightRE, loginTitleRE, productBlockRE}
	n := 0
	for _, re := range res {
		for _, b := range bodies {
			if re.Match(b) {
				n++
				break
			}
		}
	}
	return n
}

// isSetupPageRendered reports whether a SetupCompleted response is the real
// PaperCut setup page (the access-control bypass rendering), not a redirect or an
// unrelated 200. It requires the setup-page marker AND the product block, so a
// generic app returning 200 on that path is not mistaken for the bypass.
func isSetupPageRendered(r httpx.Response, err error) bool {
	if err != nil || r.StatusCode != 200 {
		return false
	}
	return setupPageRE.Match(r.Body) && productBlockRE.Match(r.Body)
}

// isRedirect reports the patched-behavior status: a fixed server redirects the
// SetupCompleted GET away instead of rendering it.
func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}
