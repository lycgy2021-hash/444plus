package papercut

import (
	"regexp"
	"strconv"
)

// pcVersion is a parsed PaperCut version. PaperCut ships major.minor.patch (e.g.
// 22.0.7) plus a separate monotonic build number (Build 64927). The build leaks
// on every page via the asset cache-param, but the CVE-2023-27350 boundary turns
// on the marketing major.minor.patch, so that is what we parse and compare. We do
// NOT map build→semver (no reliable, maintainable table); no semver → unknown.
type pcVersion struct {
	major, minor, patch int
}

func (v pcVersion) String() string {
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}

// productVersionRE extracts the exact version from the SetupCompleted page, where
// PaperCut renders `class="product">` followed by `<span>22.0.7</span>`. Anchoring
// on the product block avoids matching an unrelated dotted number elsewhere on the
// page. Confirmed on live MF 22.0.7.
var productVersionRE = regexp.MustCompile(`class="product"[\s\S]{0,300}?<span>(\d+)\.(\d+)\.(\d+)</span>`)

// parseProductVersion reads major.minor.patch from a SetupCompleted body. ok=false
// when the product version span is absent (a patched server redirects and never
// renders it), which callers MUST treat as "unknown", never "not affected".
func parseProductVersion(body []byte) (pcVersion, string, bool) {
	m := productVersionRE.FindSubmatch(body)
	if m == nil {
		return pcVersion{}, "", false
	}
	v := pcVersion{major: atoi(m[1]), minor: atoi(m[2]), patch: atoi(m[3])}
	return v, v.String(), true
}

// atoi parses digits already validated by the regex; a pathologically long run is
// clamped rather than overflowing.
func atoi(b []byte) int {
	n := 0
	for _, c := range b {
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 1 << 30
		}
	}
	return n
}
