package gitlab

import (
	"regexp"
	"strconv"
	"strings"
)

// glVersion is a parsed GitLab version. GitLab ships strictly three components
// (major.minor.patch, e.g. 16.6.0); the maintenance branch (major.minor) selects
// which fix line applies, exactly the axis CVE-2023-7028's boundary turns on.
type glVersion struct {
	major, minor, patch int
}

// helpVersionRE reads the version GitLab embeds — anonymously readable — in the
// `/help` page's `gon` object. On the wire the page HTML-entity-escapes the JSON
// (`&quot;`), so callers unescape `&quot;`→`"` first (see parseVersionFromHelp),
// leaving `"gitlab_version":{"major":16,"minor":6,"patch":0,"suffix_s":""}`. This
// is the reliable version source (headers and /api/v4/version give anon nothing).
var helpVersionRE = regexp.MustCompile(`"gitlab_version":\{"major":(\d+),"minor":(\d+),"patch":(\d+)`)

// parseVersionFromHelp extracts major.minor.patch from a `/help` page body. It
// returns ok=false when the gon `gitlab_version` object is absent (e.g. the
// instance restricts public access and /help redirected to sign-in), which
// callers MUST treat as "unknown", never "not affected".
func parseVersionFromHelp(body []byte) (glVersion, string, bool) {
	// The gon JSON is HTML-escaped in the page; normalise the one entity we need.
	s := strings.ReplaceAll(string(body), "&quot;", `"`)
	m := helpVersionRE.FindStringSubmatch(s)
	if m == nil {
		return glVersion{}, "", false
	}
	v := glVersion{major: atoi(m[1]), minor: atoi(m[2]), patch: atoi(m[3])}
	return v, v.String(), true
}

func (v glVersion) String() string {
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}

// atoi parses digits already validated by helpVersionRE (so it cannot fail); a
// pathologically long run is clamped rather than overflowing.
func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 1 << 30
		}
	}
	return n
}
