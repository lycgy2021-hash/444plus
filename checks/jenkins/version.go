package jenkins

import "regexp"

// jkVersion is a parsed Jenkins version. Jenkins ships on two lines with
// distinct numbering: weekly releases carry two components (e.g. 2.441), and
// LTS releases carry three (e.g. 2.426.2 — an LTS baseline plus a patch level).
// The component count is itself information: it tells us which fix line applies.
type jkVersion struct {
	major, minor, patch int
	isLTS               bool // true when a third (patch) component was present
}

// versionRE reads the leading dotted-numeric version from a string such as the
// X-Jenkins header ("2.568.3") or a page's data-version. A trailing vendor
// suffix (e.g. "2.462.3-cb-4" on CloudBees builds) is ignored.
var versionRE = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)

// parseVersion parses a Jenkins version string. It returns ok=false when no
// dotted-numeric version is present, which callers must treat as "unknown",
// never "not affected".
func parseVersion(s string) (jkVersion, bool) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return jkVersion{}, false
	}
	v := jkVersion{major: atoi(m[1]), minor: atoi(m[2])}
	if m[3] != "" {
		v.patch, v.isLTS = atoi(m[3]), true
	}
	return v, true
}

// atoi parses digits already validated by versionRE (so it cannot fail); a
// pathologically long run of digits is clamped rather than overflowing.
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

// dataVersionRE is a fallback version source from an HTML body: Jenkins renders
// `data-version="2.568.3"` on the <body>. Used only when the X-Jenkins header is
// absent (e.g. stripped by a proxy) but we already hold a page body.
var dataVersionRE = regexp.MustCompile(`data-version=["']([0-9][0-9.]*)["']`)

func parseVersionBody(body []byte) (jkVersion, string, bool) {
	m := dataVersionRE.FindSubmatch(body)
	if m == nil {
		return jkVersion{}, "", false
	}
	v, ok := parseVersion(string(m[1]))
	if !ok {
		return jkVersion{}, "", false
	}
	return v, string(m[1]), true
}
