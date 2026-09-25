// Package netscaler holds detection-only checkers for Citrix NetScaler ADC /
// Gateway. It never equates a generic Citrix page with NetScaler: product-
// specific evidence (Gateway/AAA surface, NetScaler markers) is required. It caps
// at `likely`; the memory-corruption bug is never triggered. No live appliance
// in this lab — fingerprints are heuristic, validated by unit tests.
package netscaler

import "regexp"

// nsVersion is a NetScaler release: a branch (with optional FIPS/NDcPP flavor)
// and a build (major.minor), e.g. branch "13.1-FIPS" build {37, 240}.
type nsVersion struct {
	branch string
	build  [2]int
}

func lessBuild(a, b [2]int) bool {
	if a[0] != b[0] {
		return a[0] < b[0]
	}
	return a[1] < b[1]
}

// nsVersionRE matches "NS14.1 47.46", "14.1-47.46", "13.1-FIPS 37.240", etc.
var nsVersionRE = regexp.MustCompile(`(?i)(?:NS)?\s*(1[0-4]\.[0-9])(-FIPS|-NDcPP)?[\s-]+([0-9]+)\.([0-9]+)`)

// parseVersion extracts a NetScaler version from a string, or ok=false.
func parseVersion(s string) (nsVersion, bool) {
	m := nsVersionRE.FindStringSubmatch(s)
	if m == nil {
		return nsVersion{}, false
	}
	branch := m[1]
	if m[2] != "" {
		branch += normalizeFlavor(m[2])
	}
	var maj, min int
	for _, c := range m[3] {
		maj = maj*10 + int(c-'0')
	}
	for _, c := range m[4] {
		min = min*10 + int(c-'0')
	}
	return nsVersion{branch: branch, build: [2]int{maj, min}}, true
}

func normalizeFlavor(s string) string {
	switch {
	case len(s) >= 5 && (s[1] == 'F' || s[1] == 'f'):
		return "-FIPS"
	default:
		return "-NDcPP"
	}
}
