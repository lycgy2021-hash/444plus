// Package detect provides shared checker scaffolding so each CVE checker only
// declares what is specific to it. VersionChecker covers passive banner/version
// detection; ProbeChecker covers safe active-probe (POST) detection. Both
// implement model.Checker and plug into the same engine, registry and policy.
package detect

import (
	"regexp"
	"strconv"
	"strings"
)

// Version is a parsed major.minor.patch triple.
type Version [3]int

func Less(a, b Version) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func ParseVersion(s string) (Version, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var v Version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, false
		}
		v[i] = n
	}
	return v, true
}

// ExtractVersion returns the single unambiguous version captured by re in a
// Server banner. re must capture the dotted version in group 1. Missing,
// malformed or conflicting versions yield ok=false, so callers report unknown
// rather than guessing. A capture immediately followed by another digit or dot
// (e.g. 1.2.3.4) is rejected as a longer, mismatched version.
func ExtractVersion(banner string, re *regexp.Regexp) (string, Version, bool) {
	matches := re.FindAllStringSubmatchIndex(banner, -1)
	found := ""
	for _, m := range matches {
		end := m[3]
		if end < len(banner) && (banner[end] == '.' || banner[end] >= '0' && banner[end] <= '9') {
			continue
		}
		candidate := banner[m[2]:end]
		if found != "" && found != candidate {
			return "", Version{}, false
		}
		found = candidate
	}
	if found == "" {
		return "", Version{}, false
	}
	v, ok := ParseVersion(found)
	if !ok {
		return "", Version{}, false
	}
	return found, v, true
}
