package fortinet

import "regexp"

// Modern FortiOS restricts unauthenticated version disclosure, so extraction is
// best-effort: when it fails the checker reports unknown rather than guessing.
// These patterns cover builds that expose a version in the login page/JSON.
var versionREs = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)Forti[A-Za-z]+[ /_-]v?([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)\bbuild[^0-9]{0,4}([0-9]+\.[0-9]+\.[0-9]+)`),
}

// extractVersion returns the first version-looking string, or ("", false).
func extractVersion(body string) (string, bool) {
	for _, re := range versionREs {
		if m := re.FindStringSubmatch(body); m != nil {
			return m[1], true
		}
	}
	return "", false
}
