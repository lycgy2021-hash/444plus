package gitlab

import "gopoc/internal/httpx"

// CVE-2023-2825: an unsanitized `@filename` in GitLab's object-storage
// `retrieve_from_store()` allowed `../` path traversal to read arbitrary files on
// the server as an UNAUTHENTICATED user (given a public project nested ≥5 groups
// deep). CVSS 10.0.
//
// Affected: EXACTLY 16.0.0. Fixed: 16.0.1. Nothing before 16.0.0 and nothing from
// 16.0.1 onward is affected — an unusually narrow, unambiguous boundary.
//
// We cap at `detected`: version == 16.0.0 → `detected`. There is no safe
// reachability probe (confirming it would require attempting the traversal, i.e.
// reading a server file), so this checker is version-only and never elevates or
// confirms. The arbitrary file read is NEVER attempted.
const cve20232825ID = "CVE-2023-2825"

func affectedCVE20232825(v glVersion) bool {
	return v.major == 16 && v.minor == 0 && v.patch == 0
}

// NewCVE20232825 constructs the CVE-2023-2825 checker. It shares GitLab's
// assessment (fingerprint + /help version) with the other checkers via
// assesscache, so it adds no extra probes on a single-IP scan.
func NewCVE20232825(client httpx.Probe) *advisoryChecker {
	c := newAdvisory(
		cve20232825ID,
		"GitLab Path Traversal Arbitrary File Read (retrieve_from_store)",
		affectedCVE20232825,
		client,
	)
	c.notAttempted = "arbitrary file read"
	// surfaceReachable stays nil: version-only, caps at detected.
	c.meta.References = []string{
		"https://about.gitlab.com/releases/2023/05/23/critical-security-release-gitlab-16-0-1-released/",
		"https://nvd.nist.gov/vuln/detail/CVE-2023-2825",
	}
	return c
}
