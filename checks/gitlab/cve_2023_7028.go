package gitlab

import "gopoc/internal/httpx"

// CVE-2023-7028: GitLab's forgotten-password flow accepted an ARRAY of email
// addresses and sent the reset link to all of them, so an UNAUTHENTICATED
// attacker submits the victim's address plus an attacker-controlled address and
// receives the reset token — full account takeover (admin included). CVSS 10.0,
// actively exploited (CISA KEV).
//
// Introduced in 16.1.0 (no branch before 16.1 is affected). Affected/fixed per
// maintenance branch:
//
//	16.1.0–16.1.5  fixed 16.1.6
//	16.2.0–16.2.8  fixed 16.2.9
//	16.3.0–16.3.6  fixed 16.3.7
//	16.4.0–16.4.4  fixed 16.4.5
//	16.5.0–16.5.5  fixed 16.5.6
//	16.6.0–16.6.3  fixed 16.6.4
//	16.7.0–16.7.1  fixed 16.7.2
//
// 16.0.x and 16.8+ are not affected.
//
// We cap at `likely`: affected version → `detected`; affected AND the
// forgotten-password flow reachable → `likely`. The reset is NEVER submitted —
// POSTing the email array would send real password-reset emails.
const cve20237028ID = "CVE-2023-7028"

// lastAffectedPatch maps a 16.x minor branch to its last affected patch level.
// A branch not in the map (16.0, 16.8, …) is not affected at all.
var cve7028LastAffected = map[int]int{1: 5, 2: 8, 3: 6, 4: 4, 5: 5, 6: 3, 7: 1}

func affectedCVE20237028(v glVersion) bool {
	if v.major != 16 {
		return false
	}
	last, ok := cve7028LastAffected[v.minor]
	if !ok {
		return false
	}
	return v.patch <= last
}

// NewCVE20237028 constructs the CVE-2023-7028 checker.
func NewCVE20237028(client httpx.Probe) *advisoryChecker {
	c := newAdvisory(
		cve20237028ID,
		"GitLab Account Takeover via Password Reset (email array)",
		affectedCVE20237028,
		client,
	)
	c.surfaceName = "forgotten-password flow (/users/password)"
	c.notAttempted = "account takeover"
	c.surfaceReachable = func(a assessment) (bool, string) {
		if a.resetReachable {
			return true, "the reset form at /users/password/new is live; the reset was NOT submitted"
		}
		return false, ""
	}
	c.meta.References = []string{
		"https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/",
		"https://nvd.nist.gov/vuln/detail/CVE-2023-7028",
	}
	return c
}
