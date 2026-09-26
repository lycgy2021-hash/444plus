package jenkins

import "gopoc/internal/httpx"

// CVE-2024-23897: Jenkins' CLI command parser (args4j) leaves the expandAtFiles
// feature enabled, so an '@' followed by a path in a CLI argument is replaced
// with that file's contents — an UNAUTHENTICATED arbitrary file read on the
// controller (first line[s] unauth; whole file with Overall/Read), which chains
// to RCE via leaked secrets. CVSS 9.8.
//
// Affected: weekly ≤ 2.441, LTS ≤ 2.426.2. Fixed: weekly 2.442, LTS 2.426.3
// (and every later LTS baseline, e.g. 2.440.1), which disable expandAtFiles.
//
// We cap at `likely`: affected version → `detected`; affected AND the CLI
// surface reachable → `likely`. The file read itself is NEVER performed in a
// default scan — reproducing it would read target file contents. A controlled,
// marker-file confirmation exists only as a lab test (see the package tests),
// never on the default single-IP path.
const cve202423897ID = "CVE-2024-23897"

// affectedCVE202423897 encodes the two documented fix lines. Component count
// distinguishes the lines: two components = weekly, three = LTS.
func affectedCVE202423897(v jkVersion) bool {
	if v.isLTS {
		// LTS X.Y.Z: fixed at 2.426.3. Baselines below 2.426 are all older and
		// affected; the 2.426 baseline is affected only up to patch 2; every LTS
		// baseline above 2.426 (2.440.1, 2.452.x, ...) carries the fix.
		switch {
		case v.major != 2:
			return v.major < 2
		case v.minor < 426:
			return true
		case v.minor == 426:
			return v.patch < 3
		default:
			return false
		}
	}
	// Weekly X.Y: fixed at 2.442, so affected iff below (2,442) i.e. ≤ 2.441.
	switch {
	case v.major != 2:
		return v.major < 2
	default:
		return v.minor < 442
	}
}

// NewCVE202423897 constructs the CVE-2024-23897 checker.
func NewCVE202423897(client httpx.Probe) *advisoryChecker {
	c := newAdvisory(
		cve202423897ID,
		"Jenkins CLI Arbitrary File Read (args4j @file expansion)",
		affectedCVE202423897,
		client,
	)
	c.surfaceName = "Jenkins CLI"
	c.surfaceReachable = func(a assessment) (bool, string) {
		return a.cliExposed(), a.cliSurface()
	}
	c.meta.References = []string{"https://www.jenkins.io/security/advisory/2024-01-24/"}
	return c
}
