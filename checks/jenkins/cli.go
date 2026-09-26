package jenkins

// CLI-surface constants and reachability logic. CVE-2024-23897's vector is the
// Jenkins CLI; before we ever call a version "likely exploitable" we confirm the
// CLI subsystem is actually reachable, not merely that the version is old.

const (
	// cliJarPath serves the CLI client jar. A 200 here means the CLI subsystem
	// is enabled and the transport is present — confirmed on live 2.568.3
	// (downloadable even in the secured default state).
	cliJarPath = "/jnlpJars/jenkins-cli.jar"
	// cliPath is the HTTP CLI endpoint. Confirmed on live 2.568.3: GET /cli
	// returns 302 (it exists and redirects), not 404.
	cliPath = "/cli"
)

// cliExposed reports whether the Jenkins CLI attack surface is reachable. The
// downloadable client jar (200) is the strongest single signal; otherwise the
// /cli endpoint answering with anything other than 404 (it redirects/negotiates
// rather than "not found") indicates the CLI is enabled. A 404 on both means the
// CLI has been disabled — the documented mitigation for CVE-2024-23897.
func (a assessment) cliExposed() bool {
	if a.cliJarErr == nil && a.cliJar.StatusCode == 200 {
		return true
	}
	if a.cliErr == nil {
		switch a.cli.StatusCode {
		case 200, 302, 400, 405:
			return true
		}
	}
	return false
}

// cliSurface renders a short human description of what made the CLI reachable.
func (a assessment) cliSurface() string {
	switch {
	case a.cliJarErr == nil && a.cliJar.StatusCode == 200:
		return "jenkins-cli.jar is downloadable"
	case a.cliErr == nil:
		return "the /cli endpoint is enabled"
	default:
		return "the CLI endpoint is reachable"
	}
}
