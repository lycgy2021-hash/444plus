// Package jbosswildfly holds detection for JBoss EAP / WildFly: an
// attack-surface base (fingerprint, management-interface auth behavior,
// best-effort version, EJB-remoting protocol exposure) rather than a bundle of
// CVE checkers. There is no recent unauthenticated-RCE CVE in this product
// worth chasing (see docs/jboss-wildfly-attack-surface.md); the reproducible,
// high-value condition is an unauthenticated management interface, which is a
// misconfiguration, not a CVE.
package jbosswildfly

import (
	"regexp"

	"gopoc/internal/httpx"
)

// welcomeRE matches the bundled WildFly/JBoss EAP welcome page. Confirmed on a
// live WildFly 41.0.1.Final image: the app port sends no Server header, so the
// welcome body is the reliable app-port signal, not a banner.
var welcomeRE = regexp.MustCompile(`(?i)Welcome to (?:WildFly|JBoss\s*(?:AS|EAP)?)\b|The WildFly Authors`)

// managementErrorRE matches WildFly/JBoss management-kernel error codes
// (WFLYxxNNNN for WildFly subsystems, JBASNNNNNN for legacy JBoss AS7/EAP6).
// These prefixes are unique to this product family and never appear in an
// unrelated Java application's own error output.
var managementErrorRE = regexp.MustCompile(`\b(?:WFLY[A-Z]{2,6}\d{4,5}|JBAS\d{6})\b`)

// haloConsoleRE matches the HAL management console WildFly/EAP serve on the
// management port (e.g. :9990/console).
var haloConsoleRE = regexp.MustCompile(`(?i)HAL Management Console`)

// looksLikeProduct reports whether r carries an HTTP-body signal specific to
// JBoss/WildFly: the bundled welcome page, a management-kernel error code, or
// the HAL console. It deliberately does not use the Server header — modern
// WildFly/EAP send none — and does not match on the bare word "WildFly"
// appearing anywhere in a page, which a spoofed page could imitate cheaply;
// the verdict this feeds never rises above `detected` on this signal alone.
func looksLikeProduct(r httpx.Response) bool {
	body := string(r.Body)
	return welcomeRE.MatchString(body) || managementErrorRE.MatchString(body) || haloConsoleRE.MatchString(body)
}
