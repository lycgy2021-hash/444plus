package tomcat

import (
	"regexp"
	"strings"

	"gopoc/internal/httpx"
)

// tomcatVersionRE matches the version banner Tomcat prints on its error pages,
// e.g. "Apache Tomcat/9.0.97".
var tomcatVersionRE = regexp.MustCompile(`(?i)Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)`)

// isTomcat identifies Tomcat from the error-page banner or the Coyote connector
// Server header. A version banner is the strongest signal.
func isTomcat(r httpx.Response) bool {
	if strings.Contains(strings.ToLower(r.Get("Server")), "coyote") {
		return true
	}
	return tomcatVersionRE.MatchString(string(r.Body))
}

// version extracts the Tomcat version from the error-page banner, or ("", false).
func version(r httpx.Response) (string, bool) {
	if m := tomcatVersionRE.FindStringSubmatch(string(r.Body)); m != nil {
		return m[1], true
	}
	return "", false
}
