// Package nginx holds detection-only checkers for NGINX CVEs.
package nginx

import (
	"regexp"

	"gopoc/checks/detect"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

var versionRE = regexp.MustCompile(`(?i)(?:^|[^a-z])nginx/([0-9]+\.[0-9]+\.[0-9]+)`)

// NewCVE202642533 detects NGINX versions affected by the map-directive regex
// heap buffer overflow. Fixed in 1.31.3 (mainline) and 1.30.4 (stable), so a
// version is affected when it is below 1.30.4 or in the 1.31.0–1.31.2 mainline
// window. Confidence is moderate: exploitation also needs a map block whose
// string expression references regex captures before the map output variable,
// which the banner cannot reveal.
func NewCVE202642533(client httpx.Probe) *detect.VersionChecker {
	return &detect.VersionChecker{
		Meta: model.Metadata{
			ID:         "CVE-2026-42533",
			Name:       "NGINX map Regex Heap Buffer Overflow",
			Product:    "nginx",
			Severity:   "high",
			References: []string{"https://www.cve.org/CVERecord?id=CVE-2026-42533"},
		},
		Client: client,
		Re:     versionRE,
		Affected: func(v detect.Version) bool {
			if detect.Less(v, detect.Version{1, 30, 4}) {
				return true
			}
			if !detect.Less(v, detect.Version{1, 31, 0}) && detect.Less(v, detect.Version{1, 31, 3}) {
				return true
			}
			return false
		},
		DetectedConfidence: 60,
		DetectedMessage:    "nginx version is in the affected range; this is a version match only — a specific vulnerable map configuration is required and is not verified by the banner",
		NotFoundMessage:    "Advertised nginx version is outside this CVE's affected range; banner evidence does not prove absence",
		UnknownMessage:     "No unambiguous nginx version exposed (server_tokens may be off); vulnerability status is unknown",
	}
}
