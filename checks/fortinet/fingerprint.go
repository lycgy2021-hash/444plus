package fortinet

import "strings"

// nameMarkers are explicit product-name substrings, checked FIRST so a page that
// names its product wins over FortiOS behavioral markers (which several Fortinet
// web surfaces share). Heuristic web-surface markers, NOT validated against live
// appliances; cookies (e.g. SVPNCOOKIE) are not visible to the HTTP client.
var nameMarkers = []struct{ product, marker string }{
	{"FortiProxy", "fortiproxy"},
	{"FortiMail", "fortimail"},
	{"FortiVoice", "fortivoice"},
	{"FortiNDR", "fortindr"},
	{"FortiRecorder", "fortirecorder"},
	{"FortiCamera", "forticamera"},
	{"FortiOS", "fortigate"},
	{"FortiOS", "fortios"},
}

// fortiOSBehavioral identify a FortiOS/FortiGate management or SSL-VPN surface
// when no explicit product name is present.
var fortiOSBehavioral = []string{"fgt_lang", "/remote/fgt_lang", "/remote/login"}

// genericMarkers indicate an unclassified Fortinet surface (product "Fortinet",
// yielding at most unknown).
var genericMarkers = []string{"logindisclaimer", "fortinet", "/sslvpn/"}

// fingerprint classifies a response body: a specific product when a product name
// is present, "FortiOS" for FortiOS behavioral markers, "Fortinet" for a generic
// marker, and ("", false) otherwise.
func fingerprint(body string) (string, bool) {
	lower := strings.ToLower(body)
	for _, nm := range nameMarkers {
		if strings.Contains(lower, nm.marker) {
			return nm.product, true
		}
	}
	for _, m := range fortiOSBehavioral {
		if strings.Contains(lower, m) {
			return "FortiOS", true
		}
	}
	for _, m := range genericMarkers {
		if strings.Contains(lower, m) {
			return "Fortinet", true
		}
	}
	return "", false
}
