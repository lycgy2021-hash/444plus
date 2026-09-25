package netscaler

import (
	"strings"

	"gopoc/internal/httpx"
)

// productMarkers identify NetScaler specifically — NOT a generic Citrix page. A
// bare "citrix" string is deliberately excluded so a Citrix logo alone never
// counts.
var productMarkers = []string{
	"netscaler", "citrix gateway", "nsgslb", "_ctxstxt",
	"/vpn/js/", "logonpoint", "/nf/auth", "ns_af", "nsc_",
}

// gatewayMarkers indicate a VPN/ICA/CVPN/RDP Gateway service face.
var gatewayMarkers = []string{"citrix gateway", "/vpn/js/", "gateway_login_form", "vpn_form", "/vpn/index.html"}

// aaaMarkers indicate an AAA vServer authentication face.
var aaaMarkers = []string{"logonpoint", "/nf/auth", "doauthentication", "nsaaa"}

func isNSResponse(r httpx.Response) bool {
	if strings.Contains(strings.ToLower(r.Get("Server")), "netscaler") {
		return true
	}
	return containsAny(strings.ToLower(string(r.Body)), productMarkers)
}

func containsAny(s string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
