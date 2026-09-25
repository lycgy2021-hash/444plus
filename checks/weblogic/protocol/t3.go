// Package protocol implements protocol-level exposure probes for WebLogic. Each
// probe performs a real handshake/feature check, never inferring a protocol from
// an open port alone. Probes are non-destructive: they read banners, not exploit.
package protocol

import (
	"context"
	"regexp"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// t3Handshake is a minimal T3 ClientHello. A WebLogic T3 listener replies with a
// HELO line carrying the server version.
var t3Handshake = []byte("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")

var heloVersionRE = regexp.MustCompile(`^HELO:([0-9]+(?:\.[0-9]+)+)`)

// T3 probes the T3 protocol. It returns whether T3 is exposed and the server
// version parsed from the HELO reply (empty if none).
func T3(ctx context.Context, client httpx.Probe, target model.Target) (exposed bool, version string, obs model.Observation) {
	resp, err := client.TCP(ctx, target, t3Handshake, 512)
	obs = model.Observation{Kind: "t3_handshake", URL: target.Origin(), Bytes: len(resp)}
	if err != nil {
		obs.Error = err.Error()
		return false, "", obs
	}
	s := string(resp)
	if !strings.HasPrefix(s, "HELO:") {
		return false, "", obs
	}
	if m := heloVersionRE.FindStringSubmatch(s); m != nil {
		version = m[1]
	}
	return true, version, obs
}
