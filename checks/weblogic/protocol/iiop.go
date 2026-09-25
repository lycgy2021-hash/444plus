package protocol

import (
	"context"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// giopProbe is a minimal GIOP 1.2 message. IIOP detection is deliberately
// CONSERVATIVE: we report exposed only on a GIOP reply, never inferring IIOP
// from an open port. A missing reply yields not-exposed (a safe false negative),
// which is preferable to mislabeling a plain listener as IIOP.
var giopProbe = []byte("GIOP\x01\x02\x00\x03\x00\x00\x00\x00")

// IIOP probes the IIOP/GIOP protocol.
func IIOP(ctx context.Context, client httpx.Probe, target model.Target) (bool, model.Observation) {
	resp, err := client.TCP(ctx, target, giopProbe, 128)
	obs := model.Observation{Kind: "iiop_giop", URL: target.Origin(), Bytes: len(resp)}
	if err != nil {
		obs.Error = err.Error()
		return false, obs
	}
	return strings.HasPrefix(string(resp), "GIOP"), obs
}
