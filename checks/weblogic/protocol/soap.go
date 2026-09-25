package protocol

import (
	"context"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// wsEndpoints are WebLogic web-service endpoints whose presence indicates the
// SOAP/WS attack surface (e.g. the wls-wsat and async endpoints).
var wsEndpoints = []string{"/wls-wsat/CoordinatorPortType", "/_async/AsyncResponseService"}

// SOAP probes for exposed WebLogic web-service endpoints over HTTP. An endpoint
// that is not 404 (and not a transport error) is treated as present.
func SOAP(ctx context.Context, client httpx.Probe, target model.Target) (bool, []model.Observation) {
	var obs []model.Observation
	exposed := false
	for _, p := range wsEndpoints {
		r, err := client.Get(ctx, target, p)
		obs = append(obs, r.Observation("soap_endpoint", err))
		if err == nil && r.StatusCode != 404 && r.StatusCode != 410 {
			exposed = true
		}
	}
	return exposed, obs
}
