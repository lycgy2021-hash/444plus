package sharepoint

import (
	"context"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// toolShellPath is the endpoint at the center of the ToolShell chain. A plain
// GET (no exploit Referer, no payload) is a safe existence check: it tells us the
// attack surface is reachable without triggering the vulnerability.
const toolShellPath = "/_layouts/15/ToolPane.aspx"

// exposure reports whether the ToolShell entry point is present/reachable. A 404
// means absent; 200/redirect/auth-gated means the surface exists.
func exposure(ctx context.Context, client httpx.Probe, target model.Target) (bool, model.Observation) {
	r, err := client.Get(ctx, target, toolShellPath)
	obs := r.Observation("toolshell_surface", err)
	if err != nil {
		return false, obs
	}
	switch r.StatusCode {
	case 404, 410:
		return false, obs
	case 200, 301, 302, 303, 307, 308, 401, 403, 500:
		return true, obs
	default:
		return false, obs
	}
}
