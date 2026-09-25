package sharepoint

import "gopoc/internal/httpx"

// buildFrom extracts the SharePoint build, preferring the
// MicrosoftSharePointTeamServices header and falling back to the body. The
// header reports a minimum build level and can lag the farm's real patch state,
// so a version match is treated as heuristic (detected), never confirmed.
func buildFrom(r httpx.Response) (SPBuild, bool) {
	if h := r.Get("MicrosoftSharePointTeamServices"); h != "" {
		if b, ok := parseBuild(h); ok {
			return b, true
		}
	}
	return parseBuild(string(r.Body))
}
