package jenkins

import (
	"context"
	"strings"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// Anonymous-access evidence. Deliberately NOT a verdict driver: some Jenkins
// instances legitimately allow anonymous read of limited metadata, so a 200 on
// /api/json is not by itself a high-risk finding (that would break our low-FP
// rule). We gather it as supporting evidence only. The genuinely high-risk
// anonymous condition — the Groovy Script Console — has its own precise checker.

const (
	apiJSONPath = "/api/json"
	whoAmIPath  = "/whoAmI/api/json"
)

// anonEvidence records what an unauthenticated caller can see. It informs the
// report but never elevates a verdict on its own.
type anonEvidence struct {
	apiJSONStatus int
	whoAmIStatus  int
	whoAmIBody    string
	obs           []model.Observation
}

// gatherAnon issues two cheap read-only GETs to characterise the anonymous
// boundary. /whoAmI reflects the caller's own identity/authorities; /api/json is
// the REST metadata face. Neither result changes a verdict here.
func gatherAnon(ctx context.Context, client httpx.Probe, target model.Target) anonEvidence {
	var e anonEvidence
	api, err := client.Get(ctx, target, apiJSONPath)
	e.apiJSONStatus = api.StatusCode
	e.obs = append(e.obs, api.Observation("anon_api_json", err))

	who, err := client.Get(ctx, target, whoAmIPath)
	e.whoAmIStatus = who.StatusCode
	e.whoAmIBody = string(who.Body)
	e.obs = append(e.obs, who.Observation("anon_whoami", err))
	return e
}

// apiReadable reports whether anonymous callers can read the REST API metadata.
func (e anonEvidence) apiReadable() bool { return e.apiJSONStatus == 200 }

// note summarises the anonymous boundary for a report message, e.g. so a
// Script-Console finding can add "anonymous can also read the REST API".
func (e anonEvidence) note() string {
	var parts []string
	if e.apiReadable() {
		parts = append(parts, "anonymous /api/json is readable")
	}
	if strings.Contains(e.whoAmIBody, `"anonymous":true`) {
		parts = append(parts, "the caller is unauthenticated (anonymous)")
	}
	return strings.Join(parts, "; ")
}
