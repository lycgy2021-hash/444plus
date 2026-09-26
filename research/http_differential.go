package research

import (
	"context"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// HTTPDifferentialValidator is a concrete, deterministic, read-only validator: it
// tests a candidate hypothesis of a path-normalization discrepancy by comparing a
// baseline request with an equivalent-but-encoded variant. Critically, the probe
// paths are the validator's OWN fixed choice, never taken from the candidate or
// any model output — so a hypothesis's free text can never become a request. It
// sends only read-only GETs through the policy-gated httpx client.
type HTTPDifferentialValidator struct {
	client httpx.Probe
}

func NewHTTPDifferentialValidator(client httpx.Probe) *HTTPDifferentialValidator {
	return &HTTPDifferentialValidator{client: client}
}

func (v *HTTPDifferentialValidator) Name() string { return "http-differential" }

// Supports matches path-normalization / generic http-differential hypotheses by
// type. It performs no I/O.
func (v *HTTPDifferentialValidator) Supports(c *Candidate) bool {
	return c.Type == "http_differential" || c.Type == "path_normalization"
}

// baselinePath and variantPath are FIXED, safe, read-only probes owned by the
// validator. "/%2e/" is an encoded "./" segment: a server (or front/back-end
// pair) that resolves it differently from "/" reveals a normalization
// discrepancy. Both are plain GETs; neither changes state.
const (
	baselinePath = "/"
	variantPath  = "/%2e/"
)

func (v *HTTPDifferentialValidator) Validate(ctx context.Context, target model.Target, _ *Candidate) (ValidationResult, error) {
	res := ValidationResult{Validator: v.Name(), Outcome: OutcomeNoSignal}

	base, baseErr := v.client.Get(ctx, target, baselinePath)
	variant, varErr := v.client.Get(ctx, target, variantPath)
	res.Evidence = []Observation{
		httpObservation("baseline_response", baselinePath, base, baseErr),
		httpObservation("normalized_response", variantPath, variant, varErr),
	}

	if baseErr != nil || varErr != nil {
		return res, nil // a failed probe is no signal, not an error to abort on
	}
	// A normalization discrepancy: the encoded-equivalent path is handled
	// differently from the baseline (different status, or different body).
	if base.StatusCode != variant.StatusCode || base.SHA256 != variant.SHA256 {
		res.Outcome = OutcomeReproduced
	}
	return res, nil
}

func httpObservation(kind, path string, r httpx.Response, err error) Observation {
	o := Observation{
		Kind:          kind,
		Source:        "http-differential",
		Endpoint:      r.URL,
		Request:       RequestSummary{Method: "GET", Path: path},
		NetworkAction: ActionReadOnly,
		Tags:          []string{kind},
	}
	if err != nil {
		o.Error = err.Error()
		return o
	}
	o.Response = ResponseSummary{StatusCode: r.StatusCode, SHA256: r.SHA256, Bytes: r.Bytes, Truncated: r.Truncated}
	if r.SHA256 != "" {
		o.Artifacts = []Artifact{{Kind: "response_body_sha256", Ref: r.SHA256}}
	}
	return o
}
