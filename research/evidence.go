// Package research is the Research Plane: it sits beside the deterministic
// detection plane (checks/, internal/engine, internal/model) and never replaces
// it. It turns real, structured facts into model-consumable evidence, lets a
// (non-authoritative) ai.Provider propose hypotheses, and tracks those as
// Candidates whose state only a deterministic validator can advance.
//
// The one rule that makes this safe: AI is not authority. A Provider's output
// becomes, at most, a hypothesis-level Candidate; Evidence is the only truth; and
// a Candidate can never be turned into a detection Verdict. This package imports
// internal/ai and internal/model but nothing in the detection plane imports it —
// the dependency points one way, so the frozen detection base cannot regress.
package research

import "gopoc/internal/model"

// NetworkAction records what a probe did to the target. The research plane
// observes; it does not attack. There is deliberately no "exploit" or
// "state_change" value here — a candidate that would need those to observe stays
// a hypothesis until a purpose-built, safe validator exists.
type NetworkAction string

const (
	ActionNone     NetworkAction = "none"      // static/passive; no request was sent
	ActionReadOnly NetworkAction = "read_only" // GET/OPTIONS/banner read
	ActionProbe    NetworkAction = "probe"     // safe, non-destructive POST probe
)

// ProductFact is what we believe about the product, as facts (not guesses a
// model made): a name/version/build we actually read.
type ProductFact struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"`
}

// ProtocolFact captures protocol-level facts, e.g. OpenWire magic + provider
// version, a T3 HELO, an HTTP normalization quirk.
type ProtocolFact struct {
	Name  string            `json:"name,omitempty"`
	Facts map[string]string `json:"facts,omitempty"`
}

// RequestSummary / ResponseSummary are bounded summaries, never raw dumps: the
// model receives facts, not noise. Bodies are referenced by hash via Artifacts.
type RequestSummary struct {
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

type ResponseSummary struct {
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	Bytes      int               `json:"bytes,omitempty"`
	Truncated  bool              `json:"truncated,omitempty"`
}

// Artifact references a stored blob (a response body, a banner, a crash input) by
// handle/hash — never the raw bytes inline.
type Artifact struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// Observation is one research-plane fact. It is the richer, model-consumable
// analogue of model.Observation: structured facts (product, protocol, bounded
// request/response) plus the network action that produced it. It is never a
// verdict and never carries a decision.
type Observation struct {
	Kind          string          `json:"kind"`
	Source        string          `json:"source,omitempty"`
	Endpoint      string          `json:"endpoint,omitempty"`
	Request       RequestSummary  `json:"request,omitempty"`
	Response      ResponseSummary `json:"response,omitempty"`
	Product       ProductFact     `json:"product,omitempty"`
	Protocol      ProtocolFact    `json:"protocol,omitempty"`
	NetworkAction NetworkAction   `json:"network_action"`
	Tags          []string        `json:"tags,omitempty"`
	Artifacts     []Artifact      `json:"artifacts,omitempty"`
	Error         string          `json:"error,omitempty"`
}

// Evidence is the machine-consumable bundle handed to an ai.Provider: structured
// facts about one target, never a raw HTTP dump and never a verdict.
type Evidence struct {
	Target       string        `json:"target"`
	Product      ProductFact   `json:"product,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
	// Notes are short, factual context lines authored by the research plane (not
	// model output).
	Notes []string `json:"notes,omitempty"`
}

// FromModelEvidence derives research Evidence from a detection-plane
// model.Evidence WITHOUT changing it — the adapter that bridges the frozen base
// to the research plane. Detection observations are HTTP GET/OPTIONS or banner
// reads, so each maps to a read-only Observation; the product version carries
// across as a ProductFact. Response bodies are referenced by their existing
// SHA-256, never copied inline.
func FromModelEvidence(target, source string, ev model.Evidence) Evidence {
	out := Evidence{Target: target}
	if ev.Version != "" {
		out.Product = ProductFact{Version: ev.Version}
	}
	for _, o := range ev.Observations {
		ro := Observation{
			Kind:          o.Kind,
			Source:        source,
			Endpoint:      o.URL,
			NetworkAction: ActionReadOnly, // detection-plane observations are read-only
			Response: ResponseSummary{
				StatusCode: o.StatusCode,
				Headers:    o.Headers,
				SHA256:     o.SHA256,
				Bytes:      o.Bytes,
				Truncated:  o.Truncated,
			},
			Error: o.Error,
		}
		if o.SHA256 != "" {
			ro.Artifacts = append(ro.Artifacts, Artifact{Kind: "response_body_sha256", Ref: o.SHA256})
		}
		out.Observations = append(out.Observations, ro)
	}
	return out
}
