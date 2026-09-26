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

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"gopoc/internal/model"
)

// Provenance is the immutable record of where a piece of research came from. It
// is set once, at the moment the producer creates the Evidence or Candidate, and
// never mutated afterward — so a candidate that travels diff → AI → validator →
// reproduced can always answer: where did this originate, which exact input
// produced it, and (via the Candidate's append-only History) which validator
// advanced it and on what evidence. InputHash makes the tie tamper-evident: the
// same input always hashes the same, and evidence itself is content-addressed by
// SHA-256, so a later substitution is detectable.
type Provenance struct {
	// ProducerKind matches an Origin kind ("ai","fuzz","diff","source_audit",
	// "passive","human") or "detection" for evidence adapted from the detection
	// plane.
	ProducerKind string    `json:"producer_kind"`
	ProducerID   string    `json:"producer_id,omitempty"`
	Tool         string    `json:"tool,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	// RawInputHash is the byte-for-byte SHA-256 (hex) of the ORIGINAL input that
	// produced this — the raw diff blob, the raw crash input, the exact bytes sent
	// to a model — taken BEFORE any parser/normalization step. Hashing the raw
	// input (not a normalized form) is deliberate: newline/encoding/parser
	// preprocessing must not break evidence traceability.
	RawInputHash string `json:"raw_input_hash,omitempty"`
}

// RawInputHash returns the hex SHA-256 of b, for stamping Provenance.RawInputHash
// over raw input bytes.
func RawInputHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newProvenance stamps a provenance record at the current time.
func newProvenance(kind, id, tool, rawInputHash string) Provenance {
	return Provenance{ProducerKind: kind, ProducerID: id, Tool: tool, Timestamp: time.Now().UTC(), RawInputHash: rawInputHash}
}

// Hash returns the content hash (hex SHA-256 of the observation's canonical JSON)
// used to reference this fact tamper-evidently from a candidate's history: a
// later substitution of the evidence changes the hash and breaks the reference.
func (o Observation) Hash() string {
	b, _ := json.Marshal(o)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

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
	// ID is a stable handle within one Evidence bundle, so a Proposal can point at
	// facts via related_observations (e.g. "obs-17").
	ID            string          `json:"id,omitempty"`
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
	// provenance is unexported so it cannot be rewritten by another package after
	// construction; read it through Provenance(), which returns a copy. It is set
	// by a producer/constructor (e.g. FromModelEvidence) and intentionally left
	// out of the JSON sent to a model.
	provenance Provenance
}

// Provenance returns a copy of the evidence's immutable origin record.
func (e Evidence) Provenance() Provenance { return e.provenance }

// FromModelEvidence derives research Evidence from a detection-plane
// model.Evidence WITHOUT changing it — the adapter that bridges the frozen base
// to the research plane. Detection observations are HTTP GET/OPTIONS or banner
// reads, so each maps to a read-only Observation; the product version carries
// across as a ProductFact. Response bodies are referenced by their existing
// SHA-256, never copied inline.
func FromModelEvidence(target, source string, ev model.Evidence) Evidence {
	out := Evidence{Target: target}
	// Provenance ties this bundle to the exact detection evidence it was built
	// from; the hash is over the marshaled model.Evidence.
	raw, _ := json.Marshal(ev)
	out.provenance = newProvenance("detection", source, "detection", RawInputHash(raw))
	if ev.Version != "" {
		out.Product = ProductFact{Version: ev.Version}
	}
	for i, o := range ev.Observations {
		ro := Observation{
			ID:            fmt.Sprintf("obs-%d", i+1),
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
