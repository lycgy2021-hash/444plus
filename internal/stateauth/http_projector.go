package stateauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// HTTPArtifact is the canonical, deterministic wire shape a Collector uses
// to encode an observed HTTP response into StateArtifact.Raw — the ONLY
// format HTTPStateProjector knows how to parse back out. It captures the
// three facts a v1 fixture needs and nothing else: no full header dump, no
// raw wire bytes, no timing — a minimal but meaningfully stronger fixture
// than RawLenProjector (see that type's own doc for why "just the byte
// length" is too weak for real state distinctions).
type HTTPArtifact struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// MarshalHTTPArtifact deterministically encodes a — the same struct, the
// same field order, every time, via Go's json package (which marshals
// struct fields in their declared order, not map order). A Collector calls
// this to build the StateArtifact.Raw bytes it returns.
func MarshalHTTPArtifact(a HTTPArtifact) ([]byte, error) {
	return json.Marshal(a)
}

// HTTPStateProjector turns a StateArtifact whose Raw bytes are a marshaled
// HTTPArtifact into an authoritative Fingerprint. Its Facts are
// deliberately narrow but real: the status code, the content-type, and a
// SHA-256 of the response body (never the raw body itself — Facts are
// meant to be small, comparable strings, not evidence storage) — enough to
// tell apart two responses of identical LENGTH but different content (e.g.
// {"authenticated":false} vs {"authenticated":true}), which RawLenProjector
// cannot.
//
// Like RawLenProjector, this type lives inside stateauth (not research) for
// the reason StateProjector's own doc requires: Project must call the
// unexported newFingerprint constructor.
type HTTPStateProjector struct{}

// ID identifies this projector.
func (HTTPStateProjector) ID() ProjectorID { return "http-v1" }

// Project parses a.Raw as a marshaled HTTPArtifact and derives Facts from
// it. A malformed a.Raw (not valid JSON, or not shaped like HTTPArtifact)
// is an error, never a best-effort partial Fingerprint.
func (p HTTPStateProjector) Project(a StateArtifact) (Fingerprint, error) {
	var art HTTPArtifact
	if err := json.Unmarshal(a.Raw, &art); err != nil {
		return Fingerprint{}, fmt.Errorf("stateauth: HTTPStateProjector: malformed StateArtifact.Raw: %w", err)
	}
	sum := sha256.Sum256(art.Body)
	facts := map[string]string{
		"status":       strconv.Itoa(art.Status),
		"content_type": art.ContentType,
		"body_sha256":  hex.EncodeToString(sum[:]),
	}
	return newFingerprint(a.ScopeHash, a.Raw, p.ID(), facts), nil
}
