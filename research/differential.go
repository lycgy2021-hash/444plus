package research

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DifferentialProducer (S9 v1) turns a DifferentialCase — a set of responses to
// the SAME semantic request under different encodings/normalizations/boundaries/
// protocol variants — into hypothesis candidates when the responses disagree in a
// way that should not happen. It is a deterministic PRODUCER, not a prober: it
// consumes already-collected variant responses (like the diff and fuzz producers
// consume diffs and crashes), compares them canonically, filters run-noise, and
// classifies anomalies. It emits only hypotheses; a Validator reproduces safely
// and the Engine promotes.
//
// v1 is deliberately narrow: status / header-set / body-shape / accept-reject /
// normalization / boundary differences only. No attack-input generation.
type DifferentialProducer struct {
	newID func() string
}

func NewDifferentialProducer() *DifferentialProducer {
	return &DifferentialProducer{newID: SequentialIDs(time.Now().UTC().Year())}
}

func (p *DifferentialProducer) WithIDFunc(fn func() string) *DifferentialProducer {
	p.newID = fn
	return p
}

// DiffVariantKind labels what a variant is relative to the baseline. Encoding,
// normalization and protocol variants are expected to be EQUIVALENT to the
// baseline (a difference is an anomaly); a boundary variant probes a limit (a
// flip at the boundary is the anomaly).
type DiffVariantKind string

const (
	VariantBaseline      DiffVariantKind = "baseline"
	VariantEncoding      DiffVariantKind = "encoding"
	VariantNormalization DiffVariantKind = "normalization"
	VariantBoundary      DiffVariantKind = "boundary"
	VariantProtocol      DiffVariantKind = "protocol"
)

// DifferentialObservation is one variant's observed response. It carries facts
// only — no raw body, just its shape (content-type + length) plus optional
// parser accept/reject.
type DifferentialObservation struct {
	Variant     string            `json:"variant"`
	Kind        DiffVariantKind   `json:"kind"`
	Request     RequestSummary    `json:"request,omitempty"`
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	BodyLen     int               `json:"body_len"`
	Accepted    *bool             `json:"accepted,omitempty"`
}

// DifferentialCase groups variant responses to one semantic request. The baseline
// is the variant with Kind==VariantBaseline, or the first element.
type DifferentialCase struct {
	Target   string                    `json:"target"`
	Intent   string                    `json:"intent"`
	Variants []DifferentialObservation `json:"variants"`
}

// Anomaly types (candidate_type values).
const (
	AnomalyStatus        = "status_differential"
	AnomalyHeader        = "header_differential"
	AnomalyBodyShape     = "body_shape_differential"
	AnomalyAcceptReject  = "accept_reject_differential"
	AnomalyNormalization = "normalization_differential"
	AnomalyBoundary      = "boundary_differential"
)

// DiffAnomaly is a single classified disagreement between a variant and baseline.
type DiffAnomaly struct {
	Type    string
	Variant string
	Detail  string
}

// volatileHeaders are run-specific and excluded from comparison and hashing (they
// differ every response and would manufacture noise). Names are lowercased.
var volatileHeaders = map[string]bool{
	"date": true, "set-cookie": true, "cookie": true, "etag": true, "age": true,
	"expires": true, "last-modified": true, "x-request-id": true, "x-correlation-id": true,
	"x-runtime": true, "x-gitlab-meta": true, "cf-ray": true, "server-timing": true,
	"content-length": true, "keep-alive": true, "connection": true, "vary": true,
}

func stableHeaderKeys(h map[string]string) []string {
	var keys []string
	for k := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if !volatileHeaders[lk] {
			keys = append(keys, lk)
		}
	}
	sort.Strings(keys)
	return keys
}

func lenBucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n < 128:
		return "xs"
	case n < 1024:
		return "s"
	case n < 16384:
		return "m"
	case n < 262144:
		return "l"
	default:
		return "xl"
	}
}

func normContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 { // drop charset/boundary params
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// shape is the coarse body class used for body-shape comparison: normalized
// content-type + a length bucket. It ignores exact byte length so trivial size
// jitter is not an anomaly.
func shape(o DifferentialObservation) string {
	return normContentType(o.ContentType) + "|" + lenBucket(o.BodyLen)
}

func baselineOf(c DifferentialCase) (DifferentialObservation, bool) {
	for _, v := range c.Variants {
		if v.Kind == VariantBaseline {
			return v, true
		}
	}
	if len(c.Variants) > 0 {
		return c.Variants[0], true
	}
	return DifferentialObservation{}, false
}

// Analyze compares each non-baseline variant to the baseline and returns the
// classified anomalies (deterministic, noise-filtered). It performs no I/O.
func (p *DifferentialProducer) Analyze(c DifferentialCase) []DiffAnomaly {
	base, ok := baselineOf(c)
	if !ok {
		return nil
	}
	baseHdr := strings.Join(stableHeaderKeys(base.Headers), ",")
	baseShape := shape(base)
	var out []DiffAnomaly
	for _, v := range c.Variants {
		if v.Variant == base.Variant && v.Kind == base.Kind {
			continue // the baseline itself
		}
		statusDiff := v.Status != base.Status
		headerDiff := strings.Join(stableHeaderKeys(v.Headers), ",") != baseHdr
		bodyDiff := shape(v) != baseShape
		acceptDiff := v.Accepted != nil && base.Accepted != nil && *v.Accepted != *base.Accepted

		switch v.Kind {
		case VariantNormalization:
			// Must be equivalent to baseline; ANY difference is a normalization
			// discrepancy (the headline), regardless of which dimension moved.
			if statusDiff || headerDiff || bodyDiff || acceptDiff {
				out = append(out, DiffAnomaly{Type: AnomalyNormalization, Variant: v.Variant,
					Detail: diffDetail(base, v, statusDiff, headerDiff, bodyDiff, acceptDiff)})
			}
		case VariantBoundary:
			// A boundary probe: an accept/reject or status flip at the boundary.
			if acceptDiff || statusDiff {
				out = append(out, DiffAnomaly{Type: AnomalyBoundary, Variant: v.Variant,
					Detail: diffDetail(base, v, statusDiff, false, false, acceptDiff)})
			}
		default: // encoding / protocol / unspecified: expected equivalent -> report per dimension
			if statusDiff {
				out = append(out, DiffAnomaly{Type: AnomalyStatus, Variant: v.Variant, Detail: fmt.Sprintf("status %d vs baseline %d", v.Status, base.Status)})
			}
			if headerDiff {
				out = append(out, DiffAnomaly{Type: AnomalyHeader, Variant: v.Variant, Detail: "stable header set differs from baseline"})
			}
			if bodyDiff {
				out = append(out, DiffAnomaly{Type: AnomalyBodyShape, Variant: v.Variant, Detail: fmt.Sprintf("body shape %s vs baseline %s", shape(v), baseShape)})
			}
			if acceptDiff {
				out = append(out, DiffAnomaly{Type: AnomalyAcceptReject, Variant: v.Variant, Detail: "parser accept/reject differs from baseline"})
			}
		}
	}
	return out
}

func diffDetail(base, v DifferentialObservation, s, h, b, a bool) string {
	var d []string
	if s {
		d = append(d, fmt.Sprintf("status %d!=%d", v.Status, base.Status))
	}
	if h {
		d = append(d, "header-set")
	}
	if b {
		d = append(d, fmt.Sprintf("body-shape %s!=%s", shape(v), shape(base)))
	}
	if a {
		d = append(d, "accept/reject")
	}
	return strings.Join(d, ", ")
}

// Produce classifies a case and emits one hypothesis Candidate per anomaly TYPE
// (grouping the variants that exhibit it), tagged Origin{Kind:"differential"}. The
// candidate's Provenance.RawInputHash is the canonical serialized case hash — the
// producer's raw input artifact, computed over the stable (noise-filtered) view so
// it is independent of volatile header/timestamp churn.
func (p *DifferentialProducer) Produce(c DifferentialCase) []*Candidate {
	anomalies := p.Analyze(c)
	if len(anomalies) == 0 {
		return nil
	}
	caseHash := canonicalCaseHash(c)
	origin := Origin{Kind: OriginDifferential, ID: c.Target}
	prov := newProvenance(string(OriginDifferential), c.Target, "differential", caseHash)

	byType := map[string][]DiffAnomaly{}
	var order []string
	for _, a := range anomalies {
		if _, seen := byType[a.Type]; !seen {
			order = append(order, a.Type)
		}
		byType[a.Type] = append(byType[a.Type], a)
	}
	sort.Strings(order)

	var candidates []*Candidate
	for _, typ := range order {
		as := byType[typ]
		var variants, details []string
		for _, a := range as {
			variants = append(variants, a.Variant)
			details = append(details, a.Variant+": "+a.Detail)
		}
		title := fmt.Sprintf("%s on %q (%s)", typ, c.Intent, strings.Join(variants, ","))
		rationale := fmt.Sprintf("Differential on %s intent=%q: %s", c.Target, c.Intent, strings.Join(details, "; "))
		cand := NewHypothesis(p.newID(), typ, title, c.Target, rationale, origin, []string{"baseline_response", "variant_response"}, prov)
		cand.Refs = map[string]string{
			"intent":       c.Intent,
			"anomaly_type": typ,
			"variants":     strings.Join(variants, ","),
			"case_hash":    caseHash,
		}
		candidates = append(candidates, cand)
	}
	return candidates
}

// canonicalCaseHash serializes the case over its STABLE view (variant kind,
// status, stable header keys, body shape, accept flag) sorted by variant, so the
// hash is deterministic and independent of variant order and volatile-header
// churn. This is the producer's raw-input-artifact hash.
func canonicalCaseHash(c DifferentialCase) string {
	lines := []string{"target=" + c.Target, "intent=" + c.Intent}
	rows := make([]string, 0, len(c.Variants))
	for _, v := range c.Variants {
		acc := "?"
		if v.Accepted != nil {
			acc = strconv.FormatBool(*v.Accepted)
		}
		rows = append(rows, strings.Join([]string{
			"v=" + v.Variant, "kind=" + string(v.Kind),
			"status=" + strconv.Itoa(v.Status),
			"hdr=" + strings.Join(stableHeaderKeys(v.Headers), "."),
			"shape=" + shape(v), "accept=" + acc,
		}, "|"))
	}
	sort.Strings(rows)
	lines = append(lines, rows...)
	return RawInputHash([]byte(strings.Join(lines, "\n")))
}
