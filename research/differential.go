package research

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DifferentialProducer (S9 v1) turns a DifferentialCase — a set of responses to
// the SAME semantic request under different encodings/normalizations/boundaries/
// protocol variants — into hypothesis candidates when the responses disagree in a
// way that VIOLATES A DECLARED EXPECTATION. It is a deterministic PRODUCER, not a
// prober: it consumes already-collected variant responses (like the diff and
// fuzz producers consume diffs and crashes), compares them canonically, filters
// run-noise, and classifies anomalies against the case's own documented contract.
// It emits only hypotheses; a Validator reproduces safely and the Engine
// promotes.
//
// v1 is deliberately narrow: status / header / body-shape / accept-reject /
// normalization / boundary differences only. No attack-input generation. A case
// with no declared Expectation is recorded but never judged — zero-FP-first.
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

// DiffVariantKind labels what a variant is relative to the baseline. It is
// descriptive (used in titles/filtering which variants a boundary check applies
// to); the JUDGMENT rule is driven by the case's Expectation, not by this alone.
type DiffVariantKind string

const (
	VariantBaseline      DiffVariantKind = "baseline"
	VariantEncoding      DiffVariantKind = "encoding"
	VariantNormalization DiffVariantKind = "normalization"
	VariantBoundary      DiffVariantKind = "boundary"
	VariantProtocol      DiffVariantKind = "protocol"
)

// ExpectedRelation is the case's OWN documented contract for what its variants
// should do relative to the baseline. Without one, v1 refuses to judge at all —
// "the responses differ" is not itself an anomaly; "the responses differ in a way
// that violates what we declared should hold" is.
type ExpectedRelation string

const (
	// ExpectEquivalent: variants (e.g. alternate encodings/protocols) are expected
	// to behave identically to the baseline; any stable-dimension difference is an
	// anomaly, reported per dimension.
	ExpectEquivalent ExpectedRelation = "equivalent"
	// ExpectNormalizeEqual: normalization variants are expected to behave
	// identically to the baseline; any difference is a single normalization
	// anomaly.
	ExpectNormalizeEqual ExpectedRelation = "normalize_equal"
	// ExpectBoundaryMonotonic: boundary variants each carry their OWN declared
	// Expected accept/reject outcome (the documented contract, e.g. "size 1025 >
	// max 1024, so this must be rejected"); an anomaly is only a variant whose
	// OBSERVED outcome contradicts its OWN declared Expected — never a mere
	// difference from the baseline. Correct fail-closed behavior at a boundary is
	// therefore never flagged.
	ExpectBoundaryMonotonic ExpectedRelation = "boundary_monotonic"
)

// DifferentialObservation is one variant's observed response, plus (for a
// boundary variant) what SHOULD have happened per the documented contract.
type DifferentialObservation struct {
	Variant     string            `json:"variant"`
	Kind        DiffVariantKind   `json:"kind"`
	Request     RequestSummary    `json:"request,omitempty"`
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	BodyLen     int               `json:"body_len"`
	// Body is optional raw response body bytes, used ONLY to compute a structural
	// fingerprint (see BodyShape) — it is never retained on the resulting
	// Candidate or Evidence, matching "facts, not raw dumps".
	Body []byte `json:"-"`
	// Accepted is what actually happened (the parser/server accepted the request).
	Accepted *bool `json:"accepted,omitempty"`
	// Expected is what SHOULD have happened per the case's documented boundary
	// contract (collector-supplied, e.g. "over the declared limit, so reject").
	// Only meaningful for ExpectBoundaryMonotonic; nil means "no contract to judge
	// against", which never produces a false positive.
	Expected *bool `json:"expected,omitempty"`
}

// DifferentialCase groups variant responses to one semantic request under one
// documented Expectation. BaselineID names the Variant to compare against
// (falling back to Kind==baseline, then the first element, for convenience).
type DifferentialCase struct {
	ID          string                    `json:"id,omitempty"`
	Target      string                    `json:"target"`
	Intent      string                    `json:"intent"`
	BaselineID  string                    `json:"baseline_id,omitempty"`
	Expectation ExpectedRelation          `json:"expectation,omitempty"`
	Variants    []DifferentialObservation `json:"variants"`
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

// DiffAnomaly is a single classified disagreement between a variant and baseline
// (or, for boundary, between a variant's observed and declared-expected outcome).
type DiffAnomaly struct {
	Type    string
	Variant string
	Detail  string
}

// volatileHeaders are run-specific and excluded from comparison and hashing (they
// differ every response and would manufacture noise). Names are lowercased. These
// never participate in the identity/comparison hash, but they DO still appear in
// the lossless CaseArtifactHash (see caseArtifactHash).
var volatileHeaders = map[string]bool{
	"date": true, "set-cookie": true, "cookie": true, "etag": true, "age": true,
	"expires": true, "last-modified": true, "x-request-id": true, "x-correlation-id": true,
	"x-runtime": true, "x-gitlab-meta": true, "cf-ray": true, "server-timing": true,
	"content-length": true, "keep-alive": true, "connection": true, "vary": true,
}

// securityHeaderWhitelist names headers whose VALUE (not just presence) carries
// security-relevant meaning, so a key-set-only comparison would miss e.g.
// "WWW-Authenticate: Basic" -> "Bearer" or "Location: /login" -> "/admin". Kept
// small and stable on purpose — this is not a generic "diff all header values"
// escape hatch (that would reintroduce the noise the volatile-header list exists
// to prevent).
var securityHeaderWhitelist = map[string]bool{
	"www-authenticate":                 true,
	"location":                         true,
	"allow":                            true,
	"content-type":                     true,
	"access-control-allow-origin":      true,
	"access-control-allow-credentials": true,
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

func getHeaderCI(h map[string]string, lowerName string) string {
	for k, v := range h {
		if strings.ToLower(strings.TrimSpace(k)) == lowerName {
			return v
		}
	}
	return ""
}

// normalizeHeaderValue normalizes a whitelisted header's value for comparison.
// Location is reduced to scheme+host+path (or just path when relative), ignoring
// query/fragment, so an incidental query-string/nonce difference is not an
// anomaly; every other whitelisted header is compared trimmed but otherwise
// verbatim.
func normalizeHeaderValue(name, value string) string {
	value = strings.TrimSpace(value)
	if strings.ToLower(name) != "location" {
		return value
	}
	u, err := url.Parse(value)
	if err != nil {
		return value
	}
	if u.Scheme == "" && u.Host == "" {
		return u.Path
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// securityHeaderValuesKey renders the normalized values of every whitelisted
// header present, as a sorted "name=value,..." string — the comparison identity
// for the value-sensitive dimension.
func securityHeaderValuesKey(h map[string]string) string {
	var parts []string
	for name := range securityHeaderWhitelist {
		if v := getHeaderCI(h, name); v != "" {
			parts = append(parts, name+"="+normalizeHeaderValue(name, v))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// diffSecurityHeaderNames lists which whitelisted headers differ in value between
// base and v (for a readable anomaly Detail).
func diffSecurityHeaderNames(base, v map[string]string) []string {
	var names []string
	for name := range securityHeaderWhitelist {
		if normalizeHeaderValue(name, getHeaderCI(base, name)) != normalizeHeaderValue(name, getHeaderCI(v, name)) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
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

// BodyShape is the coarse-but-discriminating body class used for body
// comparison: normalized media type, a length bucket, and — for JSON bodies
// where the raw bytes were provided — a StructuralHash. StructuralHash is
// deterministic over KEY NAMES and VALUE KINDS only (never concrete values), so
// {"admin":false} and {"admin":true} share a shape (a value changed, not the
// structure) while {"admin":true} and {"error":"invalid"} do not (the keys
// differ) — catching the "same length bucket, different meaning" gap a coarse
// media-type+length comparison misses.
type BodyShape struct {
	MediaType      string
	LengthBucket   string
	StructuralHash string // JSON only in v1; "" when not JSON or not parseable
}

func (b BodyShape) key() string { return b.MediaType + "|" + b.LengthBucket + "|" + b.StructuralHash }

func bodyLenOf(o DifferentialObservation) int {
	if len(o.Body) > 0 {
		return len(o.Body)
	}
	return o.BodyLen
}

func computeBodyShape(o DifferentialObservation) BodyShape {
	bs := BodyShape{MediaType: normContentType(o.ContentType), LengthBucket: lenBucket(bodyLenOf(o))}
	if bs.MediaType == "application/json" && len(o.Body) > 0 {
		if h, ok := jsonStructuralHash(o.Body); ok {
			bs.StructuralHash = h
		}
	}
	return bs
}

const maxJSONStructureDepth = 8

// jsonStructuralHash parses body as JSON and hashes a canonical structural
// description: object keys (sorted) mapped to their value KIND (string/number/
// bool/null/array/object, recursively), never the concrete value. ok=false when
// the body does not parse as JSON.
func jsonStructuralHash(body []byte) (string, bool) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return "", false
	}
	var b strings.Builder
	writeJSONStructure(&b, v, 0)
	return RawInputHash([]byte(b.String())), true
}

func writeJSONStructure(b *strings.Builder, v any, depth int) {
	if depth > maxJSONStructureDepth {
		b.WriteString("...")
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(k)
			b.WriteString(":")
			writeJSONStructure(b, t[k], depth+1)
		}
		b.WriteString("}")
	case []any:
		b.WriteString("[")
		switch {
		case len(t) == 0:
			b.WriteString("empty")
		case jsonHomogeneous(t):
			writeJSONStructure(b, t[0], depth+1) // representative element structure
		default:
			b.WriteString("mixed")
		}
		b.WriteString("]")
	case string:
		b.WriteString("string")
	case float64:
		b.WriteString("number")
	case bool:
		b.WriteString("bool")
	case nil:
		b.WriteString("null")
	default:
		b.WriteString("unknown")
	}
}

func jsonHomogeneous(arr []any) bool {
	if len(arr) == 0 {
		return true
	}
	first := jsonLeafKind(arr[0])
	for _, e := range arr[1:] {
		if jsonLeafKind(e) != first {
			return false
		}
	}
	return true
}

func jsonLeafKind(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// baselineOf resolves the case's baseline: BaselineID by name, else the first
// Kind==baseline variant, else the first variant.
func baselineOf(c DifferentialCase) (DifferentialObservation, bool) {
	if c.BaselineID != "" {
		for _, v := range c.Variants {
			if v.Variant == c.BaselineID {
				return v, true
			}
		}
	}
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

// Analyze compares the case's variants and returns classified anomalies,
// deterministically and with no I/O. A case with no declared Expectation is
// NEVER judged — v1's zero-FP-first rule: "the responses differ" is recorded via
// the observations themselves, but only "differs in a way that violates the
// case's own documented contract" produces an anomaly.
func (p *DifferentialProducer) Analyze(c DifferentialCase) []DiffAnomaly {
	switch c.Expectation {
	case ExpectEquivalent, ExpectNormalizeEqual:
		base, ok := baselineOf(c)
		if !ok {
			return nil
		}
		return analyzeEquivalence(c, base)
	case ExpectBoundaryMonotonic:
		return analyzeBoundary(c)
	default:
		return nil
	}
}

// analyzeEquivalence handles ExpectEquivalent (per-dimension anomalies) and
// ExpectNormalizeEqual (a single combined normalization anomaly).
func analyzeEquivalence(c DifferentialCase, base DifferentialObservation) []DiffAnomaly {
	baseHdrKeys := strings.Join(stableHeaderKeys(base.Headers), ",")
	baseSecVals := securityHeaderValuesKey(base.Headers)
	baseShape := computeBodyShape(base)

	var out []DiffAnomaly
	for _, v := range c.Variants {
		if v.Variant == base.Variant {
			continue // the baseline itself
		}
		statusDiff := v.Status != base.Status
		hdrKeyDiff := strings.Join(stableHeaderKeys(v.Headers), ",") != baseHdrKeys
		secValDiff := securityHeaderValuesKey(v.Headers) != baseSecVals
		headerDiff := hdrKeyDiff || secValDiff
		vShape := computeBodyShape(v)
		bodyDiff := vShape.key() != baseShape.key()
		acceptDiff := v.Accepted != nil && base.Accepted != nil && *v.Accepted != *base.Accepted

		if c.Expectation == ExpectNormalizeEqual {
			if statusDiff || headerDiff || bodyDiff || acceptDiff {
				out = append(out, DiffAnomaly{Type: AnomalyNormalization, Variant: v.Variant,
					Detail: equivalenceDetail(statusDiff, headerDiff, bodyDiff, acceptDiff, base, v, baseShape, vShape)})
			}
			continue
		}
		// ExpectEquivalent: per-dimension, so a validator can act on exactly what moved.
		if statusDiff {
			out = append(out, DiffAnomaly{Type: AnomalyStatus, Variant: v.Variant, Detail: fmt.Sprintf("status %d vs baseline %d", v.Status, base.Status)})
		}
		if headerDiff {
			detail := "stable header key-set differs from baseline"
			if secValDiff {
				detail = fmt.Sprintf("security-relevant header value differs from baseline (%s)", strings.Join(diffSecurityHeaderNames(base.Headers, v.Headers), ","))
			}
			out = append(out, DiffAnomaly{Type: AnomalyHeader, Variant: v.Variant, Detail: detail})
		}
		if bodyDiff {
			out = append(out, DiffAnomaly{Type: AnomalyBodyShape, Variant: v.Variant, Detail: fmt.Sprintf("body shape %s vs baseline %s", vShape.key(), baseShape.key())})
		}
		if acceptDiff {
			out = append(out, DiffAnomaly{Type: AnomalyAcceptReject, Variant: v.Variant, Detail: "parser accept/reject differs from baseline"})
		}
	}
	return out
}

func equivalenceDetail(statusDiff, headerDiff, bodyDiff, acceptDiff bool, base, v DifferentialObservation, baseShape, vShape BodyShape) string {
	var d []string
	if statusDiff {
		d = append(d, fmt.Sprintf("status %d!=%d", v.Status, base.Status))
	}
	if headerDiff {
		d = append(d, "header")
	}
	if bodyDiff {
		d = append(d, fmt.Sprintf("body-shape %s!=%s", vShape.key(), baseShape.key()))
	}
	if acceptDiff {
		d = append(d, "accept/reject")
	}
	return strings.Join(d, ", ")
}

// analyzeBoundary judges ONLY against each boundary variant's OWN declared
// Expected outcome — never against the baseline. Correct fail-closed behavior
// (e.g. size-over-limit correctly rejected) matches its own declared Expected and
// is therefore never an anomaly; only a variant whose observed outcome
// contradicts its documented contract is flagged. A variant with no declared
// Expected (or no observed Accepted) is skipped — no contract to judge against
// means no judgment, never a guessed anomaly.
func analyzeBoundary(c DifferentialCase) []DiffAnomaly {
	var out []DiffAnomaly
	for _, v := range c.Variants {
		if v.Kind != VariantBoundary || v.Expected == nil || v.Accepted == nil {
			continue
		}
		if *v.Expected != *v.Accepted {
			out = append(out, DiffAnomaly{Type: AnomalyBoundary, Variant: v.Variant,
				Detail: fmt.Sprintf("expected accepted=%v but observed accepted=%v (status=%d)", *v.Expected, *v.Accepted, v.Status)})
		}
	}
	return out
}

// Produce classifies a case and emits one hypothesis Candidate per anomaly TYPE
// (grouping the variants that exhibit it), tagged Origin{Kind:"differential"}.
//
// Two distinct hashes, never mixed (same discipline as the fuzz producer):
//   - caseArtifactHash: a LOSSLESS canonical serialization of the case — every
//     variant in its given order, every header (including volatile ones), exact
//     status/body-length/content-type, no denoising. Map keys are sorted only
//     because Go maps have no defined iteration order (sorting does not drop
//     information); nothing else is normalized away. This IS the producer's raw
//     input artifact, and it is what Provenance.RawInputHash points at — so
//     RawInputHash keeps its frozen, cross-producer meaning: "hash of the raw
//     input the producer ingested, before any denoising".
//   - comparisonHash: the DENOISED, order-independent identity used to recognize
//     "is this the same differential finding" — volatile headers excluded, body
//     compared as a shape, variants sorted. This is recorded in Refs, never in
//     Provenance.RawInputHash.
func (p *DifferentialProducer) Produce(c DifferentialCase) []*Candidate {
	anomalies := p.Analyze(c)
	if len(anomalies) == 0 {
		return nil
	}
	artifactHash := caseArtifactHash(c)
	cmpHash := comparisonHash(c)
	origin := Origin{Kind: OriginDifferential, ID: c.Target}
	prov := newProvenance(string(OriginDifferential), c.Target, "differential", artifactHash)

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
		rationale := fmt.Sprintf("Differential on %s intent=%q expectation=%s: %s", c.Target, c.Intent, c.Expectation, strings.Join(details, "; "))
		cand := NewHypothesis(p.newID(), typ, title, c.Target, rationale, origin, []string{"baseline_response", "variant_response"}, prov)
		cand.Refs = map[string]string{
			"intent":             c.Intent,
			"anomaly_type":       typ,
			"variants":           strings.Join(variants, ","),
			"case_artifact_hash": artifactHash,
			"comparison_hash":    cmpHash,
		}
		candidates = append(candidates, cand)
	}
	return candidates
}

// caseArtifactHash is the LOSSLESS canonical serialization hash: every variant in
// its GIVEN order, every header (including volatile ones) with its exact value,
// exact status/body-length/content-type/accepted/expected. Header keys are
// sorted only because Go maps have no defined order — that sort does not discard
// information (a Date header value change still changes this hash).
func caseArtifactHash(c DifferentialCase) string {
	var b strings.Builder
	b.WriteString("id=" + c.ID + "\nintent=" + c.Intent + "\nbaseline_id=" + c.BaselineID + "\nexpectation=" + string(c.Expectation) + "\n")
	for i, v := range c.Variants {
		b.WriteString(fmt.Sprintf("variant[%d]=%s\n", i, losslessObservation(v)))
	}
	return RawInputHash([]byte(b.String()))
}

func losslessObservation(o DifferentialObservation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "variant=%s|kind=%s|method=%s|path=%s|status=%d|content_type=%s|body_len=%d",
		o.Variant, o.Kind, o.Request.Method, o.Request.Path, o.Status, o.ContentType, o.BodyLen)
	if len(o.Body) > 0 {
		b.WriteString("|body_sha256=" + RawInputHash(o.Body))
	}
	if o.Accepted != nil {
		b.WriteString("|accepted=" + strconv.FormatBool(*o.Accepted))
	}
	if o.Expected != nil {
		b.WriteString("|expected=" + strconv.FormatBool(*o.Expected))
	}
	keys := make([]string, 0, len(o.Headers))
	for k := range o.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys) // sorting keys is lossless: Go maps have no original order to preserve
	for _, k := range keys {
		b.WriteString("|hdr:" + k + "=" + o.Headers[k])
	}
	return b.String()
}

// comparisonHash is the DENOISED, order-independent identity hash used to
// recognize the same differential finding across runs: volatile headers
// excluded, whitelisted header VALUES included (they carry meaning),
// stable-header-key-set otherwise, body compared as a shape, variants sorted.
// This is recorded in Refs — never in Provenance.RawInputHash.
func comparisonHash(c DifferentialCase) string {
	lines := []string{"target=" + c.Target, "intent=" + c.Intent, "expectation=" + string(c.Expectation)}
	rows := make([]string, 0, len(c.Variants))
	for _, v := range c.Variants {
		acc, exp := "?", "?"
		if v.Accepted != nil {
			acc = strconv.FormatBool(*v.Accepted)
		}
		if v.Expected != nil {
			exp = strconv.FormatBool(*v.Expected)
		}
		rows = append(rows, strings.Join([]string{
			"kind=" + string(v.Kind),
			"status=" + strconv.Itoa(v.Status),
			"hdrkeys=" + strings.Join(stableHeaderKeys(v.Headers), "."),
			"secvals=" + securityHeaderValuesKey(v.Headers),
			"shape=" + computeBodyShape(v).key(),
			"accept=" + acc,
			"expected=" + exp,
		}, "|"))
	}
	sort.Strings(rows)
	lines = append(lines, rows...)
	return RawInputHash([]byte(strings.Join(lines, "\n")))
}
