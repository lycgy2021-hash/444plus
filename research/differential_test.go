package research

import (
	"context"
	"testing"

	"gopoc/internal/model"
)

func boolp(b bool) *bool { return &b }

func TestNoExpectationNeverProducesCandidates(t *testing.T) {
	// v1's zero-FP-first rule: a case with no declared Expectation is recorded
	// (observations exist) but NEVER judged, however different the variants are.
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b",
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 200, ContentType: "text/html", BodyLen: 500},
			{Variant: "weird", Kind: VariantNormalization, Status: 500, ContentType: "application/json", BodyLen: 9000},
		},
	}
	if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
		t.Fatalf("case with no Expectation must never produce candidates, got %+v", cands)
	}
	if anomalies := NewDifferentialProducer().Analyze(c); len(anomalies) != 0 {
		t.Fatalf("Analyze must return nil with no Expectation, got %+v", anomalies)
	}
}

func TestDifferentialNormalizationAnomaly(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b", BaselineID: "baseline", Expectation: ExpectNormalizeEqual,
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 200, ContentType: "text/html", BodyLen: 500},
			{Variant: "dotdot", Kind: VariantNormalization, Status: 403, ContentType: "text/html", BodyLen: 90},
		},
	}
	cands := NewDifferentialProducer().WithIDFunc(SequentialIDs(2026)).Produce(c)
	if len(cands) != 1 || cands[0].Type != AnomalyNormalization {
		t.Fatalf("expected one normalization_differential, got %+v", cands)
	}
	c0 := cands[0]
	if c0.State != Hypothesis || c0.Origin.Kind != OriginDifferential {
		t.Fatalf("bad candidate: state=%s origin=%+v", c0.State, c0.Origin)
	}
	// Provenance must be the LOSSLESS artifact hash, and must NOT equal the
	// denoised comparison hash (the two are never interchangeable).
	if c0.Provenance().RawInputHash != c0.Refs["case_artifact_hash"] {
		t.Fatalf("RawInputHash must equal case_artifact_hash: %+v vs refs=%v", c0.Provenance(), c0.Refs)
	}
	if c0.Provenance().RawInputHash == c0.Refs["comparison_hash"] {
		t.Fatal("RawInputHash (lossless artifact) must not equal comparison_hash (denoised identity)")
	}
	if c0.Provenance().ProducerKind != "differential" {
		t.Fatalf("provenance producer kind = %q", c0.Provenance().ProducerKind)
	}
}

func TestDifferentialDimensionAnomalies(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /x", BaselineID: "baseline", Expectation: ExpectEquivalent,
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 200, ContentType: "application/json", BodyLen: 50},
			{Variant: "url_encoded", Kind: VariantEncoding, Status: 500, ContentType: "text/html", BodyLen: 9000},
		},
	}
	cands := NewDifferentialProducer().Produce(c)
	types := map[string]bool{}
	for _, x := range cands {
		types[x.Type] = true
	}
	if !types[AnomalyStatus] || !types[AnomalyBodyShape] {
		t.Fatalf("expected status + body-shape anomalies, got %v", types)
	}
}

// --- Blocker 2: boundary must judge against its OWN declared Expected, never
// merely against the baseline. Correct fail-closed behavior is never flagged. ---

func TestBoundaryCorrectFailClosedIsNotAnomaly(t *testing.T) {
	// max=1024: 1024 bytes accepted (expected true, observed true); 1025 bytes
	// rejected (expected false, observed false). This is CORRECT behavior.
	c := DifferentialCase{
		Target: "http://t", Intent: "len boundary", Expectation: ExpectBoundaryMonotonic,
		Variants: []DifferentialObservation{
			{Variant: "at_limit", Kind: VariantBoundary, Status: 200, Accepted: boolp(true), Expected: boolp(true)},
			{Variant: "over_limit", Kind: VariantBoundary, Status: 413, Accepted: boolp(false), Expected: boolp(false)},
		},
	}
	if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
		t.Fatalf("correct fail-closed boundary behavior must NOT be flagged as an anomaly, got %+v", cands)
	}
}

func TestBoundaryViolationIsAnomaly(t *testing.T) {
	// over_limit is accepted when it should have been rejected: a real anomaly.
	c := DifferentialCase{
		Target: "http://t", Intent: "len boundary", Expectation: ExpectBoundaryMonotonic,
		Variants: []DifferentialObservation{
			{Variant: "at_limit", Kind: VariantBoundary, Status: 200, Accepted: boolp(true), Expected: boolp(true)},
			{Variant: "over_limit", Kind: VariantBoundary, Status: 200, Accepted: boolp(true), Expected: boolp(false)},
		},
	}
	cands := NewDifferentialProducer().Produce(c)
	if len(cands) != 1 || cands[0].Type != AnomalyBoundary {
		t.Fatalf("expected one boundary_differential, got %+v", cands)
	}
}

func TestBoundaryWithoutDeclaredExpectationNeverFlags(t *testing.T) {
	// A boundary variant with no Expected field: no contract to judge against, so
	// even though status/accept differ from the "baseline" there is no anomaly.
	c := DifferentialCase{
		Target: "http://t", Intent: "len boundary", Expectation: ExpectBoundaryMonotonic,
		Variants: []DifferentialObservation{
			{Variant: "at_limit", Kind: VariantBoundary, Status: 200, Accepted: boolp(true)},
			{Variant: "over_limit", Kind: VariantBoundary, Status: 413, Accepted: boolp(false)}, // no Expected
		},
	}
	if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
		t.Fatalf("boundary variant with no declared Expected must never be flagged, got %+v", cands)
	}
}

// --- Blocker/recommendation 3: JSON structural comparison, not just length bucket. ---

func TestJSONStructuralHashIgnoresValuesKeepsKeys(t *testing.T) {
	same1 := computeBodyShape(DifferentialObservation{ContentType: "application/json", Body: []byte(`{"admin":false}`)})
	same2 := computeBodyShape(DifferentialObservation{ContentType: "application/json", Body: []byte(`{"admin":true}`)})
	if same1.key() != same2.key() {
		t.Fatalf("value-only change must share a structural shape: %+v vs %+v", same1, same2)
	}
	diff := computeBodyShape(DifferentialObservation{ContentType: "application/json", Body: []byte(`{"error":"invalid credentials"}`)})
	if same1.key() == diff.key() {
		t.Fatal("different key set must NOT share a structural shape")
	}
}

func TestDifferentialBodyStructuralAnomaly(t *testing.T) {
	// Same content-type and length bucket, but genuinely different JSON structure
	// (login-failure vs success-with-profile) — the coarse media+length check
	// alone would miss this; the structural hash must catch it.
	body1 := []byte(`{"error":"invalid_credentials"}`)
	body2 := []byte(`{"id":1234,"name":"bob"}`) // deliberately similar length
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /profile", BaselineID: "baseline", Expectation: ExpectEquivalent,
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 200, ContentType: "application/json", Body: body1, BodyLen: len(body1)},
			{Variant: "alt_encoding", Kind: VariantEncoding, Status: 200, ContentType: "application/json", Body: body2, BodyLen: len(body2)},
		},
	}
	cands := NewDifferentialProducer().Produce(c)
	found := false
	for _, x := range cands {
		if x.Type == AnomalyBodyShape {
			found = true
		}
	}
	if !found {
		t.Fatalf("structurally different JSON bodies in the same length bucket must be flagged, got %+v", cands)
	}
}

// --- Blocker/recommendation 4: security-relevant header VALUE comparison. ---

func TestSecurityHeaderValueDifferential(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /resource", BaselineID: "baseline", Expectation: ExpectEquivalent,
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 401,
				Headers: map[string]string{"WWW-Authenticate": "Basic", "Date": "Mon"}},
			{Variant: "alt", Kind: VariantEncoding, Status: 401,
				Headers: map[string]string{"WWW-Authenticate": "Bearer", "Date": "Tue"}},
		},
	}
	cands := NewDifferentialProducer().Produce(c)
	found := false
	for _, x := range cands {
		if x.Type == AnomalyHeader {
			found = true
		}
	}
	if !found {
		t.Fatalf("a WWW-Authenticate scheme change must be flagged despite an identical key-set, got %+v", cands)
	}
}

func TestLocationValueDifferentialIgnoresQuery(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /r", BaselineID: "baseline", Expectation: ExpectEquivalent,
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 302, Headers: map[string]string{"Location": "/login?x=1"}},
			{Variant: "same_path_diff_query", Kind: VariantEncoding, Status: 302, Headers: map[string]string{"Location": "/login?x=2"}},
			{Variant: "different_path", Kind: VariantProtocol, Status: 302, Headers: map[string]string{"Location": "/admin"}},
		},
	}
	anomalies := NewDifferentialProducer().Analyze(c)
	hasDiffPath, hasSameQuery := false, false
	for _, a := range anomalies {
		if a.Type != AnomalyHeader {
			continue
		}
		switch a.Variant {
		case "different_path":
			hasDiffPath = true
		case "same_path_diff_query":
			hasSameQuery = true
		}
	}
	if !hasDiffPath {
		t.Fatalf("Location pointing at a different path must be flagged: %+v", anomalies)
	}
	if hasSameQuery {
		t.Fatalf("Location differing only in query must NOT be flagged: %+v", anomalies)
	}
}

func TestDifferentialNoiseFiltering(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /x", BaselineID: "baseline", Expectation: ExpectEquivalent,
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 200, ContentType: "text/html; charset=utf-8", BodyLen: 500,
				Headers: map[string]string{"Date": "Mon", "X-Request-Id": "aaa", "Set-Cookie": "s=1", "Content-Type": "text/html"}},
			{Variant: "encoded", Kind: VariantEncoding, Status: 200, ContentType: "text/html; charset=utf-8", BodyLen: 512,
				Headers: map[string]string{"Date": "Tue", "X-Request-Id": "bbb", "Set-Cookie": "s=2", "Content-Type": "text/html"}},
		},
	}
	if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
		t.Fatalf("volatile-header/jitter-only difference must not produce anomalies, got %+v", cands)
	}
}

// --- Blocker 1: RawInputHash (case_artifact_hash) is lossless; comparison_hash
// is the denoised, order-independent identity. They must never be conflated. ---

func TestCaseArtifactHashIsLosslessComparisonHashIsDenoised(t *testing.T) {
	mk := func(date string) DifferentialCase {
		return DifferentialCase{
			Target: "http://t", Intent: "GET /x", BaselineID: "baseline", Expectation: ExpectEquivalent,
			Variants: []DifferentialObservation{
				{Variant: "baseline", Kind: VariantBaseline, Status: 200, ContentType: "text/html", BodyLen: 100,
					Headers: map[string]string{"Date": date, "Server": "nginx"}},
				{Variant: "enc", Kind: VariantEncoding, Status: 200, ContentType: "text/html", BodyLen: 100,
					Headers: map[string]string{"Date": date, "Server": "nginx"}},
			},
		}
	}
	a1, a2 := caseArtifactHash(mk("Mon")), caseArtifactHash(mk("Tue"))
	if a1 == a2 {
		t.Fatal("caseArtifactHash MUST change when a volatile header (Date) changes — it is lossless, not denoised")
	}
	c1, c2 := comparisonHash(mk("Mon")), comparisonHash(mk("Tue"))
	if c1 != c2 {
		t.Fatal("comparisonHash must be independent of volatile headers")
	}
	// Variant order independence: comparisonHash unaffected; artifact hash (order
	// is part of the literal artifact) is allowed to differ.
	c := mk("Mon")
	c.Variants[0], c.Variants[1] = c.Variants[1], c.Variants[0]
	if comparisonHash(c) != c1 {
		t.Fatal("comparisonHash must be independent of variant order")
	}
}

func TestDifferentialCandidateFlowsThroughSpine(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b", Expectation: ExpectNormalizeEqual,
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 200, BodyLen: 10},
			{Variant: "dotdot", Kind: VariantNormalization, Status: 403, BodyLen: 90},
		},
	}
	cands := NewDifferentialProducer().Produce(c)
	if len(cands) == 0 {
		t.Fatal("expected a candidate")
	}
	e := NewEngine(NewRegistry(NewHTTPDifferentialValidator(nil))) // type won't match
	results, err := e.Validate(context.Background(), model.Target{}, cands[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 || cands[0].State != Hypothesis {
		t.Fatalf("differential candidate must stay hypothesis with no matching validator; state=%s", cands[0].State)
	}
}
