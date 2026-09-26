package research

import (
	"context"
	"testing"

	"gopoc/internal/model"
)

func boolp(b bool) *bool { return &b }

// A stand-in authoritative source used across tests that need judgment to run at
// all; individual tests below prove what happens when it is absent or forged.
var testSource = ExpectationSource{Kind: ExpectationSourceDeterministicRule, ID: "test-rule"}

func TestNoExpectationNeverProducesCandidates(t *testing.T) {
	// v1's zero-FP-first rule: a case with no declared Expectation is recorded
	// (observations exist) but NEVER judged, however different the variants are —
	// even with an otherwise-authoritative source present.
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b", ExpectationSource: testSource,
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

// --- Authority boundary: Expectation/Expected must come from an authoritative
// ExpectationSource. AI (or any unverified producer) authoring "what should
// happen" would let it indirectly control what counts as an anomaly without ever
// touching Verdict/State — this is the bypass the whitelist closes. ---

func TestForbiddenExpectationSourcesRejected(t *testing.T) {
	// A genuine, obvious anomaly (status 500 vs 200) — the ONLY thing that
	// changes across sub-tests is who claims to have authored the Expectation.
	build := func(kind ExpectationSourceKind) DifferentialCase {
		return DifferentialCase{
			Target: "http://t", Intent: "GET /b", BaselineID: "baseline", Expectation: ExpectEquivalent,
			ExpectationSource: ExpectationSource{Kind: kind, ID: "whatever"},
			Variants: []DifferentialObservation{
				{Variant: "baseline", Kind: VariantBaseline, Status: 200},
				{Variant: "alt", Kind: VariantEncoding, Status: 500},
			},
		}
	}
	// Explicitly forbidden kinds, exactly as named in the audit: an AI proposal
	// (or any producer's free text) must never author what a protocol "should" do.
	for _, kind := range []ExpectationSourceKind{"ai", "llm", "proposal", "candidate_text", "fuzz", "diff", "differential", "not_a_real_kind"} {
		t.Run(string(kind), func(t *testing.T) {
			c := build(kind)
			if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
				t.Fatalf("ExpectationSource.Kind=%q must never be authoritative, got %+v", kind, cands)
			}
		})
	}
}

func TestEmptyExpectationSourceRejected(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b", BaselineID: "baseline", Expectation: ExpectEquivalent,
		// ExpectationSource left as the zero value — Kind="".
		Variants: []DifferentialObservation{
			{Variant: "baseline", Kind: VariantBaseline, Status: 200},
			{Variant: "alt", Kind: VariantEncoding, Status: 500},
		},
	}
	if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
		t.Fatalf("an empty ExpectationSource must never be authoritative, got %+v", cands)
	}
}

func TestAllAuthoritativeSourceKindsAccepted(t *testing.T) {
	// The positive complement: every kind actually on the whitelist works.
	for _, kind := range []ExpectationSourceKind{
		ExpectationSourceSpec, ExpectationSourceDeterministicRule, ExpectationSourceHumanConfig, ExpectationSourceDetectionFact,
	} {
		t.Run(string(kind), func(t *testing.T) {
			c := DifferentialCase{
				Target: "http://t", Intent: "GET /b", BaselineID: "baseline", Expectation: ExpectEquivalent,
				ExpectationSource: ExpectationSource{Kind: kind, ID: "ref"},
				Variants: []DifferentialObservation{
					{Variant: "baseline", Kind: VariantBaseline, Status: 200},
					{Variant: "alt", Kind: VariantEncoding, Status: 500},
				},
			}
			if cands := NewDifferentialProducer().Produce(c); len(cands) == 0 {
				t.Fatalf("authoritative kind %q must be accepted", kind)
			}
		})
	}
}

// --- Malformed-case guards: bad input must never manufacture a candidate. ---

func TestMalformedCaseGuards(t *testing.T) {
	cases := map[string]DifferentialCase{
		"fewer_than_2_variants": {
			Target: "http://t", Intent: "x", Expectation: ExpectEquivalent, ExpectationSource: testSource,
			Variants: []DifferentialObservation{{Variant: "baseline", Kind: VariantBaseline, Status: 200}},
		},
		"duplicate_variant_names": {
			Target: "http://t", Intent: "x", Expectation: ExpectEquivalent, ExpectationSource: testSource,
			Variants: []DifferentialObservation{
				{Variant: "a", Kind: VariantBaseline, Status: 200},
				{Variant: "a", Kind: VariantEncoding, Status: 500},
			},
		},
		"empty_variant_name": {
			Target: "http://t", Intent: "x", Expectation: ExpectEquivalent, ExpectationSource: testSource,
			Variants: []DifferentialObservation{
				{Variant: "baseline", Kind: VariantBaseline, Status: 200},
				{Variant: "", Kind: VariantEncoding, Status: 500},
			},
		},
		"baseline_id_does_not_exist": {
			Target: "http://t", Intent: "x", BaselineID: "no-such-variant", Expectation: ExpectEquivalent, ExpectationSource: testSource,
			Variants: []DifferentialObservation{
				{Variant: "a", Kind: VariantBaseline, Status: 200},
				{Variant: "b", Kind: VariantEncoding, Status: 500},
			},
		},
		"equivalent_case_carries_stray_expected": {
			Target: "http://t", Intent: "x", BaselineID: "baseline", Expectation: ExpectEquivalent, ExpectationSource: testSource,
			Variants: []DifferentialObservation{
				{Variant: "baseline", Kind: VariantBaseline, Status: 200},
				{Variant: "alt", Kind: VariantEncoding, Status: 500, Expected: boolp(true)}, // mixing contracts
			},
		},
		"boundary_with_no_comparable_variant": {
			Target: "http://t", Intent: "x", Expectation: ExpectBoundaryMonotonic, ExpectationSource: testSource,
			Variants: []DifferentialObservation{
				{Variant: "at_limit", Kind: VariantBoundary, Status: 200, Accepted: boolp(true)},    // no Expected
				{Variant: "over_limit", Kind: VariantBoundary, Status: 413, Accepted: boolp(false)}, // no Expected
			},
		},
		"unknown_expectation_value": {
			Target: "http://t", Intent: "x", Expectation: ExpectedRelation("not_a_real_relation"), ExpectationSource: testSource,
			Variants: []DifferentialObservation{
				{Variant: "a", Kind: VariantBaseline, Status: 200},
				{Variant: "b", Kind: VariantEncoding, Status: 500},
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.validate() {
				t.Fatalf("case should be invalid")
			}
			if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
				t.Fatalf("malformed case must never produce candidates, got %+v", cands)
			}
		})
	}
}

func TestDifferentialNormalizationAnomaly(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b", BaselineID: "baseline", Expectation: ExpectNormalizeEqual, ExpectationSource: testSource,
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
	if c0.Refs["expectation_source_kind"] != string(ExpectationSourceDeterministicRule) {
		t.Fatalf("expectation_source_kind ref missing/wrong: %+v", c0.Refs)
	}
}

func TestDifferentialDimensionAnomalies(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /x", BaselineID: "baseline", Expectation: ExpectEquivalent, ExpectationSource: testSource,
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

// --- boundary must judge against its OWN declared Expected, never merely
// against the baseline. Correct fail-closed behavior is never flagged. ---

func TestBoundaryCorrectFailClosedIsNotAnomaly(t *testing.T) {
	// max=1024: 1024 bytes accepted (expected true, observed true); 1025 bytes
	// rejected (expected false, observed false). This is CORRECT behavior.
	c := DifferentialCase{
		Target: "http://t", Intent: "len boundary", Expectation: ExpectBoundaryMonotonic,
		ExpectationSource: ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "max-upload-1024"},
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
		ExpectationSource: ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "max-upload-1024"},
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

func TestBoundaryVariantWithoutExpectedIsSkippedNotFlagged(t *testing.T) {
	// One comparable variant (so validate() passes) matches its own declared
	// Expected (no anomaly); a SECOND boundary variant with no declared Expected
	// must be skipped by the classifier, not guessed at.
	c := DifferentialCase{
		Target: "http://t", Intent: "len boundary", Expectation: ExpectBoundaryMonotonic,
		ExpectationSource: ExpectationSource{Kind: ExpectationSourceHumanConfig, ID: "max-upload-1024"},
		Variants: []DifferentialObservation{
			{Variant: "at_limit", Kind: VariantBoundary, Status: 200, Accepted: boolp(true), Expected: boolp(true)},
			{Variant: "undocumented", Kind: VariantBoundary, Status: 413, Accepted: boolp(false)}, // no Expected
		},
	}
	if cands := NewDifferentialProducer().Produce(c); len(cands) != 0 {
		t.Fatalf("a boundary variant with no declared Expected must never be flagged, got %+v", cands)
	}
}

// --- JSON structural comparison, not just length bucket. ---

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
		Target: "http://t", Intent: "GET /profile", BaselineID: "baseline", Expectation: ExpectEquivalent, ExpectationSource: testSource,
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

// --- security-relevant header VALUE comparison. ---

func TestSecurityHeaderValueDifferential(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /resource", BaselineID: "baseline", Expectation: ExpectEquivalent, ExpectationSource: testSource,
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
		Target: "http://t", Intent: "GET /r", BaselineID: "baseline", Expectation: ExpectEquivalent, ExpectationSource: testSource,
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
		Target: "http://t", Intent: "GET /x", BaselineID: "baseline", Expectation: ExpectEquivalent, ExpectationSource: testSource,
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

// --- RawInputHash (case_artifact_hash) is lossless; comparison_hash is the
// denoised, order-independent identity. They must never be conflated. ---

func TestCaseArtifactHashIsLosslessComparisonHashIsDenoised(t *testing.T) {
	mk := func(date string) DifferentialCase {
		return DifferentialCase{
			Target: "http://t", Intent: "GET /x", BaselineID: "baseline", Expectation: ExpectEquivalent, ExpectationSource: testSource,
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
		Target: "http://t", Intent: "GET /b", Expectation: ExpectNormalizeEqual, ExpectationSource: testSource,
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
