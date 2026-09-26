package research

import (
	"context"
	"testing"

	"gopoc/internal/model"
)

func boolp(b bool) *bool { return &b }

func TestDifferentialNormalizationAnomaly(t *testing.T) {
	// A normalization variant ("/a/../b" ~ "/b") that returns a DIFFERENT status
	// than the baseline is a normalization discrepancy.
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b",
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
	if c0.Provenance().RawInputHash != c0.Refs["case_hash"] || c0.Provenance().ProducerKind != "differential" {
		t.Fatalf("provenance must be the canonical case hash: %+v / refs=%v", c0.Provenance(), c0.Refs)
	}
}

func TestDifferentialDimensionAnomalies(t *testing.T) {
	// An encoding variant (expected equivalent) that differs in body shape AND
	// status yields two dimension anomalies.
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /x",
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

func TestDifferentialBoundaryAndAcceptReject(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "len boundary",
		Variants: []DifferentialObservation{
			{Variant: "at_limit", Kind: VariantBaseline, Status: 200, Accepted: boolp(true)},
			{Variant: "over_limit", Kind: VariantBoundary, Status: 400, Accepted: boolp(false)},
		},
	}
	cands := NewDifferentialProducer().Produce(c)
	if len(cands) != 1 || cands[0].Type != AnomalyBoundary {
		t.Fatalf("expected one boundary_differential, got %+v", cands)
	}
}

func TestDifferentialNoiseFiltering(t *testing.T) {
	// Two variants identical except volatile headers (Date, Set-Cookie,
	// X-Request-Id) and a tiny length jitter within one bucket: NO anomaly.
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /x",
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

func TestDifferentialCaseHashStableAndNoiseIndependent(t *testing.T) {
	mk := func(date, reqid string) DifferentialCase {
		return DifferentialCase{
			Target: "http://t", Intent: "GET /x",
			Variants: []DifferentialObservation{
				{Variant: "baseline", Kind: VariantBaseline, Status: 200, ContentType: "text/html", BodyLen: 100,
					Headers: map[string]string{"Date": date, "X-Request-Id": reqid, "Server": "nginx"}},
				{Variant: "enc", Kind: VariantEncoding, Status: 200, ContentType: "text/html", BodyLen: 100,
					Headers: map[string]string{"Date": date, "X-Request-Id": reqid, "Server": "nginx"}},
			},
		}
	}
	h1 := canonicalCaseHash(mk("Mon", "aaa"))
	h2 := canonicalCaseHash(mk("Tue", "zzz"))
	if h1 != h2 {
		t.Fatal("case hash must be independent of volatile headers")
	}
	// Variant order independence.
	c := mk("Mon", "aaa")
	c.Variants[0], c.Variants[1] = c.Variants[1], c.Variants[0]
	if canonicalCaseHash(c) != h1 {
		t.Fatal("case hash must be independent of variant order")
	}
}

func TestDifferentialCandidateFlowsThroughSpine(t *testing.T) {
	c := DifferentialCase{
		Target: "http://t", Intent: "GET /b",
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
