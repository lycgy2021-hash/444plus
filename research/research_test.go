package research

import (
	"context"
	"testing"

	"gopoc/internal/ai"
	"gopoc/internal/model"
)

func TestCandidateStateLadder(t *testing.T) {
	c := NewHypothesis("RC-2026-000001", "path_normalization", "double-encoded traversal", "http://t", "why", Origin{Kind: OriginAI, ID: "openai-compat:qwen"}, []string{"baseline_response"}, Provenance{ProducerKind: "human"})
	if c.State != Hypothesis {
		t.Fatalf("born at %s, want hypothesis", c.State)
	}

	// Legal one-rung advance by a named validator with evidence.
	if err := c.Promote(Reproducible, "path-normalization-validator", []string{"obs:baseline", "obs:normalized"}); err != nil {
		t.Fatalf("legal promote failed: %v", err)
	}
	if c.State != Reproducible || len(c.History) != 1 || c.History[0].By != "path-normalization-validator" {
		t.Fatalf("bad state/history: %s %+v", c.State, c.History)
	}

	// Skipping a rung is illegal.
	if err := c.Promote(VendorConfirmed, "v", []string{"e"}); err == nil {
		t.Fatal("rung-skip allowed")
	}
	// Backward is illegal.
	if err := c.Promote(Hypothesis, "v", []string{"e"}); err == nil {
		t.Fatal("backward allowed")
	}
	// No validator identity is illegal.
	if err := c.Promote(ImpactConfirmed, "", []string{"e"}); err == nil {
		t.Fatal("promote without validator allowed")
	}
	// No evidence is illegal.
	if err := c.Promote(ImpactConfirmed, "v", nil); err == nil {
		t.Fatal("promote without evidence allowed")
	}
	// State unchanged after the illegal attempts.
	if c.State != Reproducible {
		t.Fatalf("state moved on illegal attempts: %s", c.State)
	}
}

func TestFormatID(t *testing.T) {
	if got := FormatID(2026, 18); got != "RC-2026-000018" {
		t.Errorf("FormatID = %q", got)
	}
}

func TestFromModelEvidence(t *testing.T) {
	ev := model.Evidence{
		Version: "5.17.5",
		Observations: []model.Observation{
			{Kind: "fingerprint", URL: "http://t/", StatusCode: 200, SHA256: "abc", Bytes: 10},
			{Kind: "probe", URL: "http://t/x", Error: "connection refused"},
		},
	}
	r := FromModelEvidence("http://t", "detection", ev)
	if r.Target != "http://t" || r.Product.Version != "5.17.5" || len(r.Observations) != 2 {
		t.Fatalf("adapter output: %+v", r)
	}
	o0 := r.Observations[0]
	if o0.NetworkAction != ActionReadOnly || o0.Response.StatusCode != 200 || o0.Endpoint != "http://t/" {
		t.Fatalf("obs0: %+v", o0)
	}
	if len(o0.Artifacts) != 1 || o0.Artifacts[0].Ref != "abc" {
		t.Fatalf("artifact not derived from sha: %+v", o0.Artifacts)
	}
	if r.Observations[1].Error != "connection refused" {
		t.Fatalf("error not carried: %+v", r.Observations[1])
	}
}

// stubProvider returns a fixed AnalysisResult without touching the network.
type stubProvider struct{ res *ai.AnalysisResult }

func (s stubProvider) Name() string { return "stub" }
func (s stubProvider) Analyze(context.Context, ai.AnalysisRequest) (*ai.AnalysisResult, error) {
	return s.res, nil
}

func TestAnalyzerEmitsOnlyHypotheses(t *testing.T) {
	prov := stubProvider{res: &ai.AnalysisResult{
		Proposals: []ai.Proposal{
			{CandidateType: "path_normalization", Title: "double-encoded traversal", Hypothesis: "front/back normalize differently", EvidenceRequired: []string{"baseline_response", "normalized_response"}},
			{CandidateType: "", Title: "no type but has title"}, // type defaults to "unspecified"
			{CandidateType: "x", Title: ""},                     // no title -> skipped
		},
		MissingEvidence: []string{"alternate_encoding_response"},
	}}
	a := NewAnalyzer(prov).WithIDFunc(SequentialIDs(2026))
	cands, res, err := a.AnalyzeFinding(context.Background(), Evidence{Target: "http://t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 { // the titleless proposal is dropped
		t.Fatalf("got %d candidates, want 2", len(cands))
	}
	for _, c := range cands {
		if c.State != Hypothesis {
			t.Errorf("candidate %s born at %s, want hypothesis (AI is never authority)", c.ID, c.State)
		}
		if !c.Origin.IsAI() || c.Origin.ID != "stub" {
			t.Errorf("origin not marked AI-suggested: %+v", c.Origin)
		}
	}
	if cands[0].ID != "RC-2026-000001" || cands[1].Type != "unspecified" {
		t.Fatalf("ids/type: %s %q", cands[0].ID, cands[1].Type)
	}
	if len(res.MissingEvidence) != 1 {
		t.Fatalf("missing evidence lost: %+v", res.MissingEvidence)
	}
}

func TestAnalyzerEvidenceGaps(t *testing.T) {
	prov := stubProvider{res: &ai.AnalysisResult{MissingEvidence: []string{"response under boundary value", "response above boundary value"}}}
	gaps, err := NewAnalyzer(prov).EvidenceGaps(context.Background(), Evidence{Target: "http://t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 2 {
		t.Fatalf("gaps = %v", gaps)
	}
}

func TestAnalyzerDeduplicateFiltersUnknownIDs(t *testing.T) {
	prov := stubProvider{res: &ai.AnalysisResult{Duplicates: [][]string{
		{"RC-2026-000001", "RC-2026-000002"}, // both real -> kept
		{"RC-2026-000001", "RC-9999-999999"}, // one invented id -> collapses to 1 -> dropped
		{"RC-9999-000000"},                   // all invented -> dropped
	}}}
	cands := []*Candidate{
		NewHypothesis("RC-2026-000001", "t", "a", "", "", Origin{Kind: OriginAI, ID: "stub"}, nil, Provenance{ProducerKind: "human"}),
		NewHypothesis("RC-2026-000002", "t", "b", "", "", Origin{Kind: OriginAI, ID: "stub"}, nil, Provenance{ProducerKind: "human"}),
	}
	groups, err := NewAnalyzer(prov).Deduplicate(context.Background(), cands)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("dedup must keep only groups of >=2 known ids, got %v (a model cannot invent ids)", groups)
	}
}
