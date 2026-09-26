package research

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"gopoc/internal/ai"
)

// Analyzer runs an ai.Provider over research Evidence and converts what it says
// into Candidates. It is the concrete place the authority boundary lives: every
// candidate it emits is born at Hypothesis via NewHypothesis, tagged with its AI
// origin. Nothing the model returns — however confident, however it phrases it —
// can leave this function as anything higher than a hypothesis.
type Analyzer struct {
	provider ai.Provider
	// newID mints candidate ids; injectable for deterministic tests. Defaults to
	// sequential RC-<year>-NNNNNN ids.
	newID func() string
}

// NewAnalyzer builds an Analyzer with a default sequential id generator anchored
// on the current year.
func NewAnalyzer(provider ai.Provider) *Analyzer {
	return &Analyzer{provider: provider, newID: SequentialIDs(time.Now().UTC().Year())}
}

// WithIDFunc overrides the id generator (used in tests for stable ids).
func (a *Analyzer) WithIDFunc(fn func() string) *Analyzer {
	a.newID = fn
	return a
}

// SequentialIDs returns an id generator producing RC-<year>-000001, -000002, ….
func SequentialIDs(year int) func() string {
	var n int
	return func() string {
		n++
		return FormatID(year, n)
	}
}

// AnalyzeFinding asks the provider to analyze the given detection evidence and
// returns the resulting hypothesis candidates plus the raw AnalysisResult (for
// its missing-evidence notes). The candidates are always at Hypothesis; a
// deterministic validator must Promote them from there.
func (a *Analyzer) AnalyzeFinding(ctx context.Context, ev Evidence) ([]*Candidate, *ai.AnalysisResult, error) {
	payload, err := json.Marshal(ev)
	if err != nil {
		return nil, nil, err
	}
	res, err := a.provider.Analyze(ctx, ai.AnalysisRequest{
		Task:    ai.TaskFindingAnalysis,
		Target:  ev.Target,
		Payload: payload,
	})
	if err != nil {
		return nil, nil, err
	}
	origin := Origin{Kind: OriginAI, ID: a.provider.Name()}
	// Provenance ties every produced candidate to the exact evidence the model saw.
	prov := newProvenance(string(OriginAI), a.provider.Name(), a.provider.Name(), RawInputHash(payload))
	var candidates []*Candidate
	for _, p := range res.Proposals {
		typ := strings.TrimSpace(p.CandidateType)
		if typ == "" {
			typ = "unspecified"
		}
		title := strings.TrimSpace(p.Title)
		if title == "" {
			continue // a proposal with no title is not actionable
		}
		candidates = append(candidates, NewHypothesis(a.newID(), typ, title, ev.Target, p.Hypothesis, origin, p.EvidenceRequired, prov))
	}
	return candidates, res, nil
}

// EvidenceGaps (TaskEvidenceGap) asks the provider only what evidence is missing
// to reach a conclusion. It proposes nothing — a pure gap list.
func (a *Analyzer) EvidenceGaps(ctx context.Context, ev Evidence) ([]string, error) {
	payload, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	res, err := a.provider.Analyze(ctx, ai.AnalysisRequest{Task: ai.TaskEvidenceGap, Target: ev.Target, Payload: payload})
	if err != nil {
		return nil, err
	}
	return res.MissingEvidence, nil
}

// Deduplicate (TaskCandidateDedup) asks the provider which candidates describe the
// same underlying issue. It returns the model's suggested groups of candidate ids
// WITHOUT merging anything — grouping is advisory; the caller decides. Groups are
// filtered to ids that were actually in the input, so the model cannot invent ids.
func (a *Analyzer) Deduplicate(ctx context.Context, candidates []*Candidate) ([][]string, error) {
	known := make(map[string]bool, len(candidates))
	view := make([]map[string]string, 0, len(candidates))
	for _, c := range candidates {
		known[c.ID] = true
		view = append(view, map[string]string{"id": c.ID, "candidate_type": c.Type, "title": c.Title})
	}
	payload, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	res, err := a.provider.Analyze(ctx, ai.AnalysisRequest{Task: ai.TaskCandidateDedup, Payload: payload})
	if err != nil {
		return nil, err
	}
	var groups [][]string
	for _, g := range res.Duplicates {
		var filtered []string
		for _, id := range g {
			if known[id] {
				filtered = append(filtered, id)
			}
		}
		if len(filtered) >= 2 { // a group needs at least two real members
			groups = append(groups, filtered)
		}
	}
	return groups, nil
}
