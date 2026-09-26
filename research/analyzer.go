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
		Task:    ai.TaskFindingAnalyst,
		Target:  ev.Target,
		Payload: payload,
	})
	if err != nil {
		return nil, nil, err
	}
	origin := Origin{Source: string(ai.TaskFindingAnalyst), AISuggested: true, Provider: a.provider.Name()}
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
		candidates = append(candidates, NewHypothesis(a.newID(), typ, title, ev.Target, p.Rationale, origin, p.RequiredEvidence))
	}
	return candidates, res, nil
}
