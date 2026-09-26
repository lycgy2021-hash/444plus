package ai

import "encoding/json"

// Task names the kind of analysis requested. S4 supports exactly three narrow
// tasks — no "omni-analysis". Each keeps the model to describing and grouping;
// none asks it to decide, attack, or rate severity.
type Task string

const (
	// TaskFindingAnalysis analyzes existing detection evidence and proposes
	// hypotheses worth a deterministic look.
	TaskFindingAnalysis Task = "finding_analysis"
	// TaskEvidenceGap names the evidence absent from the input that would be
	// needed to decide — it proposes nothing, it only lists gaps.
	TaskEvidenceGap Task = "evidence_gap_analysis"
	// TaskCandidateDedup groups candidates the model believes are the same
	// underlying issue. Advisory only: the caller decides whether to merge.
	TaskCandidateDedup Task = "candidate_deduplication"
)

func (t Task) valid() bool {
	switch t {
	case TaskFindingAnalysis, TaskEvidenceGap, TaskCandidateDedup:
		return true
	}
	return false
}

// AnalysisRequest is the input to Provider.Analyze. The material is passed as
// opaque JSON so this package need not import the research or detection planes —
// keeping the gateway free of any verdict vocabulary and free of import cycles.
type AnalysisRequest struct {
	Task Task `json:"task"`
	// Target is a label for the subject (a URL, a package name). Context for the
	// prompt, never something the model is asked to attack.
	Target string `json:"target,omitempty"`
	// Payload is the task-specific material the model reasons over: marshaled
	// research.Evidence, or a list of candidates for deduplication.
	Payload json.RawMessage `json:"payload,omitempty"`
	// Instruction is an optional human-authored steer; it cannot widen the schema.
	Instruction string `json:"instruction,omitempty"`
}

// Proposal is a single hypothesis the model puts forward. It is descriptive only:
// no severity, no confidence, no verdict, no state. It names what to look at and
// what evidence a validator would need — a deterministic validator decides the
// rest.
type Proposal struct {
	// CandidateType routes to a registered validator via Validator.Supports; an
	// unknown type simply matches nothing and the candidate stays a hypothesis.
	CandidateType string `json:"candidate_type,omitempty"`
	Title         string `json:"title"`
	Hypothesis    string `json:"hypothesis,omitempty"`
	// EvidenceRequired is what a validator must collect to test the hypothesis.
	EvidenceRequired []string `json:"evidence_required,omitempty"`
	// RelatedObservations references observation ids from the input evidence.
	RelatedObservations []string `json:"related_observations,omitempty"`
}

// AnalysisResult is everything a Provider may return. By construction it can only
// describe and group: no Verdict, State, Confirmed, Severity, or Confidence
// field, so a model — however prompted or however it misbehaves — cannot express
// a decision or a severity through this type. Unknown fields in a model's JSON
// reply are dropped on unmarshal, so a reply inventing "verdict":"confirmed" or
// "severity":"critical" is silently discarded.
type AnalysisResult struct {
	Proposals       []Proposal `json:"proposals,omitempty"`
	MissingEvidence []string   `json:"missing_evidence,omitempty"`
	// Duplicates are groups of candidate ids the model believes are the same
	// issue (TaskCandidateDedup). Advisory; nothing is merged automatically.
	Duplicates [][]string `json:"duplicate_groups,omitempty"`
	Notes      string     `json:"notes,omitempty"`
	// Usage is filled by the Provider from the backend's token accounting; it is
	// not part of the model's own reply.
	Usage Usage `json:"-"`
}

// resultSchemaHint is embedded in the prompt so the model returns the exact shape
// AnalysisResult unmarshals. It offers no verdict/state/severity/confidence key.
const resultSchemaHint = `{
  "proposals": [
    {
      "candidate_type": "short_snake_case_kind",
      "title": "one line",
      "hypothesis": "what might be true and why it is worth validating",
      "evidence_required": ["what a deterministic validator must collect to test it"],
      "related_observations": ["observation ids from the input this refers to"]
    }
  ],
  "missing_evidence": ["evidence absent from the input that would change the analysis"],
  "duplicate_groups": [["candidate-id-a", "candidate-id-b"]],
  "notes": "optional short free text"
}`
