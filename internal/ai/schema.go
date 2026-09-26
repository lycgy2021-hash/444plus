package ai

import "encoding/json"

// Task names the kind of analysis requested. Each keeps the model in a narrow
// lane — analyze, compare, audit, triage — and none of them asks the model to
// decide anything: the model proposes and names gaps, a validator decides.
type Task string

const (
	// TaskFindingAnalyst analyzes existing evidence and points out what evidence
	// is missing to reach a conclusion (P0).
	TaskFindingAnalyst Task = "finding_analyst"
	// TaskDiffAnalyst analyzes a version/patch diff for security-relevant change
	// (P0).
	TaskDiffAnalyst Task = "diff_analyst"
	// TaskSourceAuditor reasons about source→sink / bounds / state machines (P1).
	TaskSourceAuditor Task = "source_auditor"
	// TaskCrashTriage clusters and ranks fuzz crashes by suspiciousness (P1).
	TaskCrashTriage Task = "crash_triage"
)

func (t Task) valid() bool {
	switch t {
	case TaskFindingAnalyst, TaskDiffAnalyst, TaskSourceAuditor, TaskCrashTriage:
		return true
	}
	return false
}

// AnalysisRequest is the input to Provider.Analyze. The evidence/context is
// passed as opaque JSON (marshaled research.Evidence, a diff, a source excerpt)
// so this package need not import the research or detection planes — keeping the
// gateway free of any verdict vocabulary and free of import cycles.
type AnalysisRequest struct {
	Task Task `json:"task"`
	// Target is a label for the subject (a URL, a package name, a file path). It
	// is context for the prompt, not something the model is asked to attack.
	Target string `json:"target,omitempty"`
	// Payload is the task-specific material the model reasons over: marshaled
	// research.Evidence for a finding analysis, a unified diff for a diff
	// analysis, a source excerpt for an audit. Never raw target bytes to attack.
	Payload json.RawMessage `json:"payload,omitempty"`
	// Instruction is an optional extra, human-authored steer appended to the
	// task's built-in prompt. It cannot widen the output schema.
	Instruction string `json:"instruction,omitempty"`
}

// Proposal is a single hypothesis the model puts forward. It is explicitly NOT a
// finding: it has no verdict, no confidence-as-truth, no state. Confidence is the
// model's own advisory self-rating and carries no authority.
type Proposal struct {
	CandidateType    string   `json:"candidate_type"`
	Title            string   `json:"title"`
	Rationale        string   `json:"rationale,omitempty"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	Confidence       float64  `json:"confidence,omitempty"`
}

// AnalysisResult is everything a Provider may return. By construction it can only
// propose and point at gaps: there is no Verdict, State, Confirmed, or Severity
// field, so a model — however it is prompted or however it misbehaves — cannot
// express a decision through this type. Unknown fields in a model's JSON reply
// are dropped on unmarshal, so a reply that invents `"verdict":"confirmed"` is
// silently discarded here.
type AnalysisResult struct {
	Proposals       []Proposal `json:"proposals"`
	MissingEvidence []string   `json:"missing_evidence,omitempty"`
	Notes           string     `json:"notes,omitempty"`
	// Usage is filled by the Provider from the backend's token accounting; it is
	// not part of the model's own reply.
	Usage Usage `json:"-"`
}

// resultSchemaHint is embedded in the prompt so the model returns the exact
// shape AnalysisResult unmarshals. It intentionally offers no verdict/state key.
const resultSchemaHint = `{
  "proposals": [
    {
      "candidate_type": "short_snake_case_kind",
      "title": "one line",
      "rationale": "why this is worth validating",
      "required_evidence": ["what a deterministic validator must collect to test it"],
      "confidence": 0.0
    }
  ],
  "missing_evidence": ["evidence absent from the input that would change the analysis"],
  "notes": "optional short free text"
}`
