package ai

import "strings"

// Message is one chat turn, matching the OpenAI chat schema every supported
// backend speaks.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// systemPreamble is the standing instruction prepended to every task. It nails
// the authority boundary in the prompt itself (belt to the schema's braces): the
// model proposes and names gaps, and a separate deterministic validator decides.
// A model that ignores this and asserts a verdict still cannot express one — the
// result schema has no field for it — so this is guidance, not the guarantee.
const systemPreamble = `You are a security-research analysis assistant operating inside a larger system.

Rules you MUST follow:
- You do NOT decide whether anything is vulnerable. A separate deterministic validator does that by collecting evidence.
- You only (a) propose hypotheses worth validating and (b) name evidence that is missing.
- You MUST NOT claim anything is "confirmed", "exploitable", "vulnerable", or assign a severity or verdict. Such claims are ignored.
- Never invent facts not present in the input. If the input is insufficient, say so in missing_evidence.
- Output ONLY a single JSON object matching this schema, with no prose before or after:
` + resultSchemaHint

// taskInstruction is the per-task framing appended after the preamble.
func taskInstruction(t Task) string {
	switch t {
	case TaskFindingAnalysis:
		return "Task: analyze the provided detection evidence. Identify anomalies worth a closer, deterministic look, and list what additional evidence a validator would need. Reference related observation ids. Do not restate any existing verdict."
	case TaskEvidenceGap:
		return "Task: given the provided evidence, list ONLY what evidence is missing to reach a conclusion. Put those in missing_evidence; propose nothing."
	case TaskCandidateDedup:
		return "Task: the input is a list of research candidates. Group ids that describe the same underlying issue into duplicate_groups. Do not invent new candidates."
	default:
		return "Task: analyze the provided material and propose hypotheses worth validating."
	}
}

// BuildMessages assembles the chat messages for a request: the standing system
// rules, the task framing, an optional caller instruction, and the payload.
func BuildMessages(req AnalysisRequest) []Message {
	var user strings.Builder
	user.WriteString(taskInstruction(req.Task))
	if req.Target != "" {
		user.WriteString("\n\nSubject: ")
		user.WriteString(req.Target)
	}
	if strings.TrimSpace(req.Instruction) != "" {
		user.WriteString("\n\nAdditional context: ")
		user.WriteString(req.Instruction)
	}
	if len(req.Payload) > 0 {
		user.WriteString("\n\nInput (JSON):\n")
		user.Write(req.Payload)
	}
	return []Message{
		{Role: "system", Content: systemPreamble},
		{Role: "user", Content: user.String()},
	}
}
