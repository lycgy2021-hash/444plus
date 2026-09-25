package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"gopoc/internal/model"
)

type Report struct {
	SchemaVersion int                   `json:"schema_version"`
	RunID         string                `json:"run_id"`
	Mode          model.Mode            `json:"mode"`
	StartedAt     time.Time             `json:"started_at"`
	FinishedAt    time.Time             `json:"finished_at"`
	Cancelled     bool                  `json:"cancelled"`
	Targets       []model.Target        `json:"targets"`
	Checks        []model.Metadata      `json:"checks"`
	Summary       map[model.Verdict]int `json:"summary"`
	Findings      []model.Finding       `json:"findings"`
}

func New(mode model.Mode, targets []model.Target, checks []model.Checker) Report {
	var id [16]byte
	_, _ = rand.Read(id[:]) // crypto/rand.Read never returns an error in Go 1.25.
	r := Report{SchemaVersion: 1, RunID: hex.EncodeToString(id[:]), Mode: mode, StartedAt: time.Now().UTC(), Targets: targets}
	for _, c := range checks {
		r.Checks = append(r.Checks, c.Metadata())
	}
	return r
}

func (r *Report) Finish(findings []model.Finding, cancelled bool) {
	r.FinishedAt, r.Cancelled, r.Findings = time.Now().UTC(), cancelled, findings
	r.Summary = map[model.Verdict]int{model.VerdictConfirmed: 0, model.VerdictLikely: 0, model.VerdictDetected: 0, model.VerdictNotFound: 0, model.VerdictUnknown: 0, model.VerdictError: 0}
	for _, f := range findings {
		r.Summary[f.Verdict]++
	}
}

func WriteJSON(w io.Writer, r Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(r)
}
