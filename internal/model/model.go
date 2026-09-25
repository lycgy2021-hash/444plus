package model

import (
	"context"
	"time"
)

type Verdict string

const (
	VerdictConfirmed Verdict = "confirmed"
	VerdictLikely    Verdict = "likely"
	// VerdictDetected sits below likely: a version or fingerprint matches an
	// affected range, but no dangerous endpoint, behavior or exploit has been
	// observed. It is not proof of exploitability.
	VerdictDetected Verdict = "detected"
	VerdictNotFound Verdict = "not_found"
	VerdictUnknown  Verdict = "unknown"
	// VerdictError is orthogonal to the evidence tiers: the check did not complete
	// normally (request failure, cancellation, checker panic, or a contract
	// violation such as a confirmed verdict without confirmation evidence). It is
	// not a statement about the target, so it is counted and reported separately.
	VerdictError Verdict = "error"
)

type Mode string

const (
	ModePassive      Mode = "passive"
	ModeActiveCanary Mode = "active-canary"
	// ModeActiveProbe permits safe, non-destructive POST probes that confirm a
	// vulnerable state without changing it (e.g. reaching an unauthenticated
	// endpoint). It does not permit state changes or command execution.
	ModeActiveProbe Mode = "active-probe"
)

type Capability uint64

const (
	CapPassive Capability = 1 << iota
	CapHTTPGet
	CapCanaryRead
	CapStateChange
	CapCommandExecution
	// CapHTTPPost is a safe, non-destructive POST probe used by detection-only
	// checkers. It is weaker than CapStateChange: the caller guarantees the
	// request cannot alter server state.
	CapHTTPPost
	// CapTCPProbe is a safe, non-destructive raw-TCP protocol handshake (e.g.
	// WebLogic T3/IIOP banner) on the target's own host:port. It reads a banner;
	// it does not exploit or change state.
	CapTCPProbe
)

func (c Capability) Names() []string {
	names := []string{}
	for _, v := range []struct {
		bit  Capability
		name string
	}{{CapPassive, "passive"}, {CapHTTPGet, "http_get"}, {CapHTTPPost, "http_post"}, {CapTCPProbe, "tcp_probe"}, {CapCanaryRead, "canary_read"}, {CapStateChange, "state_change"}, {CapCommandExecution, "command_execution"}} {
		if c&v.bit != 0 {
			names = append(names, v.name)
		}
	}
	return names
}

type Metadata struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Product      string   `json:"product"`
	Severity     string   `json:"severity"`
	Family       string   `json:"family,omitempty"` // groups related CVEs, e.g. "ToolShell"
	References   []string `json:"references"`
	Capabilities []string `json:"capabilities"`
}

// Observation contains bounded, selected evidence. Response bodies and cookies
// are deliberately excluded from reports.
type Observation struct {
	Kind       string            `json:"kind"`
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	Bytes      int               `json:"bytes"`
	Truncated  bool              `json:"truncated,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type Evidence struct {
	StatusCode   int               `json:"status_code,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Version      string            `json:"version,omitempty"`
	Message      string            `json:"message"`
	Observations []Observation     `json:"observations,omitempty"`
	// Confirmation is the machine-readable proof behind a confirmed verdict. The
	// engine rejects a confirmed finding whose Confirmation does not Pass, so a
	// checker cannot mint confirmed from a bare status check.
	Confirmation *Confirmation `json:"confirmation,omitempty"`
}

// ConfirmStep records one probe in a confirmation: the positive exploit probe or
// a negative control, and whether it exhibited the vulnerability feature.
type ConfirmStep struct {
	Role    string `json:"role"` // "positive" or "negative"
	Kind    string `json:"kind"`
	URL     string `json:"url,omitempty"`
	Status  int    `json:"status_code,omitempty"`
	Matched bool   `json:"matched"`
	Matcher string `json:"matcher,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Confirmation is the structured result of the shared confirmation contract.
type Confirmation struct {
	PositivePasses int           `json:"positive_passes"`
	PositiveNeeded int           `json:"positive_needed"`
	NegativePasses int           `json:"negative_passes"`
	NegativeNeeded int           `json:"negative_needed"`
	DiffMatched    bool          `json:"diff_matched"`
	RepeatOK       bool          `json:"repeat_ok"`
	Steps          []ConfirmStep `json:"steps,omitempty"`
}

// Passed reports whether the confirmation meets the contract: enough positive
// matches, enough clean negative controls, and an explainable positive/negative
// difference. Only a passing Confirmation may back a confirmed verdict.
func (c *Confirmation) Passed() bool {
	return c != nil &&
		c.PositiveNeeded > 0 && c.PositivePasses >= c.PositiveNeeded &&
		c.NegativeNeeded > 0 && c.NegativePasses >= c.NegativeNeeded &&
		c.DiffMatched && c.RepeatOK
}

type Finding struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Target     string    `json:"target"`
	Verdict    Verdict   `json:"verdict"`
	Confidence int       `json:"confidence"`
	Reason     string    `json:"reason,omitempty"`
	Evidence   Evidence  `json:"evidence"`
	CheckedAt  time.Time `json:"checked_at"`
	DurationMS int64     `json:"duration_ms"`
}

// Checkers must be safe for concurrent calls and honor context cancellation.
// A registry is a set of trusted, compiled Go plugins, not a code sandbox.
type Checker interface {
	ID() string
	Name() string
	Metadata() Metadata
	Capabilities() Capability
	Check(context.Context, Target) Finding
}
