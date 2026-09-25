package detect

import (
	"context"
	"regexp"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// VersionChecker is a passive checker: it fingerprints the target, extracts the
// product version from the Server banner and decides a verdict from an affected
// predicate. Callers supply only the product-specific fields.
type VersionChecker struct {
	Meta     model.Metadata
	Client   httpx.Probe
	Re       *regexp.Regexp
	Affected func(Version) bool
	// A version match is the "detected" tier: it never rises to likely or
	// confirmed on its own, because no dangerous behavior has been observed.
	DetectedConfidence int
	DetectedMessage    string
	NotFoundMessage    string
	UnknownMessage     string
}

func (c *VersionChecker) ID() string   { return c.Meta.ID }
func (c *VersionChecker) Name() string { return c.Meta.Name }
func (c *VersionChecker) Metadata() model.Metadata {
	m := c.Meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Passive detection never sends an exploit request.
func (c *VersionChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *VersionChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	r, err := c.Client.Fingerprint(ctx, target)
	f.Evidence = model.Evidence{StatusCode: r.StatusCode, Headers: r.Headers, Observations: []model.Observation{r.Observation("fingerprint", err)}}
	if err != nil {
		f.Verdict, f.Reason = model.VerdictError, "request_failed"
		f.Evidence.Message = "Fingerprint request failed: " + err.Error()
		return f
	}
	raw, v, ok := ExtractVersion(r.Headers["Server"], c.Re)
	f.Evidence.Version = raw
	switch {
	case !ok:
		f.Confidence, f.Reason = 20, "version_unknown"
		f.Evidence.Message = c.UnknownMessage
	case c.Affected(v):
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, c.DetectedConfidence, "affected_version"
		f.Evidence.Message = c.DetectedMessage
	default:
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 70, "version_not_affected"
		f.Evidence.Message = c.NotFoundMessage
	}
	return f
}

// ProbeChecker is a safe active-probe checker: in active-probe mode it sends one
// non-destructive POST and classifies the response. In any other mode it reports
// unknown (the probe is the only reliable signal). Callers supply the request
// and a classifier.
type ProbeChecker struct {
	Meta   model.Metadata
	Client httpx.Probe
	Mode   model.Mode
	// Kind labels the observation, e.g. "restore_probe".
	Kind string
	Path string
	// Build returns the request body, its Content-Type, and a per-request token
	// the classifier may need (e.g. an echoed uid). Any field may be empty.
	Build func() (body []byte, contentType string, token string)
	// PassiveMessage explains why non-active-probe modes cannot decide.
	PassiveMessage string
	// Classify maps the probe response to (verdict, confidence, reason, message).
	Classify func(status int, body, token string) (model.Verdict, int, string, string)
}

func (c *ProbeChecker) ID() string   { return c.Meta.ID }
func (c *ProbeChecker) Name() string { return c.Meta.Name }
func (c *ProbeChecker) Metadata() model.Metadata {
	m := c.Meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

func (c *ProbeChecker) Capabilities() model.Capability {
	caps := model.CapPassive | model.CapHTTPGet
	if c.Mode == model.ModeActiveProbe {
		caps |= model.CapHTTPPost
	}
	return caps
}

func (c *ProbeChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	if c.Mode != model.ModeActiveProbe {
		f.Confidence, f.Reason = 0, "requires_active_probe"
		f.Evidence.Message = c.PassiveMessage
		return f
	}
	var body []byte
	contentType, token := "", ""
	if c.Build != nil {
		body, contentType, token = c.Build()
	}
	r, err := c.Client.Post(ctx, target, c.Path, contentType, body)
	f.Evidence = model.Evidence{StatusCode: r.StatusCode, Headers: r.Headers, Observations: []model.Observation{r.Observation(c.Kind, err)}}
	if err != nil {
		f.Verdict, f.Reason = model.VerdictError, "request_failed"
		f.Evidence.Message = "Probe request failed: " + err.Error()
		return f
	}
	verdict, confidence, reason, message := c.Classify(r.StatusCode, string(r.Body), token)
	f.Verdict, f.Confidence, f.Reason, f.Evidence.Message = verdict, confidence, reason, message
	return f
}
