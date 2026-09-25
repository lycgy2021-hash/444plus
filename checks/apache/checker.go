package apache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"gopoc/checks/detect"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

const reference = "https://httpd.apache.org/security/vulnerabilities_24.html"

var apacheVersionRE = regexp.MustCompile(`(?i)(?:^|[\s(])Apache/([0-9]+\.[0-9]+\.[0-9]+)`)

type checker struct {
	meta     model.Metadata
	versions map[string]bool
	segment  string
	client   httpx.Probe
	mode     model.Mode
	canary   model.CanaryConfig
}

func (c *checker) ID() string   { return c.meta.ID }
func (c *checker) Name() string { return c.meta.Name }
func (c *checker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

func (c *checker) Capabilities() model.Capability {
	caps := model.CapPassive | model.CapHTTPGet
	if c.mode == model.ModeActiveCanary {
		caps |= model.CapCanaryRead
	}
	return caps
}

func (c *checker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	r, err := c.client.Fingerprint(ctx, target)
	f.Evidence = model.Evidence{StatusCode: r.StatusCode, Headers: r.Headers, Observations: []model.Observation{r.Observation("fingerprint", err)}}
	if err != nil {
		f.Verdict, f.Reason = model.VerdictError, "request_failed"
		f.Evidence.Message = "Fingerprint request failed: " + err.Error()
		return f
	}
	version, _, _ := detect.ExtractVersion(r.Headers["Server"], apacheVersionRE)
	f.Evidence.Version = version
	switch {
	case version == "":
		f.Confidence, f.Reason = 20, "version_unknown"
		f.Evidence.Message = "No unambiguous Apache version exposed; vulnerability status is unknown"
	case c.versions[version]:
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 85, "affected_version"
		f.Evidence.Message = "Affected Apache version advertised (version match only); configuration, backports and exploitability are unverified. Active-canary mode can raise this to confirmed"
	default:
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 70, "version_not_affected"
		f.Evidence.Message = "Advertised version is outside this CVE's affected set; banner evidence does not prove absence"
		if c.ID() == "CVE-2021-41773" && version == "2.4.50" {
			f.Evidence.Message += "; check CVE-2021-42013"
		}
	}
	if c.mode == model.ModeActiveCanary {
		return c.checkCanary(ctx, target, f)
	}
	return f
}

func (c *checker) checkCanary(ctx context.Context, target model.Target, f model.Finding) model.Finding {
	if err := c.canary.Validate(); err != nil {
		f.Verdict, f.Confidence, f.Reason = model.VerdictError, 0, "invalid_canary"
		f.Evidence.Message = err.Error()
		return f
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		f.Evidence.Message += "; could not generate canary control"
		return f
	}
	path := c.canary.AliasPath + strings.Repeat(c.segment+"/", c.canary.TraversalDepth) + strings.TrimPrefix(c.canary.FilePath, "/")
	missingPath := path + ".gopoc-missing-" + hex.EncodeToString(random[:])
	expected := c.canary.Expected
	// The vulnerability feature is an exact, whole-body canary read on a 200 —
	// a body-level match, never a bare status code.
	feature := func(r httpx.Response) (bool, string, string) {
		if r.Truncated {
			return false, "canary_exact", "response truncated"
		}
		if r.StatusCode == 200 && matchesCanary(r.Body, expected) {
			return true, "canary_exact", "body equals the configured canary"
		}
		return false, "canary_exact", "body is not the exact canary"
	}
	res := detect.Confirm(ctx, c.client, target, detect.ConfirmSpec{
		Positive: detect.ConfirmProbe{Kind: "canary_probe", Method: "GET", Path: path},
		Negatives: []detect.ConfirmProbe{
			{Kind: "direct_control", Method: "GET", Path: c.canary.FilePath},
			{Kind: "missing_control", Method: "GET", Path: missingPath},
		},
		Feature: feature,
		// Both controls must be clean, so the missing/direct reads cannot explain the hit.
		Policy: detect.ConfirmPolicy{MinPositiveMatches: 2, MinNegativePasses: 2, RequireDiff: true, RequireRepeat: true},
	})
	f.Evidence.Observations = append(f.Evidence.Observations, res.Observations...)
	f.Evidence.Confirmation = res.Confirmation
	if res.Confirmed {
		f.Verdict, f.Confidence, f.Reason = model.VerdictConfirmed, 99, "canary_verified"
		f.Evidence.Message = fmt.Sprintf("CVE-specific traversal returned the exact configured canary on %d/%d probes; direct and randomized missing-file controls did not. File-read behavior confirmed for %s; command execution was not tested", res.Confirmation.PositivePasses, res.Confirmation.PositiveNeeded, c.ID())
	} else {
		f.Evidence.Message += "; active canary did not confirm traversal; the passive verdict is retained"
	}
	return f
}

func matchesCanary(body []byte, expected string) bool {
	value := strings.TrimSuffix(string(body), "\n")
	value = strings.TrimSuffix(value, "\r")
	return value == expected
}
