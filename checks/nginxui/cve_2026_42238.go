// Package nginxui holds detection-only checkers for the nginx-ui web panel
// (github.com/0xJacky/nginx-ui). nginx-ui exposes no version to an
// unauthenticated client, so detection uses safe, non-destructive probes in
// active-probe mode and earns confirmed through the shared Confirm contract.
package nginxui

import (
	"context"
	"strings"

	"gopoc/checks/detect"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

const reference = "https://www.cve.org/CVERecord?id=CVE-2026-42238"

// restorePath is the unauthenticated backup-restore endpoint; authControlPath is
// a normal API that requires authentication, used as the negative control.
const (
	restorePath     = "/api/restore"
	authControlPath = "/api/settings"
)

type checker struct {
	meta   model.Metadata
	client httpx.Probe
	mode   model.Mode
}

func NewCVE202642238(client httpx.Probe, mode model.Mode) *checker {
	return &checker{
		meta: model.Metadata{
			ID:         "CVE-2026-42238",
			Name:       "nginx-ui Unauthenticated Backup Restore Code Injection",
			Product:    "nginx-ui",
			Severity:   "critical",
			References: []string{reference},
		},
		client: client,
		mode:   mode,
	}
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
	if c.mode == model.ModeActiveProbe {
		caps |= model.CapHTTPPost
	}
	return caps
}

func (c *checker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	if c.mode != model.ModeActiveProbe {
		f.Confidence, f.Reason = 0, "requires_active_probe"
		f.Evidence.Message = "nginx-ui exposes no version to unauthenticated clients; run --mode active-probe to safely test the unauthenticated restore window"
		return f
	}

	// Positive: reaching the restore handler unauthenticated. Negative: a normal
	// API that requires auth, proving the server is not blanket-accepting.
	res := detect.Confirm(ctx, c.client, target, detect.ConfirmSpec{
		Positive:  detect.ConfirmProbe{Kind: "restore_probe", Method: "POST", Path: restorePath},
		Negatives: []detect.ConfirmProbe{{Kind: "auth_control", Method: "GET", Path: authControlPath}},
		Feature:   restoreFeature,
		Policy:    detect.DefaultConfirmPolicy(),
	})
	f.Evidence = model.Evidence{Observations: res.Observations, Confirmation: res.Confirmation}
	if len(res.Observations) > 0 {
		f.Evidence.StatusCode = res.Observations[0].StatusCode
		f.Evidence.Headers = res.Observations[0].Headers
	}

	switch {
	case res.Confirmed:
		f.Verdict, f.Confidence, f.Reason = model.VerdictConfirmed, 96, "unauthenticated_restore"
		f.Evidence.Message = "The backup restore handler executed without authentication (rejected only for a missing multipart archive), reproduced across probes, while an auth-required control was rejected. CVE-2026-42238 unauthenticated window is open. No archive was uploaded, so nothing was restored and no command was executed"
	case res.PositiveErr != nil:
		f.Verdict, f.Reason, f.Evidence.Message = model.VerdictError, "request_failed", "Restore probe failed: "+res.PositiveErr.Error()
	case res.PositiveStatus == 401 || res.PositiveStatus == 403:
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 75, "authentication_required"
		f.Evidence.Message = "The restore endpoint requires authentication; the unauthenticated window is closed or the instance is patched"
	case res.PositiveMatched:
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 70, "restore_reachable"
		f.Evidence.Message = "The restore handler appears reachable unauthenticated but confirmation was incomplete (control or repeat did not hold); treated as likely, not confirmed"
	default:
		f.Confidence, f.Reason = 20, "inconclusive"
		f.Evidence.Message = "Restore endpoint returned an unrecognized response; unauthenticated status could not be determined"
	}
	return f
}

// restoreFeature matches the restore handler running without auth: not an auth
// rejection, not absent, and carrying the backup handler's own error signature.
func restoreFeature(r httpx.Response) (bool, string, string) {
	body := string(r.Body)
	if r.StatusCode == 401 || r.StatusCode == 403 || strings.Contains(body, "Authorization failed") {
		return false, "restore_handler", "authentication required"
	}
	if r.StatusCode == 404 {
		return false, "restore_handler", "endpoint absent"
	}
	// nginx-ui-specific: only the backup restore handler answers with scope=backup.
	// A bare "multipart/form-data" or "4511" is too generic (appears in ordinary
	// API errors) and previously caused a false likely — do not match on those.
	if strings.Contains(body, `"scope":"backup"`) {
		return true, "restore_handler", "reached backup restore handler without authentication"
	}
	return false, "restore_handler", "no backup restore handler signature"
}
