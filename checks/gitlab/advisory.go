package gitlab

import (
	"context"
	"fmt"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// assessment is the shared, per-scan GitLab assessment. Every checker in this
// package reads from one assessment so a single-IP scan probes GitLab once, not
// once per CVE (the assesscache reuse this package exists to demonstrate).
type assessment struct {
	isGitLab   bool
	rawVersion string // e.g. "16.6.0", from the /help gon object
	ver        glVersion
	hasVersion bool

	resetReachable bool

	obs []model.Observation
}

// assess returns the shared GitLab assessment, memoized per scan.
func assess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "gitlab"}, func() any {
			return doAssess(ctx, client, target)
		}).(assessment)
	}
	return doAssess(ctx, client, target)
}

func doAssess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	var a assessment

	// Signal 1: the X-Gitlab-Meta response header (Fingerprint keeps headers,
	// nils the body). Never enough alone — the ≥2-signal lock.
	fp, fpErr := client.Fingerprint(ctx, target)
	a.obs = append(a.obs, fp.Observation("fingerprint", fpErr))
	hasMeta := fpErr == nil && fp.Get(metaHeader) != ""

	// Signal 2: the sign-in page body markers (needs a body-bearing Get).
	signIn, signInErr := client.Get(ctx, target, signInPath)
	a.obs = append(a.obs, signIn.Observation("sign_in", signInErr))
	bodyGitLab := signInErr == nil && bodyLooksLikeGitLab(signIn.Body)

	signals := 0
	if hasMeta {
		signals++
	}
	if bodyGitLab {
		signals++
	}
	// Tiebreaker: when exactly one signal is present, consult the PWA manifest so
	// GitLab-behind-a-header-stripping-proxy (meta gone) or a header-only case can
	// still reach two independent signals — but a lone signal never identifies.
	if signals == 1 {
		mf, mfErr := client.Get(ctx, target, manifestPath)
		a.obs = append(a.obs, mf.Observation("manifest", mfErr))
		if mfErr == nil && manifestIsGitLab(mf.Body) {
			signals++
		}
	}
	a.isGitLab = signals >= 2

	// Short-circuit: never probe GitLab-specific paths against a non-GitLab
	// target. A non-GitLab server sees only the fingerprint + sign-in GET.
	if !a.isGitLab {
		return a
	}

	// Reliable anonymous version from the /help gon object.
	help, helpErr := client.Get(ctx, target, helpPath)
	a.obs = append(a.obs, help.Observation("help_version", helpErr))
	if helpErr == nil {
		if v, raw, ok := parseVersionFromHelp(help.Body); ok {
			a.ver, a.rawVersion, a.hasVersion = v, raw, true
		}
	}

	// Forgotten-password surface (CVE-2023-7028). Read-only; never POSTed.
	reset, resetErr := client.Get(ctx, target, resetNewPath)
	a.obs = append(a.obs, reset.Observation("password_reset", resetErr))
	a.resetReachable = resetFlowReachable(reset, resetErr)

	return a
}

// advisoryChecker assesses one version-bounded GitLab CVE. A version in the
// affected range is `detected`; when the CVE exposes a surface we can safely
// confirm reachable, that raises it to `likely`. It never confirms — the exploit
// (account takeover / file read) is never performed against a real target.
type advisoryChecker struct {
	meta     model.Metadata
	client   httpx.Probe
	affected func(glVersion) bool
	// surfaceReachable, when non-nil, reports whether the CVE's exploit surface is
	// exposed and a short description. Nil means version-only (caps at detected).
	surfaceReachable func(assessment) (bool, string)
	surfaceName      string
	// notAttempted names the exploit action we deliberately did not perform, for
	// the report (e.g. "account takeover", "arbitrary file read").
	notAttempted string
}

func newAdvisory(id, name string, affected func(glVersion) bool, client httpx.Probe) *advisoryChecker {
	return &advisoryChecker{
		meta: model.Metadata{
			ID:         id,
			Name:       name,
			Product:    "gitlab",
			Severity:   "critical",
			References: []string{"https://about.gitlab.com/releases/categories/releases/"},
		},
		client:   client,
		affected: affected,
	}
}

func (c *advisoryChecker) ID() string   { return c.meta.ID }
func (c *advisoryChecker) Name() string { return c.meta.Name }
func (c *advisoryChecker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: HTTP fingerprint plus read-only GET probes. No POST is ever
// sent, so this never triggers a password reset.
func (c *advisoryChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *advisoryChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.obs}

	if !a.isGitLab {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 65, "product_not_gitlab"
		f.Evidence.Message = "No GitLab fingerprint (needs X-Gitlab-Meta plus GitLab-specific page markers); this CVE does not apply"
		return f
	}
	if !a.hasVersion {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = "GitLab detected but no version was exposed (the /help gon version was unreadable, e.g. public access is restricted); affected status is unknown"
		return f
	}
	f.Evidence.Version = a.rawVersion
	if !c.affected(a.ver) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 80, "version_not_affected"
		f.Evidence.Message = fmt.Sprintf("GitLab %s is outside the affected range; not affected", a.rawVersion)
		return f
	}

	base := fmt.Sprintf("GitLab %s is affected by %s. %s was NOT attempted", a.rawVersion, c.meta.ID, capitalize(c.notAttempted))
	if c.surfaceReachable != nil {
		if reachable, detail := c.surfaceReachable(a); reachable {
			f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 88, "affected_surface_exposed"
			f.Evidence.Message = fmt.Sprintf("%s; the %s is reachable (%s)", base, c.surfaceName, detail)
			return f
		}
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = fmt.Sprintf("%s; the %s was not found reachable (version match only)", base, c.surfaceName)
		return f
	}
	// Version-only CVE (no safe reachability probe): caps at detected.
	f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
	f.Evidence.Message = base + " (version match only)"
	return f
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32) + s[1:]
}
