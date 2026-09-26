package jenkins

import (
	"context"
	"fmt"

	"gopoc/internal/assesscache"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// assessment is the shared, per-scan Jenkins assessment. Both checkers in this
// package (the Script-Console misconfig and CVE-2024-23897) read from one
// assessment so a single-IP scan probes Jenkins once, not twice.
type assessment struct {
	isJenkins  bool
	rawVersion string // e.g. "2.568.3", from X-Jenkins (or a data-version fallback)
	ver        jkVersion
	hasVersion bool

	script    httpx.Response
	scriptErr error
	cliJar    httpx.Response
	cliJarErr error
	cli       httpx.Response
	cliErr    error
	anon      anonEvidence

	obs []model.Observation
}

// assess returns the shared Jenkins assessment, memoized per scan.
func assess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	if c := assesscache.From(ctx); c != nil {
		return c.GetOrRun(assesscache.Key{Target: target.BaseURL, Product: "jenkins"}, func() any {
			return doAssess(ctx, client, target)
		}).(assessment)
	}
	return doAssess(ctx, client, target)
}

func doAssess(ctx context.Context, client httpx.Probe, target model.Target) assessment {
	var a assessment

	fp, fpErr := client.Fingerprint(ctx, target)
	a.obs = append(a.obs, fp.Observation("fingerprint", fpErr))
	if fpErr == nil {
		a.isJenkins = looksLikeJenkins(fp)
		if v, ok := parseVersion(fp.Get("X-Jenkins")); ok {
			a.ver, a.rawVersion, a.hasVersion = v, fp.Get("X-Jenkins"), true
		}
	}
	// Short-circuit: never probe Jenkins-specific paths (/script, /cli, /api/json)
	// against a target that is not Jenkins. This keeps the FP corpus fast and
	// guarantees a non-Jenkins server sees only the one shared fingerprint GET.
	if !a.isJenkins {
		return a
	}

	// Script Console (body-bearing, so a real Get — Fingerprint nils bodies).
	a.script, a.scriptErr = client.Get(ctx, target, scriptPath)
	a.obs = append(a.obs, a.script.Observation("script_console", a.scriptErr))

	// Version fallback from the page body when the header was absent.
	if !a.hasVersion && a.scriptErr == nil {
		if v, raw, ok := parseVersionBody(a.script.Body); ok {
			a.ver, a.rawVersion, a.hasVersion = v, raw, true
		}
	}

	// CLI surface (CVE-2024-23897 vector reachability).
	a.cliJar, a.cliJarErr = client.Get(ctx, target, cliJarPath)
	a.obs = append(a.obs, a.cliJar.Observation("cli_jar", a.cliJarErr))
	a.cli, a.cliErr = client.Get(ctx, target, cliPath)
	a.obs = append(a.obs, a.cli.Observation("cli_endpoint", a.cliErr))

	// Anonymous boundary (evidence only, never elevates).
	a.anon = gatherAnon(ctx, client, target)
	a.obs = append(a.obs, a.anon.obs...)

	return a
}

// advisoryChecker assesses one Jenkins CVE that is version-bounded and whose
// exploit surface can be safely fingerprinted. A version in the affected range
// is `detected`; the exploit surface being reachable raises it to `likely`. It
// never confirms — the exploit itself is never run against a real target.
type advisoryChecker struct {
	meta     model.Metadata
	client   httpx.Probe
	affected func(jkVersion) bool
	// surfaceReachable reports whether the CVE's exploit surface is exposed on
	// this target, and returns a short human description of what was found.
	surfaceReachable func(assessment) (bool, string)
	surfaceName      string
}

func newAdvisory(id, name string, affected func(jkVersion) bool, client httpx.Probe) *advisoryChecker {
	return &advisoryChecker{
		meta: model.Metadata{
			ID:         id,
			Name:       name,
			Product:    "jenkins",
			Severity:   "critical",
			References: []string{"https://www.jenkins.io/security/"},
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

// Detection-only: HTTP fingerprint plus read-only GET probes.
func (c *advisoryChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *advisoryChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.obs}

	if !a.isJenkins {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 65, "product_not_jenkins"
		f.Evidence.Message = "No Jenkins fingerprint (needs X-Jenkins plus X-Hudson/X-Jenkins-Session); this CVE does not apply"
		return f
	}
	if !a.hasVersion {
		f.Confidence, f.Reason = 40, "version_unknown"
		f.Evidence.Message = "Jenkins detected but no version was exposed (X-Jenkins header and data-version both absent); affected status is unknown"
		return f
	}
	f.Evidence.Version = a.rawVersion
	if !c.affected(a.ver) {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 80, "version_not_affected"
		f.Evidence.Message = fmt.Sprintf("Jenkins %s is at or above the fix line; not affected", a.rawVersion)
		return f
	}

	reachable, detail := c.surfaceReachable(a)
	base := fmt.Sprintf("Jenkins %s is affected by %s. Exploit execution was NOT attempted", a.rawVersion, c.meta.ID)
	if reachable {
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 88, "affected_surface_exposed"
		f.Evidence.Message = fmt.Sprintf("%s; the %s is reachable (%s). Arbitrary file read was NOT attempted", base, c.surfaceName, detail)
	} else {
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 70, "affected_version"
		f.Evidence.Message = fmt.Sprintf("%s; the %s was not found reachable (version match only)", base, c.surfaceName)
	}
	return f
}
