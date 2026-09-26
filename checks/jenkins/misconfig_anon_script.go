package jenkins

import (
	"context"
	"fmt"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
)

// anonScriptID is not a CVE: the highest-value, lowest-FP, most reproducible
// Jenkins condition is a misconfiguration — the Groovy Script Console reachable
// by an unauthenticated caller. That is a direct remote code execution (any
// Groovy runs in the controller JVM). We detect the exposed console; we never
// POST a Groovy payload to prove it.
const anonScriptID = "MISCONFIG-JENKINS-ANON-SCRIPT-CONSOLE"

type anonScriptChecker struct {
	meta   model.Metadata
	client httpx.Probe
}

// NewAnonScriptConsole detects a Jenkins Script Console reachable without
// authentication.
func NewAnonScriptConsole(client httpx.Probe) *anonScriptChecker {
	return &anonScriptChecker{
		meta: model.Metadata{
			ID:       anonScriptID,
			Name:     "Jenkins Anonymous Script Console (Groovy RCE)",
			Product:  "jenkins",
			Severity: "critical",
			Family:   "misconfiguration",
			References: []string{
				"https://www.jenkins.io/doc/book/managing/script-console/",
			},
		},
		client: client,
	}
}

func (c *anonScriptChecker) ID() string   { return c.meta.ID }
func (c *anonScriptChecker) Name() string { return c.meta.Name }
func (c *anonScriptChecker) Metadata() model.Metadata {
	m := c.meta
	m.Capabilities = c.Capabilities().Names()
	return m
}

// Detection-only: fingerprint plus a read-only GET on /script. No Groovy is ever
// submitted, so this is a passive-mode capability.
func (c *anonScriptChecker) Capabilities() model.Capability {
	return model.CapPassive | model.CapHTTPGet
}

func (c *anonScriptChecker) Check(ctx context.Context, target model.Target) model.Finding {
	f := model.Finding{ID: c.ID(), Name: c.Name(), Target: target.BaseURL, Verdict: model.VerdictUnknown}
	a := assess(ctx, c.client, target)
	f.Evidence = model.Evidence{Observations: a.obs, Version: a.rawVersion}

	if !a.isJenkins {
		f.Verdict, f.Confidence, f.Reason = model.VerdictNotFound, 65, "product_not_jenkins"
		f.Evidence.Message = "No Jenkins fingerprint (needs X-Jenkins plus X-Hudson/X-Jenkins-Session); this check does not apply"
		return f
	}

	f.Evidence.StatusCode = a.script.StatusCode
	scriptURL := target.Origin() + scriptPath

	switch classifyScript(a.script, a.scriptErr) {
	case scriptUnreachable:
		f.Confidence, f.Reason = 30, "script_console_unreachable"
		f.Evidence.Message = fmt.Sprintf("Jenkins detected, but %s did not respond; anonymous Script Console exposure could not be determined", scriptURL)
	case scriptProtected:
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 75, "script_console_protected"
		f.Evidence.Message = fmt.Sprintf("Jenkins Script Console at %s requires authentication (HTTP %d); this is the secure default, not a misconfiguration", scriptURL, a.script.StatusCode)
	case scriptExposed:
		f.Verdict, f.Confidence, f.Reason = model.VerdictLikely, 92, "anonymous_script_console_exposed"
		msg := fmt.Sprintf("Jenkins Groovy Script Console at %s is reachable WITHOUT authentication (HTTP 200, console page confirmed). An unauthenticated caller can execute arbitrary Groovy in the controller JVM = full remote code execution", scriptURL)
		if note := a.anon.note(); note != "" {
			msg += fmt.Sprintf(" (%s)", note)
		}
		msg += ". No Groovy was submitted; code execution was NOT attempted"
		f.Evidence.Message = msg
	default: // scriptUnclear
		f.Verdict, f.Confidence, f.Reason = model.VerdictDetected, 60, "script_console_unconfirmed"
		f.Evidence.Message = fmt.Sprintf("Jenkins detected and %s returned HTTP %d, but the response was not the Script Console page; anonymous console exposure not confirmed", scriptURL, a.script.StatusCode)
	}
	return f
}
