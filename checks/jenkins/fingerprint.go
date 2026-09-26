// Package jenkins holds detection for Jenkins CI: an attack-surface base
// (product fingerprint, reliable version from the X-Jenkins header, anonymous
// access boundary, Script Console / CLI surfaces) plus one CVE. Unlike
// JBoss/WildFly, Jenkins gives two solid, low-FP, safely-verifiable lines:
//
//  1. MISCONFIG-JENKINS-ANON-SCRIPT-CONSOLE — the Groovy Script Console reachable
//     anonymously (== unauthenticated RCE). The primary rule.
//  2. CVE-2024-23897 — CLI @file arbitrary file read, cleanly version-bounded
//     because Jenkins advertises its exact version in the X-Jenkins header.
//
// See docs/jenkins-attack-surface.md. All checkers here are detection-only and
// cap at `likely`: the Script Console is never POSTed a Groovy payload, and the
// CVE's file read is never attempted against a real target.
package jenkins

import (
	"regexp"
	"strings"

	"gopoc/internal/httpx"
)

// looksLikeJenkins reports whether r carries at least TWO Jenkins-specific
// response headers. A single header is deliberately not enough: a reverse proxy
// (or an attacker) can forge one `X-Jenkins` cheaply, and we must never let a
// forged header alone drive a high verdict. `X-Jenkins` names the version;
// `X-Hudson` (a constant legacy marker, e.g. 1.395) and `X-Jenkins-Session` are
// emitted by the real servlet on every response — confirmed on live 2.568.3,
// present even on a 403. Requiring X-Jenkins AND one of the other two is the
// "combine ≥2 signals" lockdown.
func looksLikeJenkins(r httpx.Response) bool {
	if r.Get("X-Jenkins") == "" {
		return false
	}
	return r.Get("X-Hudson") != "" || r.Get("X-Jenkins-Session") != ""
}

// scriptFormRE matches the Script Console's Groovy input control: a textarea (or
// input) whose name is exactly "script". Confirmed on live 2.568.3:
// `<textarea id="script" name="script" class="script">`.
var scriptFormRE = regexp.MustCompile(`(?i)<(?:textarea|input)[^>]*\bname=["']script["']`)

// groovyConsoleRE matches the Script Console's own descriptive copy or its
// bundled Groovy editor. Confirmed on live 2.568.3: the page reads "Type in an
// arbitrary <a ...>Groovy script</a> and execute it on the server" and loads the
// CodeMirror groovy mode adjunct.
var groovyConsoleRE = regexp.MustCompile(`(?i)arbitrary\b.{0,40}Groovy script|codemirror/mode/groovy|execute it on the server`)

// isScriptConsole reports whether body is the real Jenkins Script Console page —
// not merely a 200 from a `/script` path. It requires the "Script Console"
// label (title/breadcrumb/h1) AND the actual Groovy execution control (the
// named textarea or the console's own copy). A reverse proxy returning a uniform
// 200 page, or an unrelated app that happens to serve `/script`, has neither and
// is not flagged.
func isScriptConsole(body []byte) bool {
	s := string(body)
	if !strings.Contains(s, "Script Console") {
		return false
	}
	return scriptFormRE.MatchString(s) || groovyConsoleRE.MatchString(s)
}
