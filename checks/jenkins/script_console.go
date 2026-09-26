package jenkins

import "gopoc/internal/httpx"

// scriptPath is the Groovy Script Console. Reachable anonymously it is a direct
// unauthenticated RCE; the secure default requires the Administer permission and
// answers 403.
const scriptPath = "/script"

type scriptState int

const (
	scriptUnreachable scriptState = iota // request failed
	scriptProtected                      // 401/403 — the secure default
	scriptExposed                        // 200 AND the real console page
	scriptUnclear                        // 200 but not the console, or another status
)

// classifyScript maps the /script response to a state. A 200 alone is NOT
// "exposed": we require the response to actually be the Script Console page
// (isScriptConsole), so a login redirect target, a proxy's uniform 200, or an
// unrelated /script handler cannot be mistaken for an open Groovy console.
func classifyScript(r httpx.Response, err error) scriptState {
	if err != nil {
		return scriptUnreachable
	}
	switch r.StatusCode {
	case 401, 403:
		return scriptProtected
	case 200:
		if isScriptConsole(r.Body) {
			return scriptExposed
		}
		return scriptUnclear
	default:
		return scriptUnclear
	}
}
