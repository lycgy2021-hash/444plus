package research

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"gopoc/internal/actionauth"
)

// HTTPExecutor runs exactly the FIXED set of read-only GET actions it was
// constructed with — a compiled-in map from actionauth.RegistryKey to a URL
// path, given in Go code by whoever wires up an Explorer. There is no
// method to add an action afterward, and Execute takes no path/method/
// header/body from its caller: it looks up action.ID().RegistryKey (itself
// only ever produced by actionauth.ActionPolicy.Select — see S10-E1) in its
// own fixed map and issues exactly the GET that key names. Nothing — not an
// AI proposal, not a candidate, not this Executor's own caller — ever
// supplies a URL, method, header, or body at call time.
type HTTPExecutor struct {
	baseURL *url.URL
	actions map[string]string // RegistryKey -> path, fixed at construction
	client  *http.Client
}

// NewHTTPExecutor constructs an Executor for baseURL with the given fixed
// RegistryKey->path actions — e.g. {"get-root": "/", "get-health": "/health"}
// — every one of them a read-only GET. actions must be non-empty; every
// path must be non-empty. The map is copied so a caller mutating their own
// original afterward can never change what this Executor will run (the same
// discipline actionauth.NewRegistry's Facts deep-copy follows).
func NewHTTPExecutor(baseURL string, actions map[string]string) (*HTTPExecutor, error) {
	if len(actions) == 0 {
		return nil, fmt.Errorf("research: HTTPExecutor requires at least one registered action")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("research: HTTPExecutor: invalid baseURL: %w", err)
	}
	copied := make(map[string]string, len(actions))
	for key, path := range actions {
		if path == "" {
			return nil, fmt.Errorf("research: HTTPExecutor: action %q has an empty path", key)
		}
		copied[key] = path
	}
	return &HTTPExecutor{baseURL: u, actions: copied, client: newBudgetedHTTPClient()}, nil
}

// HTTPActionSpecID is the canonical, stable identity for "a read-only GET
// to path, with redirects refused and no body" — the ONLY executable shape
// HTTPExecutor.Execute ever performs (see this file's own top-of-file doc).
// Whoever registers an actionauth.RegisteredAction for a RegistryKey this
// Executor serves MUST set RegisteredAction.SpecID to HTTPActionSpecID(path)
// for that SAME path — Execute (below) independently recomputes this value
// from its own fixed map and refuses to run if the BoundAction it was
// handed carries anything else. This is what makes "PolicyID matches" also
// mean "the same real HTTP operation executes", never merely "the same
// declarative Key/Safety/Requirements happened to be registered against
// whatever this Executor does today" — see actionauth.RegisteredAction.
// SpecID's own doc for the gap this closes.
func HTTPActionSpecID(path string) string {
	return RawInputHash([]byte("http_action_v1\nmethod=GET\npath=" + path + "\nredirect=disabled\nbody=none"))
}

// Execute looks up action.ID().RegistryKey in this Executor's own fixed
// action map and issues exactly that GET — nothing else. A response status
// outside 2xx/3xx is treated as a failed action (the target refused or
// errored on a request this Executor knows to be one of its own registered
// read-only probes); a redirect (3xx) is observed as itself, never followed
// — refuseRedirects applies here exactly as it does for HTTPCollector.
//
// BEFORE issuing any request, Execute independently re-verifies
// action.SpecID() against HTTPActionSpecID(path) for the path THIS
// Executor's own fixed map resolves for that RegistryKey — never trusting
// the registry/policy side's SpecID as sufficient on its own. This is the
// SAME defense-in-depth discipline as ValidFor: a BoundAction's own
// registered SpecID and this Executor's actual wiring could otherwise each
// be individually "valid" while wired to each other incorrectly (e.g. a
// policy and an Executor upgraded independently, out of step) — see
// actionauth.RegisteredAction.SpecID's own doc.
func (e *HTTPExecutor) Execute(ctx context.Context, action actionauth.BoundAction) error {
	path, ok := e.actions[action.ID().RegistryKey]
	if !ok {
		return fmt.Errorf("research: HTTPExecutor: %q is not one of this executor's fixed registered actions", action.ID().RegistryKey)
	}
	if wantSpecID := HTTPActionSpecID(path); action.SpecID() != wantSpecID {
		return fmt.Errorf("research: HTTPExecutor: action %q carries SpecID %q, but this executor's own registered spec for that key is %q — refusing to execute a possibly mis-wired action",
			action.ID().RegistryKey, action.SpecID(), wantSpecID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL.String()+path, nil)
	if err != nil {
		return fmt.Errorf("research: HTTPExecutor: building request: %w", err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("research: HTTPExecutor: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("research: HTTPExecutor: %s %s returned status %d", http.MethodGet, path, resp.StatusCode)
	}
	return nil
}

// ExecuteRecovery is a deliberate no-op for this fixture: every action
// HTTPExecutor can ever run is a read-only GET (enforced by construction —
// there is no way to register anything else), so no HTTP action this
// Executor performs ever mutates target state, and there is nothing to
// reverse. This is honest about why, not a placeholder: a future Executor
// whose registered actions DO mutate state (a real write action) would need
// a real ExecuteRecovery, and must not copy this one.
func (e *HTTPExecutor) ExecuteRecovery(ctx context.Context, recovery actionauth.BoundRecovery) error {
	return nil
}
