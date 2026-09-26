package research

import (
	"fmt"
	"net/url"
	"strings"
)

// HTTPProfile binds exactly one ExplorationScope to exactly one HTTP
// origin: its Collector and its Executor are built from the SAME baseURL,
// inside the SAME constructor call, so a Collector pointed at one target
// and an Executor pointed at a different one can never end up wired into
// the same Explorer by accident.
//
// The gap this closes: HTTPCollector and HTTPExecutor were previously
// constructed independently (each taking its own baseURL string), and
// nothing stopped a caller from building them against two DIFFERENT
// origins and passing both, plus an unrelated ExplorationScope, into the
// same NewExplorer call — e.g. `scopeHash = target-A` while
// `HTTPExecutor.baseURL = target-B`. ExplorationScope's own fields
// (TargetID, BuildID, SessionID, Protocol, HarnessID) are deliberately
// abstract identifiers a caller defines to mean whatever they want — S10's
// frozen contract never gave them a URL to literally validate an origin
// against — so the fix is structural, not a runtime comparison: HTTPProfile
// is the ONE place a scope and an HTTP origin are ever paired, and it
// builds the Collector and Executor for that origin ITSELF, from a single
// baseURL argument, rather than accepting two independently-built values
// that could have silently diverged.
type HTTPProfile struct {
	scope     ExplorationScope
	collector *HTTPCollector
	executor  *HTTPExecutor
	// originID is computed ONCE, at construction, as a pure function of
	// baseURL — never a caller assertion. See OriginID's own doc for why
	// this exists (S10/E8's "same-target physical binding" freeze item).
	originID string
}

// NewHTTPProfile builds an HTTPProfile for scope against baseURL: one
// HTTPCollector (observing observationPath) and one HTTPExecutor (running
// exactly the fixed actions map, RegistryKey -> path), both built from this
// SAME baseURL. See HTTPCollector/HTTPExecutor's own docs for the
// per-request guarantees (metered, redirect-refusing, body-capped) both
// still carry — HTTPProfile only closes the scope/origin binding gap; it
// changes nothing about how either one behaves once built.
func NewHTTPProfile(scope ExplorationScope, baseURL, observationPath string, actions map[string]string) (*HTTPProfile, error) {
	collector, err := NewHTTPCollector(baseURL, observationPath)
	if err != nil {
		return nil, err
	}
	executor, err := NewHTTPExecutor(baseURL, actions)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("research: HTTPProfile: invalid baseURL: %w", err)
	}
	return &HTTPProfile{scope: scope, collector: collector, executor: executor, originID: canonicalHTTPOrigin(u)}, nil
}

// canonicalHTTPOrigin renders u's scheme+host (which already includes a
// non-default port, if one was given) as a lowercased, canonical string —
// two baseURLs that name the same real network origin always produce the
// same value, regardless of case or of the observationPath/actions a
// caller happens to pair with them.
func canonicalHTTPOrigin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// Scope returns the ExplorationScope this profile was built for.
func (p *HTTPProfile) Scope() ExplorationScope { return p.scope }

// Collector returns this profile's Collector, for wiring into NewExplorer.
func (p *HTTPProfile) Collector() Collector { return p.collector }

// Executor returns this profile's Executor, for wiring into NewExplorer.
func (p *HTTPProfile) Executor() Executor { return p.executor }

// OriginID returns the canonical network origin (scheme://host) this
// profile's Collector AND Executor were both built from — a pure function
// of baseURL, never a caller assertion, and never affected by
// observationPath or the actions map. NewHTTPStateMachineReplayValidator
// (state_machine_replay.go) uses this to prove a ReplayTarget's own
// declared OriginID really does match the real network location the
// profile's Collector/Executor point at, rather than assuming it by
// convention — see that constructor's own doc for the gap this closes.
func (p *HTTPProfile) OriginID() string { return p.originID }
