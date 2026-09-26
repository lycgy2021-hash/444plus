package research

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"gopoc/internal/stateauth"
)

// maxHTTPBodyBytes bounds how much of a response body HTTPCollector/
// HTTPExecutor will ever read into memory — a fixed, generous-for-a-fixture
// cap, never a caller-adjustable knob. A target that returns more than this
// is treated as an error, never silently truncated into a misleading Fact.
const maxHTTPBodyBytes = 1 << 20 // 1 MiB

// refuseRedirects makes an *http.Client return the redirect response itself
// (the 3xx status, headers, and body) as its result, rather than following
// Location — used by both HTTPCollector and HTTPExecutor. v1's fixed,
// same-origin-only design has no legitimate reason to ever leave the target
// it was configured for: a redirect is exactly how a probe against one
// scope could end up actually talking to a different host, so v1 refuses
// every redirect outright rather than trying to decide which ones are
// "safe" (e.g. same-origin) to follow.
func refuseRedirects(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// newBudgetedHTTPClient builds the one kind of *http.Client every HTTP-based
// piece of the S10-E5 fixture uses: BudgetedRoundTripper as its Transport
// (so ExplorationBudget.MaxRequests bounds real network calls — see
// http_meter.go) and refuseRedirects as its CheckRedirect (so a probe can
// never be redirected off its own scope). Neither HTTPCollector nor
// HTTPExecutor accepts a caller-supplied *http.Client instead — that would
// reopen exactly the "an implementation could forget to wire this in
// correctly" gap S10-E4h closed for metering, one layer up, for redirects.
func newBudgetedHTTPClient() *http.Client {
	return &http.Client{
		Transport:     &BudgetedRoundTripper{},
		CheckRedirect: refuseRedirects,
	}
}

// HTTPCollector observes state by issuing a GET to ONE FIXED path against
// ONE FIXED base URL — both given at construction, in Go code, by whoever
// wires up an Explorer; neither ever comes from an AI proposal, a
// candidate, or any other caller-supplied value at call time. It is the
// first real (non-mock) Collector implementation: S10-E5's proof that the
// scope/budget/authority boundaries built and tested against fakes still
// hold under real HTTP I/O.
type HTTPCollector struct {
	baseURL *url.URL
	path    string
	client  *http.Client
}

// NewHTTPCollector constructs a Collector that always observes state by
// GETting baseURL+path. Both are fixed for the lifetime of the returned
// Collector — there is no method to change them, and no per-call parameter
// through which a caller could redirect it to a different path.
func NewHTTPCollector(baseURL, path string) (*HTTPCollector, error) {
	if path == "" {
		return nil, errors.New("research: HTTPCollector requires a non-empty observation path")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("research: HTTPCollector: invalid baseURL: %w", err)
	}
	return &HTTPCollector{baseURL: u, path: path, client: newBudgetedHTTPClient()}, nil
}

// Collect issues the one fixed GET this Collector was built with and
// encodes the response into a StateArtifact via stateauth.MarshalHTTPArtifact
// — HTTPStateProjector is the only thing that ever parses it back out. A
// redirect response is returned AS ITSELF (status 3xx, its own body) per
// refuseRedirects — never followed.
func (c *HTTPCollector) Collect(ctx context.Context, scope ExplorationScope) (stateauth.StateArtifact, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL.String()+c.path, nil)
	if err != nil {
		return stateauth.StateArtifact{}, fmt.Errorf("research: HTTPCollector: building request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return stateauth.StateArtifact{}, fmt.Errorf("research: HTTPCollector: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes+1))
	if err != nil {
		return stateauth.StateArtifact{}, fmt.Errorf("research: HTTPCollector: reading response body: %w", err)
	}
	if len(body) > maxHTTPBodyBytes {
		return stateauth.StateArtifact{}, fmt.Errorf("research: HTTPCollector: response body exceeds %d bytes", maxHTTPBodyBytes)
	}

	raw, err := stateauth.MarshalHTTPArtifact(stateauth.HTTPArtifact{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
	})
	if err != nil {
		return stateauth.StateArtifact{}, fmt.Errorf("research: HTTPCollector: encoding artifact: %w", err)
	}
	return stateauth.StateArtifact{ScopeHash: scope.Hash(), Raw: raw}, nil
}
