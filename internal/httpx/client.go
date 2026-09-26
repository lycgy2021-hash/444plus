package httpx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopoc/internal/model"
	"gopoc/internal/policy"
)

type Options struct {
	Timeout     time.Duration `yaml:"timeout"`
	MaxBodySize int64         `yaml:"max_body_size"`
	Concurrency int           `yaml:"concurrency"`
	PerHost     int           `yaml:"per_host"`
	Rate        float64       `yaml:"rate"`
	Redirects   int           `yaml:"redirects"`
	UserAgent   string        `yaml:"user_agent"`
	Proxy       string        `yaml:"proxy"`
	DNS         string        `yaml:"dns"`
	InsecureTLS bool          `yaml:"insecure_tls"`
}

func Defaults() Options {
	return Options{Timeout: 5 * time.Second, MaxBodySize: 1 << 20, Concurrency: 20, PerHost: 2, Rate: 2, Redirects: 3, UserAgent: "gopoc/0.1"}
}

func (o Options) Validate() error {
	if o.Timeout <= 0 || o.Timeout > time.Hour || o.MaxBodySize < 1 || o.MaxBodySize > 64<<20 || o.Concurrency < 1 || o.Concurrency > 1024 || o.PerHost < 1 || o.PerHost > 1024 {
		return errors.New("invalid HTTP limits: timeout (0,1h], body [1,64MiB], concurrency/per_host [1,1024]")
	}
	if math.IsNaN(o.Rate) || math.IsInf(o.Rate, 0) || o.Rate < 0 || o.Rate > 10000 || (o.Rate > 0 && o.Rate < 0.001) {
		return errors.New("rate must be 0 (unlimited) or between 0.001 and 10000 requests/second")
	}
	if o.Redirects < 0 || o.Redirects > 10 || o.UserAgent == "" || strings.ContainsAny(o.UserAgent, "\r\n") {
		return errors.New("invalid redirects or User-Agent")
	}
	return nil
}

type Response struct {
	URL        string
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Bytes      int
	Truncated  bool
	SHA256     string
	Location   string
}

// Get returns a captured response header by name, case-insensitively.
func (r Response) Get(key string) string { return r.Headers[http.CanonicalHeaderKey(key)] }

func (r Response) Observation(kind string, err error) model.Observation {
	o := model.Observation{Kind: kind, URL: r.URL, StatusCode: r.StatusCode, Headers: r.Headers, SHA256: r.SHA256, Bytes: r.Bytes, Truncated: r.Truncated}
	if err != nil {
		o.Error = err.Error()
	}
	return o
}

type Probe interface {
	Fingerprint(context.Context, model.Target) (Response, error)
	Get(context.Context, model.Target, string) (Response, error)
	Post(context.Context, model.Target, string, string, []byte) (Response, error)
	Options(context.Context, model.Target, string) (Response, error)
	TCP(context.Context, model.Target, []byte, int) ([]byte, error)
}

type cached struct {
	done chan struct{}
	resp Response
	err  error
}

type Client struct {
	http         *http.Client
	transport    *http.Transport
	dialer       *net.Dialer
	options      Options
	policy       *policy.Policy
	forwardProxy bool
	global       chan struct{}
	rateGate     chan struct{}
	next         time.Time
	mu           sync.Mutex
	hosts        map[string]chan struct{}
	cache        map[string]*cached
	httpReqs     atomic.Int64
	tcpReqs      atomic.Int64
}

// Stats reports the number of HTTP and TCP requests actually dispatched, for
// per-scan reporting.
func (c *Client) Stats() (httpReqs, tcpReqs int64) {
	return c.httpReqs.Load(), c.tcpReqs.Load()
}

func New(options Options, p *policy.Policy) (*Client, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("HTTP client requires a policy")
	}
	dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}
	if options.DNS != "" {
		if _, _, err := net.SplitHostPort(options.DNS); err != nil {
			return nil, errors.New("dns must be an address with port, e.g. 127.0.0.1:53")
		}
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: options.Timeout}).DialContext(ctx, network, options.DNS)
		}}
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext, ForceAttemptHTTP2: false,
		MaxIdleConns: options.Concurrency, MaxConnsPerHost: options.PerHost,
		MaxIdleConnsPerHost: options.PerHost, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: options.Timeout, ResponseHeaderTimeout: options.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.InsecureTLS},
	}
	// Proxy use is explicit: environment proxies are not inherited implicitly.
	forwardProxy := false
	if options.Proxy != "" {
		u, err := url.Parse(options.Proxy)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("invalid proxy URL")
		}
		transport.Proxy = http.ProxyURL(u)
		forwardProxy = u.Scheme == "http" || u.Scheme == "https"
	}
	return &Client{
		http:      &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		transport: transport, dialer: dialer, options: options, policy: p, forwardProxy: forwardProxy,
		global: make(chan struct{}, options.Concurrency), rateGate: make(chan struct{}, 1),
		hosts: map[string]chan struct{}{}, cache: map[string]*cached{},
	}, nil
}

// TCP opens one raw TCP connection to the target's host:port, optionally sends
// payload, reads up to limit bytes, and closes. It is for protocol-level
// handshake fingerprinting (e.g. WebLogic T3/IIOP) that HTTP cannot express. It
// honors the same target allowlist, concurrency and rate limits, requires the
// CapTCPProbe capability, and never reuses the connection.
func (c *Client) TCP(ctx context.Context, target model.Target, payload []byte, limit int) ([]byte, error) {
	if err := c.policy.CheckTarget(target); err != nil {
		return nil, err
	}
	if err := c.policy.CheckCapabilities(model.CapTCPProbe); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1<<20 {
		return nil, errors.New("tcp read limit must be between 1 and 1MiB")
	}
	c.mu.Lock()
	sem := c.hosts[target.Host]
	if sem == nil {
		sem = make(chan struct{}, c.options.PerHost)
		c.hosts[target.Host] = sem
	}
	c.mu.Unlock()
	if err := acquire(ctx, sem); err != nil {
		return nil, err
	}
	defer func() { <-sem }()
	if err := acquire(ctx, c.global); err != nil {
		return nil, err
	}
	defer func() { <-c.global }()
	if err := c.waitRate(ctx); err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	c.tcpReqs.Add(1)
	conn, err := c.dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.options.Timeout))
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return nil, fmt.Errorf("tcp write failed: %w", err)
		}
	}
	buf := make([]byte, 0, limit)
	tmp := make([]byte, 4096)
	for len(buf) < limit {
		n, err := conn.Read(tmp)
		if n > 0 {
			room := limit - len(buf)
			if n > room {
				n = room
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break // EOF, deadline, or reset — return what we have
		}
	}
	return buf, nil
}

func (c *Client) Close() { c.transport.CloseIdleConnections() }

func acquire(ctx context.Context, sem chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) waitRate(ctx context.Context) error {
	if c.options.Rate == 0 {
		return ctx.Err()
	}
	if err := acquire(ctx, c.rateGate); err != nil {
		return err
	}
	defer func() { <-c.rateGate }()
	if wait := time.Until(c.next); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.next = time.Now().Add(time.Duration(float64(time.Second) / c.options.Rate))
	return ctx.Err()
}

// Get sends one GET to the target origin and never follows redirects. rawPath
// preserves the original request target, including CVE-2021-42013's %% encoding.
func (c *Client) Get(ctx context.Context, target model.Target, rawPath string) (Response, error) {
	return c.do(ctx, target, http.MethodGet, rawPath, "", nil, model.CapHTTPGet)
}

// Post sends one POST with an optional body and never follows redirects. It is
// for detection-only checkers that need a safe, non-destructive probe; the
// caller must ensure the request cannot change server state. It requires the
// CapHTTPPost capability, which only active-probe mode grants.
func (c *Client) Post(ctx context.Context, target model.Target, rawPath, contentType string, body []byte) (Response, error) {
	return c.do(ctx, target, http.MethodPost, rawPath, contentType, body, model.CapHTTPPost)
}

// Options sends one OPTIONS request. OPTIONS is safe and non-mutating, so it is
// gated by the same capability as GET; checkers use it to read a resource's Allow
// methods without changing state.
func (c *Client) Options(ctx context.Context, target model.Target, rawPath string) (Response, error) {
	return c.do(ctx, target, http.MethodOptions, rawPath, "", nil, model.CapHTTPGet)
}

func (c *Client) do(ctx context.Context, target model.Target, method, rawPath, contentType string, body []byte, requiredCap model.Capability) (Response, error) {
	if err := c.policy.CheckTarget(target); err != nil {
		return Response{}, err
	}
	if err := c.policy.CheckCapabilities(requiredCap); err != nil {
		return Response{}, err
	}
	// The path may carry a query string ("/app?service=page/SetupCompleted") for
	// products whose routing is query-based; it flows through URL.Opaque into the
	// request line verbatim (see below). A fragment or backslash is still refused,
	// and the ASCII check below rejects spaces/control bytes, so a query must be
	// percent-encoded.
	if !strings.HasPrefix(rawPath, "/") || strings.HasPrefix(rawPath, "//") || strings.ContainsAny(rawPath, "\\#") {
		return Response{}, errors.New("request path must be an origin-relative path (query allowed, no fragment)")
	}
	for _, b := range []byte(rawPath) {
		if b <= 32 || b >= 127 {
			return Response{}, errors.New("request path must be ASCII without control characters (percent-encode Unicode)")
		}
	}
	resp := Response{URL: target.Origin() + rawPath}
	c.mu.Lock()
	sem := c.hosts[target.Host]
	if sem == nil {
		sem = make(chan struct{}, c.options.PerHost)
		c.hosts[target.Host] = sem
	}
	c.mu.Unlock()
	if err := acquire(ctx, sem); err != nil {
		return resp, err
	}
	defer func() { <-sem }()
	if err := acquire(ctx, c.global); err != nil {
		return resp, err
	}
	defer func() { <-c.global }()
	if err := c.waitRate(ctx); err != nil {
		return resp, err
	}
	// Request timeout covers DNS, connect, TLS, headers and body. Time waiting for
	// the concurrency/rate budget only consumes the scan's parent context.
	requestCtx, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(requestCtx, method, target.Origin()+"/", reader)
	if err != nil {
		return resp, err
	}
	req.URL.Opaque = rawPath
	if c.forwardProxy && target.Scheme == "http" {
		// Forward proxies use absolute-form; direct and CONNECT requests use
		// origin-form. URL.Host still controls the actual connection destination.
		req.URL.Opaque = "//" + req.URL.Host + rawPath
	}
	req.URL.Path = ""
	req.Header.Set("User-Agent", c.options.UserAgent)
	req.Header.Set("Accept", "*/*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c.httpReqs.Add(1)
	r, err := c.http.Do(req)
	if err != nil {
		return resp, fmt.Errorf("HTTP %s failed: %w", method, err)
	}
	defer r.Body.Close()
	resp.StatusCode, resp.Location = r.StatusCode, r.Header.Get("Location")
	// Capture all response headers except cookies (deliberately excluded), so
	// fingerprint checkers can read product headers (e.g. MicrosoftSharePoint-
	// TeamServices). Bounded in count and value length to keep reports small.
	resp.Headers = map[string]string{}
	const maxHeaders = 64
	for key, values := range r.Header {
		if key == "Set-Cookie" || key == "Cookie" || len(values) == 0 {
			continue
		}
		if len(resp.Headers) >= maxHeaders {
			break
		}
		value := values[0]
		if len(value) > 512 {
			value = value[:512]
		}
		resp.Headers[key] = value
	}
	body, readErr := io.ReadAll(io.LimitReader(r.Body, c.options.MaxBodySize+1))
	if int64(len(body)) > c.options.MaxBodySize {
		resp.Truncated = true
		body = body[:c.options.MaxBodySize]
	}
	resp.Body = body
	resp.Bytes = len(body)
	sum := sha256.Sum256(body)
	resp.SHA256 = hex.EncodeToString(sum[:])
	if readErr != nil {
		return resp, fmt.Errorf("reading response: %w", readErr)
	}
	return resp, nil
}

func (c *Client) Fingerprint(ctx context.Context, t model.Target) (Response, error) {
	c.mu.Lock()
	entry, ok := c.cache[t.BaseURL]
	if !ok {
		entry = &cached{done: make(chan struct{})}
		c.cache[t.BaseURL] = entry
	}
	c.mu.Unlock()
	if ok {
		select {
		case <-entry.done:
			return entry.resp, entry.err
		case <-ctx.Done():
			return Response{}, ctx.Err()
		}
	}
	entry.resp, entry.err = c.fingerprint(ctx, t)
	// Retain metadata only: a large target list must not keep one whole response
	// body per target in the shared fingerprint cache.
	entry.resp.Body = nil
	close(entry.done)
	return entry.resp, entry.err
}

func (c *Client) fingerprint(ctx context.Context, t model.Target) (Response, error) {
	current, _ := url.Parse(t.BaseURL)
	for n := 0; ; n++ {
		r, err := c.Get(ctx, t, current.EscapedPath())
		if err != nil || r.Location == "" || !isRedirect(r.StatusCode) || n >= c.options.Redirects {
			return r, err
		}
		next, err := current.Parse(r.Location)
		if err != nil || next.User != nil || next.RawQuery != "" || next.Fragment != "" {
			return r, nil
		}
		nextTarget, err := model.ParseTarget(next.String())
		if err != nil || nextTarget.Origin() != t.Origin() {
			return r, nil
		}
		current, _ = url.Parse(nextTarget.BaseURL)
	}
}

func isRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}
