package httpx

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopoc/internal/model"
	"gopoc/internal/policy"
	"gopoc/internal/testutil"
)

func testClient(t *testing.T, options Options) *Client {
	t.Helper()
	p, _ := policy.New(model.ModePassive, nil)
	c, err := New(options, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func testTarget(t *testing.T, raw string) model.Target {
	t.Helper()
	target, err := model.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestRedirectScopeAndFingerprintCoalescing(t *testing.T) {
	var outside, hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outside.Add(1) }))
	defer other.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/inside")
			w.WriteHeader(302)
			return
		}
		w.Header().Set("Location", other.URL)
		w.Header().Set("Server", "Apache/2.4.49")
		w.WriteHeader(302)
	}))
	defer s.Close()
	opts := Defaults()
	opts.Rate = 0
	c := testClient(t, opts)
	target := testTarget(t, s.URL)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.Fingerprint(context.Background(), target)
			if err != nil || r.StatusCode != 302 || r.Headers["Server"] != "Apache/2.4.49" {
				t.Errorf("unexpected fingerprint: %+v, %v", r, err)
			}
		}()
	}
	wg.Wait()
	if outside.Load() != 0 || hits.Load() != 2 {
		t.Fatalf("outside=%d local=%d", outside.Load(), hits.Load())
	}
}

func TestBodyLimitAfterDecompressionAndTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(strings.Repeat("a", 4096)))
		_ = gz.Close()
	}))
	defer s.Close()
	opts := Defaults()
	opts.Rate = 0
	opts.MaxBodySize = 64
	opts.Timeout = 100 * time.Millisecond
	c := testClient(t, opts)
	target := testTarget(t, s.URL)
	r, err := c.Get(context.Background(), target, "/")
	if err != nil || !r.Truncated || len(r.Body) != 64 {
		t.Fatalf("body limit failed: %+v %v", r, err)
	}
	if _, err := c.Get(context.Background(), target, "/slow"); err == nil {
		t.Fatal("timeout was not enforced")
	}
}

func TestRawPathAndRejectOriginEscape(t *testing.T) {
	var hits atomic.Int32
	const path = "/canary-alias/.%%32%65/tmp/gopoc.txt"
	s := testutil.NewRawServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.RequestURI != path {
			t.Errorf("got RequestURI %q", r.RequestURI)
		}
	}))
	defer s.Close()
	opts := Defaults()
	opts.Rate = 0
	c := testClient(t, opts)
	target := testTarget(t, s.URL)
	if _, err := c.Get(context.Background(), target, path); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"//another-host/file", "http://host/", "/file\r\nX: value", "/a?query", "/a#fragment", "/\\host/file", "/space here"} {
		if _, err := c.Get(context.Background(), target, path); err == nil {
			t.Errorf("accepted unsafe path %q", path)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("unexpected outbound requests: %d", hits.Load())
	}
}

func TestRateConcurrencyAndCancellation(t *testing.T) {
	var inFlight, peak atomic.Int32
	var mu sync.Mutex
	var starts []time.Time
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		defer inFlight.Add(-1)
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		time.Sleep(90 * time.Millisecond)
	}))
	defer s.Close()
	opts := Defaults()
	opts.Rate = 20
	opts.PerHost = 2
	opts.Concurrency = 3
	c := testClient(t, opts)
	target := testTarget(t, s.URL)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), target, "/"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatalf("per-host limit exceeded: %d", peak.Load())
	}
	if len(starts) != 5 || starts[len(starts)-1].Sub(starts[0]) < 170*time.Millisecond {
		t.Fatalf("rate limit not enforced: %v", starts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Get(ctx, target, "/"); err == nil {
		t.Fatal("cancelled request accepted")
	}
}

func TestTLSVerificationAndExplicitProxy(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer s.Close()
	opts := Defaults()
	opts.Rate = 0
	c := testClient(t, opts)
	if _, err := c.Get(context.Background(), testTarget(t, s.URL), "/"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	opts.InsecureTLS = true
	c = testClient(t, opts)
	if _, err := c.Get(context.Background(), testTarget(t, s.URL), "/"); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	proxy := testutil.NewRawServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.RequestURI != "http://test.invalid/canary/.%%32%65/file" {
			t.Errorf("proxy path changed: %s", r.RequestURI)
		}
	}))
	defer proxy.Close()
	opts.Proxy = proxy.URL
	c = testClient(t, opts)
	if _, err := c.Get(context.Background(), testTarget(t, "http://test.invalid"), "/canary/.%%32%65/file"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatal("explicit proxy not used")
	}
}
