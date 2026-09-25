package apache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
	"gopoc/internal/testutil"
)

func probeFor(t *testing.T, url string, mode model.Mode, maxBody int64) (*httpx.Client, model.Target) {
	t.Helper()
	p, err := policy.New(mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := httpx.Defaults()
	opts.Rate = 0
	if maxBody != 0 {
		opts.MaxBodySize = maxBody
	}
	c, err := httpx.New(opts, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	target, err := model.ParseTarget(url)
	if err != nil {
		t.Fatal(err)
	}
	return c, target
}

func TestVersionMatrixAndSharedFingerprint(t *testing.T) {
	cases := []struct {
		banner         string
		v41773, v42013 model.Verdict
	}{
		{"Apache/2.4.49", model.VerdictDetected, model.VerdictDetected},
		{"Apache/2.4.50 (Unix)", model.VerdictNotFound, model.VerdictDetected},
		{"Apache/2.4.51", model.VerdictNotFound, model.VerdictNotFound},
		{"Apache/2.4.48", model.VerdictNotFound, model.VerdictNotFound},
		{"Apache", model.VerdictUnknown, model.VerdictUnknown},
		{"nginx/1.20", model.VerdictUnknown, model.VerdictUnknown},
		{"", model.VerdictUnknown, model.VerdictUnknown},
		{"NotApache/2.4.49", model.VerdictUnknown, model.VerdictUnknown},
		{"Apache/2.4.49.1", model.VerdictUnknown, model.VerdictUnknown},
		{"Apache/2.4.49 Apache/2.4.51", model.VerdictUnknown, model.VerdictUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.banner, func(t *testing.T) {
			var hits atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Method != "GET" || r.RequestURI != "/" {
					t.Errorf("unexpected probe: %s %s", r.Method, r.RequestURI)
				}
				w.Header().Set("Server", tc.banner)
				w.Header().Set("Set-Cookie", "private=secret")
			}))
			defer s.Close()
			client, target := probeFor(t, s.URL, model.ModePassive, 0)
			checks := []model.Checker{NewCVE202141773(client, model.ModePassive, model.CanaryConfig{}), NewCVE202142013(client, model.ModePassive, model.CanaryConfig{})}
			for i, want := range []model.Verdict{tc.v41773, tc.v42013} {
				f := checks[i].Check(context.Background(), target)
				if f.Verdict != want {
					t.Fatalf("%s: got %s, want %s: %+v", checks[i].ID(), f.Verdict, want, f)
				}
				if f.Evidence.Headers["Set-Cookie"] != "" {
					t.Fatal("cookie leaked to evidence")
				}
			}
			if hits.Load() != 1 {
				t.Fatalf("fingerprint not reused: %d requests", hits.Load())
			}
		})
	}
}

func TestCanaryControlsAndRawEncoding(t *testing.T) {
	canary := model.CanaryConfig{AliasPath: "/canary-alias/", TraversalDepth: 4, FilePath: "/tmp/gopoc-canary.txt", Expected: "GOPOC-TEST-7f732a64"}
	for _, id := range []string{"CVE-2021-41773", "CVE-2021-42013"} {
		for _, behavior := range []string{"confirmed", "hidden_version", "public", "catchall", "missing_echo", "truncated", "probe_404", "control_500", "redirect", "partial_match"} {
			t.Run(id+"/"+behavior, func(t *testing.T) {
				segment := ".%2e/"
				if id == "CVE-2021-42013" {
					segment = ".%%32%65/"
				}
				expectedPath := "/canary-alias/" + strings.Repeat(segment, 4) + "tmp/gopoc-canary.txt"
				var actualProbe atomic.Int32
				s := testutil.NewRawServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if behavior != "hidden_version" {
						w.Header().Set("Server", "Apache/2.4.49")
					}
					if r.RequestURI == "/" {
						return
					}
					if behavior == "catchall" {
						_, _ = w.Write([]byte(canary.Expected))
						return
					}
					if r.RequestURI == canary.FilePath {
						switch behavior {
						case "public":
							_, _ = w.Write([]byte(canary.Expected))
							return
						case "control_500":
							w.WriteHeader(500)
							return
						}
						w.WriteHeader(404)
						return
					}
					if strings.HasPrefix(r.RequestURI, expectedPath+".gopoc-missing-") {
						if behavior == "missing_echo" {
							_, _ = w.Write([]byte(canary.Expected))
							return
						}
						w.WriteHeader(404)
						return
					}
					if r.RequestURI != expectedPath {
						t.Errorf("raw path was changed: %s", r.RequestURI)
						w.WriteHeader(400)
						return
					}
					actualProbe.Add(1)
					switch behavior {
					case "probe_404":
						w.WriteHeader(404)
					case "redirect":
						w.Header().Set("Location", "/exposed")
						w.WriteHeader(302)
					case "truncated":
						_, _ = w.Write([]byte(canary.Expected + strings.Repeat("\n", 100)))
					case "partial_match":
						_, _ = w.Write([]byte("before " + canary.Expected + " after"))
					default:
						_, _ = w.Write([]byte(canary.Expected + "\n"))
					}
				}))
				defer s.Close()
				maxBody := int64(0)
				if behavior == "truncated" {
					maxBody = int64(len(canary.Expected))
				}
				client, target := probeFor(t, s.URL, model.ModeActiveCanary, maxBody)
				var c model.Checker = NewCVE202141773(client, model.ModeActiveCanary, canary)
				if id == "CVE-2021-42013" {
					c = NewCVE202142013(client, model.ModeActiveCanary, canary)
				}
				f := c.Check(context.Background(), target)
				want := model.VerdictDetected
				if behavior == "confirmed" || behavior == "hidden_version" {
					want = model.VerdictConfirmed
				}
				if f.Verdict != want {
					t.Fatalf("got %s, want %s: %+v", f.Verdict, want, f)
				}
				if want == model.VerdictConfirmed {
					// positive probe is repeated twice; observations = fingerprint + 2 positive + 2 controls
					if actualProbe.Load() != 2 || len(f.Evidence.Observations) != 5 {
						t.Fatalf("incomplete confirmation: probes=%d obs=%d %+v", actualProbe.Load(), len(f.Evidence.Observations), f)
					}
					if !f.Evidence.Confirmation.Passed() {
						t.Fatalf("confirmed without passing confirmation: %+v", f.Evidence.Confirmation)
					}
				}
			})
		}
	}
}
