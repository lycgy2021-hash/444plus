package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"gopoc/internal/model"
	"gopoc/internal/report"
)

func TestCLIEndToEndAndOutputIsolation(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Header().Set("Server", "Apache/2.4.50") }))
	defer s.Close()
	dir := t.TempDir()
	targetsFile := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsFile, []byte("\ufeff# test targets\n"+s.URL+"\n"+s.URL+"/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"scan", "--targets", targetsFile, "--target", s.URL, "--rate", "0", "--json", "-", "--sqlite", filepath.Join(dir, "scan.db")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not pure JSON: %s: %v", stdout.String(), err)
	}
	if len(result.Targets) != 1 || len(result.Findings) != 31 || result.Findings[0].Verdict != model.VerdictNotFound || result.Findings[1].Verdict != model.VerdictDetected {
		t.Fatalf("unexpected result %+v, hits %d", result, hits.Load())
	}
	firstHits := hits.Load()
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"scan", "-u", s.URL, "--allow", "outside.invalid", "--rate", "0", "--json", "-"}, &stdout, &stderr)
	if code != 0 || hits.Load() != firstHits {
		t.Fatalf("blocked scan made requests or failed: %s", stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Findings[0].Reason != "policy_blocked" {
		t.Fatalf("missing blocked finding: %s", stdout.String())
	}
}

func TestCLIRejectsInvalidArgumentsBeforeRequests(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer s.Close()
	for _, extra := range [][]string{{"--mode", "active-canary"}, {"--cve", "CVE-NOT-REAL"}, {"--rate", "-1"}, {"--product", "unknown"}, {"--per-host", "0"}} {
		var out, err bytes.Buffer
		args := append([]string{"scan", "-u", s.URL}, extra...)
		if run(context.Background(), args, &out, &err) != 1 {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("invalid arguments caused network requests")
	}
}

func TestCLIActiveConfigurationAndCancellationReport(t *testing.T) {
	const token = "GOPOC-TEST-e81d5ce2"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49")
		if r.RequestURI == "/" {
			return
		}
		if strings.Contains(r.RequestURI, ".%2e/") && !strings.Contains(r.RequestURI, "gopoc-missing-") {
			_, _ = w.Write([]byte(token))
			return
		}
		w.WriteHeader(404)
	}))
	defer s.Close()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "canary.yaml")
	if err := os.WriteFile(cfg, []byte("http:\n  rate: 0\nactive:\n  enabled: true\n  canary:\n    file_path: /tmp/gopoc-canary.txt\n    expected: "+token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"scan", "--config", cfg, "--mode", "active-canary", "-u", s.URL, "-id", "CVE-2021-41773", "--json", "-"}
	if code := run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Findings[0].Verdict != model.VerdictConfirmed {
		t.Fatalf("canary not confirmed: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := run(ctx, []string{"scan", "-u", s.URL, "--rate", "0", "--json", "-"}, &stdout, &stderr); code != 130 {
		t.Fatalf("cancel code %d: %s", code, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || !result.Cancelled || len(result.Findings) != 31 || result.Findings[0].Reason != "cancelled" {
		t.Fatalf("partial report invalid: %s", stdout.String())
	}
}

func TestReportsNeverOverwriteInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputs(path, "", "unused"); err == nil {
		t.Fatal("existing JSON accepted")
	}
	if err := validateOutputs("-", path, path); err == nil {
		t.Fatal("SQLite output aliasing input accepted")
	}
	if err := writeJSON(path, &bytes.Buffer{}, report.Report{}); err == nil {
		t.Fatal("overwritten existing JSON")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("input changed: %s %v", data, err)
	}
}
