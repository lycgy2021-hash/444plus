package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"gopoc/checks"
	"gopoc/internal/assesscache"
	"gopoc/internal/config"
	"gopoc/internal/engine"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/policy"
	"gopoc/internal/registry"
	"gopoc/internal/report"
)

const version = "0.1.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	var err error
	switch args[0] {
	case "help", "--help", "-h":
		usage(stdout)
	case "version", "--version":
		fmt.Fprintln(stdout, "gopoc "+version)
	case "list":
		err = list(args[1:], stdout, stderr)
	case "scan":
		err = scan(ctx, args[1:], stdout, stderr)
	default:
		err = fmt.Errorf("unknown command %q (use gopoc help)", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 130
		}
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `gopoc - extensible HTTP vulnerability scanner

Usage:
  gopoc list [--product apache] [--severity critical] [--json]
  gopoc scan --target URL [--cve CVE-ID] [--json report.json] [--sqlite scans.db]
  gopoc scan --targets targets.txt --product apache
  gopoc scan --target URL --mode active-canary --config canary.yaml

Use 'gopoc scan --help' for flags. Default mode: passive.
JSON goes to stdout unless --json names a file. Diagnostics go to stderr.`)
}

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func flatten(values []string) []string {
	var out []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			out = append(out, strings.TrimSpace(item))
		}
	}
	return out
}

func addFilter(fs *flag.FlagSet, ids *stringsFlag, product, severity *string) {
	fs.Var(ids, "cve", "CVE ID (repeatable or comma-separated)")
	fs.Var(ids, "id", "alias for --cve")
	fs.StringVar(product, "product", "", "filter by product")
	fs.StringVar(severity, "severity", "", "filter by severity")
}

func list(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var ids stringsFlag
	var product, severity string
	addFilter(fs, &ids, &product, &severity)
	asJSON := fs.Bool("json", false, "output checker metadata as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("list takes flags only")
	}
	r, err := checks.Builtin(nil, model.ModePassive, model.CanaryConfig{})
	if err != nil {
		return err
	}
	selected, err := r.Select(registry.Filter{IDs: flatten(ids), Product: product, Severity: severity})
	if err != nil {
		return err
	}
	if *asJSON {
		meta := []model.Metadata{}
		for _, c := range selected {
			meta = append(meta, c.Metadata())
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(meta)
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRODUCT\tSEVERITY\tNAME")
	for _, c := range selected {
		m := c.Metadata()
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.ID, m.Product, m.Severity, m.Name)
	}
	return tw.Flush()
}

func configPath(args []string) (string, error) {
	var path string
	for i := 0; i < len(args); i++ {
		arg := strings.TrimPrefix(args[i], "-")
		if arg == "-config" || arg == "config" {
			i++
			if i == len(args) {
				return "", errors.New("--config requires a filename")
			}
			path = args[i]
		} else if strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "config=") {
			path = strings.SplitN(arg, "=", 2)[1]
		}
	}
	return path, nil
}

func scan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfgPath, err := configPath(args)
	if err != nil {
		return err
	}
	cfg := config.Defaults()
	if cfgPath != "" {
		cfg, err = config.Load(cfgPath)
		if err != nil {
			return err
		}
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var rawTargets, ids, allowlist stringsFlag
	var product, severity, targetsFile, jsonPath, sqlitePath, modeValue string
	var scanTimeout time.Duration
	fs.Var(&rawTargets, "target", "target HTTP(S) URL (repeatable)")
	fs.Var(&rawTargets, "u", "alias for --target")
	fs.StringVar(&targetsFile, "targets", "", "file with one target URL per line")
	addFilter(fs, &ids, &product, &severity)
	fs.StringVar(&cfgPath, "config", cfgPath, "strict YAML configuration file")
	fs.StringVar(&modeValue, "mode", string(model.ModePassive), "passive, active-canary or active-probe")
	fs.Var(&allowlist, "allow", "additional allowlist entry (repeatable)")
	fs.StringVar(&jsonPath, "json", "", "write machine-readable JSON to a filename or - for stdout (default: human report only)")
	fs.StringVar(&jsonPath, "o", "", "alias for --json")
	fs.StringVar(&sqlitePath, "sqlite", "", "append scan to a SQLite database")
	var evidence bool
	fs.BoolVar(&evidence, "evidence", false, "print a human-readable evidence block per finding on stderr")
	fs.BoolVar(&evidence, "v", false, "alias for --evidence")
	var discover bool
	fs.BoolVar(&discover, "discover", false, "identify each target's product(s) first and run only the relevant checkers")
	fs.DurationVar(&cfg.HTTP.Timeout, "timeout", cfg.HTTP.Timeout, "network timeout per request")
	fs.DurationVar(&scanTimeout, "scan-timeout", 0, "total scan deadline (0 disables)")
	fs.IntVar(&cfg.HTTP.Concurrency, "concurrency", cfg.HTTP.Concurrency, "worker count and maximum in-flight requests")
	fs.IntVar(&cfg.HTTP.PerHost, "per-host", cfg.HTTP.PerHost, "maximum in-flight requests per hostname")
	fs.Float64Var(&cfg.HTTP.Rate, "rate", cfg.HTTP.Rate, "global requests/second (0 disables)")
	fs.Int64Var(&cfg.HTTP.MaxBodySize, "max-body", cfg.HTTP.MaxBodySize, "maximum response body bytes")
	fs.IntVar(&cfg.HTTP.Redirects, "redirects", cfg.HTTP.Redirects, "maximum same-origin fingerprint redirects")
	fs.StringVar(&cfg.HTTP.UserAgent, "user-agent", cfg.HTTP.UserAgent, "HTTP User-Agent")
	fs.StringVar(&cfg.HTTP.Proxy, "proxy", cfg.HTTP.Proxy, "explicit HTTP(S) or SOCKS5 proxy URL")
	fs.StringVar(&cfg.HTTP.DNS, "dns", cfg.HTTP.DNS, "custom DNS resolver host:port")
	fs.BoolVar(&cfg.HTTP.InsecureTLS, "insecure", cfg.HTTP.InsecureTLS, "disable TLS certificate verification")
	// Parse in a loop so flags and positional targets may be interspersed, e.g.
	// `gopoc scan 10.0.0.8 --discover`. Positional arguments are targets.
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if scanTimeout < 0 {
		return errors.New("negative scan timeout")
	}
	rawTargets = append(rawTargets, positional...)
	mode := model.Mode(modeValue)
	if err := cfg.Validate(mode); err != nil {
		return err
	}
	cfg.Allowlist = append(cfg.Allowlist, allowlist...)
	p, err := policy.New(mode, cfg.Allowlist)
	if err != nil {
		return err
	}
	targets, err := readTargets(rawTargets, targetsFile)
	if err != nil {
		return err
	}
	if err := validateOutputs(jsonPath, sqlitePath, cfgPath, targetsFile); err != nil {
		return err
	}
	client, err := httpx.New(cfg.HTTP, p)
	if err != nil {
		return err
	}
	defer client.Close()
	r, err := checks.Builtin(client, mode, cfg.Active.Canary)
	if err != nil {
		return err
	}
	selected, err := r.Select(registry.Filter{IDs: flatten(ids), Product: product, Severity: severity})
	if err != nil {
		return err
	}
	if scanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanTimeout)
		defer cancel()
	}
	// One shared assessment cache for the whole scan (discovery + checkers reuse it).
	cache := assesscache.New()
	ctx = assesscache.With(ctx, cache)
	considered := len(selected)
	discovered := map[string]bool{}
	if discover {
		for _, tgt := range targets {
			d := checks.Discover(ctx, client, tgt)
			for pr := range d.Products {
				discovered[pr] = true
			}
		}
		routed := selected[:0:0]
		for _, c := range selected {
			if discovered[c.Metadata().Product] {
				routed = append(routed, c)
			}
		}
		selected = routed
	}
	result := report.New(mode, targets, selected)
	fmt.Fprintf(stderr, "Scanning %d target(s), %d checker(s), mode=%s\n", len(targets), len(selected), mode)
	e := engine.Engine{Workers: cfg.HTTP.Concurrency, Policy: p}
	findings, scanErr := e.Run(ctx, targets, selected)
	result.Finish(findings, scanErr != nil)
	// An interrupted scan still gets a bounded opportunity to persist its report.
	persistCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var writeErrors []error
	if sqlitePath != "" {
		if err := report.WriteSQLite(persistCtx, sqlitePath, result); err != nil {
			writeErrors = append(writeErrors, fmt.Errorf("SQLite report: %w", err))
		}
	}
	// Output: JSON (machine) goes to stdout or a file only when --json is used;
	// otherwise the clean human report owns stdout. When JSON takes stdout, the
	// human report goes to stderr so a pipe still gets pure JSON.
	humanOut := stdout
	if jsonPath != "" {
		if err := writeJSON(jsonPath, stdout, result); err != nil {
			writeErrors = append(writeErrors, fmt.Errorf("JSON report: %w", err))
		}
		if jsonPath == "-" {
			humanOut = stderr
		}
	}
	httpReqs, tcpReqs := client.Stats()
	renderReport(humanOut, result, reportMeta{
		discover:    discover,
		discovered:  discovered,
		considered:  considered,
		executed:    len(selected),
		httpReqs:    httpReqs,
		tcpReqs:     tcpReqs,
		assessments: cache.Len(),
		verbose:     evidence,
	})
	return errors.Join(append(writeErrors, scanErr)...)
}

type reportMeta struct {
	discover             bool
	discovered           map[string]bool
	considered, executed int
	httpReqs, tcpReqs    int64
	assessments          int
	verbose              bool
}

// renderReport writes the human single-IP report: Target, Discovered, High-Risk
// Findings grouped by action priority, and Scan Quality. not_found/unknown are
// hidden by default (counted in Scan Quality; full data is in --json).
func renderReport(w io.Writer, r report.Report, m reportMeta) {
	product := map[string]string{}
	for _, c := range r.Checks {
		product[c.ID] = c.Product
	}

	for _, t := range r.Targets {
		fmt.Fprintf(w, "Target: %s\n", t.BaseURL)
	}

	if m.discover {
		fmt.Fprintln(w, "\nDiscovered")
		if len(m.discovered) == 0 {
			fmt.Fprintln(w, "  (no known product identified)")
		}
		for _, prod := range sortedKeys(m.discovered) {
			ver, surface := productSummary(r, prod)
			line := "  - " + prod
			if ver != "" {
				line += " " + ver
			}
			fmt.Fprintln(w, line)
			if surface != "" {
				fmt.Fprintln(w, "      dangerous surface: "+surface)
			}
		}
	}

	immediate := findingsBy(r, model.VerdictConfirmed, model.VerdictLikely)
	review := findingsBy(r, model.VerdictDetected)
	issues := findingsBy(r, model.VerdictError)
	fmt.Fprintln(w, "\nHigh-Risk Findings")
	if len(immediate)+len(review)+len(issues) == 0 {
		fmt.Fprintln(w, "  none")
	}
	renderGroup(w, "Immediate attention", immediate, product, m.verbose)
	renderGroup(w, "Review", review, product, m.verbose)
	renderGroup(w, "Scanner issues", issues, product, m.verbose)

	fmt.Fprintln(w, "\nScan Quality")
	if m.discover {
		fmt.Fprintf(w, "  Routing: %d considered, %d executed, %d skipped\n", m.considered, m.executed, m.considered-m.executed)
	}
	fmt.Fprintf(w, "  Requests: HTTP=%d TCP=%d\n", m.httpReqs, m.tcpReqs)
	fmt.Fprintf(w, "  Shared assessments: %d\n", m.assessments)
	fmt.Fprintf(w, "  Hidden (see --json): not_found=%d unknown=%d\n",
		r.Summary[model.VerdictNotFound], r.Summary[model.VerdictUnknown])
}

func renderGroup(w io.Writer, title string, fs []model.Finding, product map[string]string, verbose bool) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s\n", title)
	for _, f := range fs {
		fmt.Fprintf(w, "    [%s] %s %s (confidence=%d)\n", strings.ToUpper(string(f.Verdict)), f.ID, product[f.ID], f.Confidence)
		if verbose {
			renderEvidence(w, f)
		}
	}
}

func findingsBy(r report.Report, verdicts ...model.Verdict) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		for _, v := range verdicts {
			if f.Verdict == v {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// productSummary returns the version and a dangerous-surface label from the
// strongest finding (likely over detected) for a product.
func productSummary(r report.Report, prod string) (version, surface string) {
	id2prod := map[string]string{}
	for _, c := range r.Checks {
		id2prod[c.ID] = c.Product
	}
	best := model.Verdict("")
	rank := map[model.Verdict]int{model.VerdictDetected: 1, model.VerdictLikely: 2, model.VerdictConfirmed: 3}
	for _, f := range r.Findings {
		if id2prod[f.ID] != prod {
			continue
		}
		if f.Evidence.Version != "" && version == "" {
			version = f.Evidence.Version
		}
		if rank[f.Verdict] > rank[best] {
			best = f.Verdict
			surface = surfaceLabel(f.Reason)
		}
	}
	return version, surface
}

func surfaceLabel(reason string) string {
	switch reason {
	case "writable_default_servlet":
		return "writable DefaultServlet"
	case "dangerous_protocol_exposed":
		return "T3/IIOP exposed"
	case "admission_webhook_exposed":
		return "admission webhook reachable"
	case "affected_and_exposed":
		return "management/portal surface exposed"
	case "toolshell_surface_exposed":
		return "ToolPane.aspx reachable"
	case "unauthenticated_restore":
		return "unauthenticated restore endpoint"
	case "weblogic_routing_confirmed":
		return "active WebLogic routing"
	case "affected_service_exposed":
		return "Gateway/AAA service face exposed"
	case "canary_verified":
		return "path traversal file read"
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func renderEvidence(w io.Writer, f model.Finding) {
	if f.Evidence.Version != "" {
		fmt.Fprintf(w, "  version: %s\n", f.Evidence.Version)
	}
	if c := f.Evidence.Confirmation; c != nil {
		fmt.Fprintln(w, "  confirmation:")
		fmt.Fprintf(w, "    positive: %s %d/%d\n", pass(c.PositivePasses >= c.PositiveNeeded), c.PositivePasses, c.PositiveNeeded)
		fmt.Fprintf(w, "    negative: %s %d/%d\n", pass(c.NegativePasses >= c.NegativeNeeded), c.NegativePasses, c.NegativeNeeded)
		fmt.Fprintf(w, "    diff:     %s\n", pass(c.DiffMatched))
		fmt.Fprintf(w, "    repeat:   %s\n", pass(c.RepeatOK))
		for _, s := range c.Steps {
			mark := "-"
			if s.Matched {
				mark = "+"
			}
			fmt.Fprintf(w, "    [%s] %-8s %-15s status=%d matched=%v (%s: %s)\n", mark, s.Role, s.Kind, s.Status, s.Matched, s.Matcher, s.Detail)
		}
	} else if f.Verdict == model.VerdictDetected {
		fmt.Fprintln(w, "  confirmation: [ ] behavioral evidence unavailable (version match only)")
	}
	if f.Reason != "" {
		fmt.Fprintf(w, "  reason: %s\n", f.Reason)
	}
	if f.Evidence.Message != "" {
		fmt.Fprintf(w, "  detail: %s\n", f.Evidence.Message)
	}
}

func pass(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func readTargets(raw []string, path string) ([]model.Target, error) {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
			if line != "" && !strings.HasPrefix(line, "#") {
				raw = append(raw, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("specify --target or --targets")
	}
	seen := map[string]bool{}
	targets := []model.Target{}
	for i, value := range raw {
		// Accept a bare IP/host (single-IP mode): default to http://.
		if !strings.Contains(value, "://") {
			value = "http://" + value
		}
		t, err := model.ParseTarget(value)
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", i+1, err)
		}
		if !seen[t.BaseURL] {
			seen[t.BaseURL] = true
			targets = append(targets, t)
		}
	}
	return targets, nil
}

func validateOutputs(jsonPath, sqlitePath string, inputs ...string) error {
	// jsonPath "" means no JSON output (human report only), which is the default.
	for _, output := range []string{jsonPath, sqlitePath} {
		if output == "" || output == "-" {
			continue
		}
		abs, err := filepath.Abs(output)
		if err != nil {
			return err
		}
		for _, input := range inputs {
			if input == "" {
				continue
			}
			inputAbs, _ := filepath.Abs(input)
			inInfo, inErr := os.Stat(input)
			outInfo, outErr := os.Stat(output)
			if strings.EqualFold(abs, inputAbs) || inErr == nil && outErr == nil && os.SameFile(inInfo, outInfo) {
				return errors.New("report output must not overwrite an input file")
			}
		}
	}
	if jsonPath != "" && jsonPath != "-" {
		if _, err := os.Stat(jsonPath); err == nil {
			return fmt.Errorf("JSON report already exists: %s", jsonPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if sqlitePath != "" {
			a, _ := filepath.Abs(jsonPath)
			b, _ := filepath.Abs(sqlitePath)
			if strings.EqualFold(a, b) {
				return errors.New("JSON and SQLite output must use different files")
			}
		}
	}
	return nil
}

func writeJSON(path string, stdout io.Writer, r report.Report) error {
	if path == "-" {
		return report.WriteJSON(stdout, r)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = report.WriteJSON(f, r)
	return errors.Join(err, f.Close())
}
