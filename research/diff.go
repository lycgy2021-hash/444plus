package research

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DiffProducer (S6 v1) is a deterministic, non-AI research producer: it reads a
// unified git diff and classifies security-relevant ADDED changes — a new bounds
// check, auth check, canonicalization, type/length validation, a replaced
// dangerous API, or a new reject/error path — into hypothesis Candidates tagged
// Origin{Kind: "diff"}. It proves the spine is producer-agnostic: these
// candidates flow into the same Registry → Validator → Engine path as AI ones,
// with no second pipeline. v1 is pattern-based on purpose, but the patterns match
// code SHAPE (a call, a comparison, an if-guard, a status response), not bare
// keywords, and comment/blank lines are skipped — so a security word in prose or
// a log line does not manufacture a candidate. An AI diff pass (later) can enrich
// these same candidates, never replace this deterministic classification.
type DiffProducer struct {
	newID func() string
}

func NewDiffProducer() *DiffProducer {
	return &DiffProducer{newID: SequentialIDs(time.Now().UTC().Year())}
}

// WithIDFunc overrides the id generator (stable ids in tests).
func (p *DiffProducer) WithIDFunc(fn func() string) *DiffProducer {
	p.newID = fn
	return p
}

// Security-relevant change categories. Each is a candidate_type; a later diff
// validator can decide how to test one.
const (
	CatBoundsCheck      = "added_bounds_check"
	CatAuthCheck        = "added_auth_check"
	CatCanonicalization = "added_canonicalization"
	CatTypeValidation   = "added_type_validation"
	CatLengthValidation = "added_length_validation"
	CatDangerousAPIRepl = "dangerous_api_replaced"
	CatRejectPath       = "added_reject_path"
)

// addedClassifiers run against a changed line's CODE (marker + leading whitespace
// stripped, comments skipped). Ordered by priority so a line is assigned at most
// one category (most specific first). Every pattern requires a code shape — a
// call `(`, a comparison operator, an `if` guard, or an HTTP status response —
// not a lone keyword, which is what kept the old auth/length/reject/normalize
// patterns from over-matching prose.
var addedClassifiers = []struct {
	cat string
	res []*regexp.Regexp
}{
	{CatAuthCheck, []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(authori[sz]e|authenticate|require_?auth|check_?auth|check_?permission|ensure_?auth|has_?role|has_?permission|is_?admin)\s*\(`),
		regexp.MustCompile(`(?i)\bif\b.{0,80}\b(permission|role|auth|admin|forbidden|unauthori[sz]ed|access[ _]denied)\b`),
		regexp.MustCompile(`(?i)(status\s*forbidden|status\s*unauthorized|writeheader\(\s*40[13]\b|http\.error\([^)]*(forbidden|unauthor)|res\.status\(\s*40[13]\b|sendstatus\(\s*40[13]\b|abort\(\s*40[13]\b)`),
	}},
	{CatCanonicalization, []*regexp.Regexp{
		regexp.MustCompile(`(?i)(filepath\.clean\(|[^a-z]path\.clean\(|^path\.clean\(|realpath\(|os\.path\.realpath\(|\.normali[sz]e\(|canonicali[sz]e\(|canonical_?path\(|decodeuricomponent\(|securejoin\()`),
	}},
	{CatLengthValidation, []*regexp.Regexp{
		regexp.MustCompile(`(?i)(max_?length\b|maxlen\b|\blen\([^)]*\)\s*(>=|>|<)|\.length\s*(>=|>|<)|\.size\(\)\s*(>=|>|<)|length limit|size limit)`),
	}},
	{CatBoundsCheck, []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bif\b.{0,80}(<=|>=|<|>).{0,40}\b(len|size|length|cap|bound|index|offset)`),
		regexp.MustCompile(`(?i)\bif\b.{0,80}\b(len|size|length|cap|bound|index|offset).{0,40}(<=|>=|<|>)`),
	}},
	{CatTypeValidation, []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\binstanceof\b|isinstance\(|reflect\.typeof\(|\btypeof\s|\.\(type\)|schema\.validate\(|validate_?type\()`),
	}},
	{CatRejectPath, []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\bthrow\s|\braise\s|\bpanic\(|[^a-z]reject\(|\babort\(|http\.error\(|writeheader\(\s*(4\d\d|5\d\d)\b|status\s*(forbidden|unauthorized|badrequest|conflict)|bad_?request)`),
	}},
}

// dangerousAPI matches a REMOVED line whose disappearance is the signal — a risky
// sink in call/assignment form. Requiring the call/assignment shape (not a bare
// word) avoids matching a mention of "eval" in a comment.
var dangerousAPI = regexp.MustCompile(`(?i)(system\(|\bexec\(|\beval\(|os/exec|runtime\.exec\(|subprocess\.(call|run|popen)\(|popen\(|pickle\.loads\(|yaml\.load\(|objectinputstream|\.innerhtml\s*=|dangerouslysetinnerhtml|unserialize\(|[^a-z]deserialize\()`)

// commentPrefixes start a line that is a comment, not code, so it is skipped
// before classification. Bare "*" is intentionally NOT here (it would skip C
// pointer lines); a block-comment continuation is prose and fails the code-shape
// patterns anyway.
var commentPrefixes = []string{"//", "/*", "#", "<!--", `"""`, "'''"}

func isCommentOrBlank(code string) bool {
	if code == "" {
		return true
	}
	for _, p := range commentPrefixes {
		if strings.HasPrefix(code, p) {
			return true
		}
	}
	return false
}

// stripMarker removes a diff line's leading +/- marker and surrounding
// whitespace, yielding the underlying code so patterns anchor on code, not "+".
func stripMarker(line string) string {
	if line == "" {
		return ""
	}
	return strings.TrimSpace(line[1:])
}

// Produce parses a unified diff and returns hypothesis candidates, one per
// (file, category). ref labels the diff (e.g. a commit range) for provenance and
// origin. It never executes anything — it only reads text. Provenance.RawInputHash
// is the byte-for-byte SHA-256 of the diff exactly as given.
func (p *DiffProducer) Produce(diff []byte, ref string) []*Candidate {
	prov := newProvenance(string(OriginDiff), ref, "git-diff", RawInputHash(diff))
	origin := Origin{Kind: OriginDiff, ID: ref}

	// perFile[file][category] = a few sample changed lines.
	perFile := map[string]map[string][]string{}
	record := func(file, cat, code string) {
		if file == "" {
			file = "(unknown)"
		}
		if perFile[file] == nil {
			perFile[file] = map[string][]string{}
		}
		if len(perFile[file][cat]) < 3 {
			perFile[file][cat] = append(perFile[file][cat], code)
		}
	}

	curFile := ""
	// Hunk-scoped state for the dangerous-API PAIR rule: only a removed dangerous
	// API AND an added line in the SAME hunk counts as a replacement.
	hunkRemovedDangerous := ""
	hunkHasAdd := false
	finalizeHunk := func() {
		if hunkRemovedDangerous != "" && hunkHasAdd {
			record(curFile, CatDangerousAPIRepl, hunkRemovedDangerous)
		}
		hunkRemovedDangerous, hunkHasAdd = "", false
	}

	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			finalizeHunk()
			curFile = parseDiffPath(line[4:])
		case strings.HasPrefix(line, "@@"):
			finalizeHunk()
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "diff --git"), strings.HasPrefix(line, "index "):
			// header lines: ignore
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "--"):
			code := stripMarker(line)
			if !isCommentOrBlank(code) && dangerousAPI.MatchString(code) {
				hunkRemovedDangerous = code
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "++"):
			code := stripMarker(line)
			if isCommentOrBlank(code) {
				continue
			}
			hunkHasAdd = true
			if cat := classifyAdded(code); cat != "" {
				record(curFile, cat, code)
			}
		}
	}
	finalizeHunk()

	var candidates []*Candidate
	for _, file := range sortedKeys(perFile) {
		for _, cat := range sortedKeys(perFile[file]) {
			samples := perFile[file][cat]
			title := fmt.Sprintf("%s in %s", cat, file)
			rationale := fmt.Sprintf("Diff %s introduces a security-relevant change (%s) in %s: %s", ref, cat, file, strings.Join(samples, " | "))
			required := []string{"pre_change_behavior", "post_change_behavior"}
			candidates = append(candidates, NewHypothesis(p.newID(), cat, title, "", rationale, origin, required, prov))
		}
	}
	return candidates
}

func classifyAdded(code string) string {
	for _, c := range addedClassifiers {
		for _, re := range c.res {
			if re.MatchString(code) {
				return c.cat
			}
		}
	}
	return ""
}

// parseDiffPath turns a diff header target ("b/pkg/x.go" or "b/pkg/x.go\t...")
// into a clean path, mapping /dev/null to "".
func parseDiffPath(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\t "); i >= 0 {
		s = s[:i]
	}
	if s == "/dev/null" {
		return ""
	}
	s = strings.TrimPrefix(s, "b/")
	s = strings.TrimPrefix(s, "a/")
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
