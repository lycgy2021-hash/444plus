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
// with no second pipeline. v1 is pattern-based on purpose; an AI diff pass
// (ai.TaskDiffAnalysis, later) can enrich the same candidates, never replace this.
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
	CatBoundsCheck       = "added_bounds_check"
	CatAuthCheck         = "added_auth_check"
	CatCanonicalization  = "added_canonicalization"
	CatTypeValidation    = "added_type_validation"
	CatLengthValidation  = "added_length_validation"
	CatDangerousAPIRepl  = "dangerous_api_replaced"
	CatRejectPath        = "added_reject_path"
)

// classifier patterns run against a single changed line. Ordered by priority so a
// line is assigned at most one category (the most specific first).
var addedClassifiers = []struct {
	cat string
	re  *regexp.Regexp
}{
	{CatAuthCheck, regexp.MustCompile(`(?i)authori[sz]|authenticat|permission|is_?admin|require_?auth|access[ _]denied|forbidden|unauthori[sz]ed|check_?auth|has_?role|\bacl\b|403\b|401\b`)},
	{CatCanonicalization, regexp.MustCompile(`(?i)canonical|normali[sz]e|realpath|filepath\.Clean|path\.Clean|os\.path\.realpath|decodeuri|unescape|resolve_?path`)},
	{CatLengthValidation, regexp.MustCompile(`(?i)max_?length|too long|exceeds|length limit|> *max\b|len limit`)},
	{CatBoundsCheck, regexp.MustCompile(`(?i)\bif\b.*(<=|>=|<|>).*(len|size|length|count|cap|bound|index|offset)`)},
	{CatTypeValidation, regexp.MustCompile(`(?i)instanceof|isinstance\(|reflect\.TypeOf|\btypeof\b|schema\.validate|validate_?type`)},
	{CatRejectPath, regexp.MustCompile(`(?i)\bthrow\b|\braise\b|return [^\n]*err|reject\(|\babort\(|\bpanic\(|http\.Error|StatusForbidden|StatusUnauthorized|BadRequest|WriteHeader\((?:400|401|403|404|409|422|500)`)},
}

// dangerousAPI matches a removed line whose disappearance is itself the signal —
// a risky sink being replaced.
var dangerousAPI = regexp.MustCompile(`(?i)system\(|\bexec\(|\beval\(|os/exec|Runtime\.exec|subprocess\.|popen\(|pickle\.loads|yaml\.load\(|ObjectInputStream|innerHTML|dangerouslySetInnerHTML|Deserialize`)

type diffChange struct {
	category string
	line     string
}

// Produce parses a unified diff and returns hypothesis candidates, one per
// (file, category). ref labels the diff (e.g. a commit range) for provenance and
// origin. It never executes anything — it only reads text.
func (p *DiffProducer) Produce(diff []byte, ref string) []*Candidate {
	prov := newProvenance(string(OriginDiff), ref, "git-diff", InputHash(diff))
	origin := Origin{Kind: OriginDiff, ID: ref}

	// perFile[file][category] = sample changed lines.
	perFile := map[string]map[string][]string{}
	record := func(file, cat, line string) {
		if file == "" {
			file = "(unknown)"
		}
		if perFile[file] == nil {
			perFile[file] = map[string][]string{}
		}
		if len(perFile[file][cat]) < 3 { // keep a few samples, not the whole hunk
			perFile[file][cat] = append(perFile[file][cat], strings.TrimSpace(line))
		}
	}

	curFile := ""
	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			curFile = parseDiffPath(line[4:])
			continue
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "diff --git"), strings.HasPrefix(line, "@@"), strings.HasPrefix(line, "index "):
			continue
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "--"):
			if dangerousAPI.MatchString(line) {
				record(curFile, CatDangerousAPIRepl, line)
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "++"):
			if cat := classifyAdded(line); cat != "" {
				record(curFile, cat, line)
			}
		}
	}

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

func classifyAdded(line string) string {
	for _, c := range addedClassifiers {
		if c.re.MatchString(line) {
			return c.cat
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
