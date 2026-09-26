package research

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FuzzProducer (S8 v1) turns raw fuzzer crash output into research candidates,
// deterministically and with strict volume control. The pipeline is:
//
//	CrashArtifact → Normalize → CrashSignature → dedup within a FuzzScope into a
//	CrashGroup → deterministic CrashInterest → (only non-noise groups) →
//	hypothesis Candidate{Origin{Kind:"fuzz"}} → the same Registry/Engine spine.
//
// Core principle: a CrashSignature is a crash FINGERPRINT, not a global bug id. A
// CrashGroup is scoped by build/harness (ScopeHash+SignatureHash), and a Candidate
// traces the whole group (GroupHash + member hashes), not one representative crash.
//
// Four distinct hashes, never mixed:
//   - TestcaseHash   — the crashing input bytes
//   - CrashOutputHash — the raw crash output bytes
//   - SignatureHash  — the normalized crash type + access + top stable frames
//   - GroupHash      — ScopeHash + SignatureHash (the group identity)
//
// Classification is deterministic; a later AI pass may explain/enrich/suggest
// merges but never decides a candidate's state.
type FuzzProducer struct {
	newID      func() string
	maxSamples int
	maxMembers int
}

func NewFuzzProducer() *FuzzProducer {
	return &FuzzProducer{newID: SequentialIDs(time.Now().UTC().Year()), maxSamples: 3, maxMembers: 64}
}

// WithIDFunc overrides the id generator (stable ids in tests).
func (p *FuzzProducer) WithIDFunc(fn func() string) *FuzzProducer {
	p.newID = fn
	return p
}

// FuzzScope bounds "same crash?" to one build/harness/fuzzer. Two crashes with an
// identical signature but different BuildID or HarnessID are NOT the same group —
// they are compared only within a scope, never merged across the whole product.
type FuzzScope struct {
	TargetID  string
	BuildID   string
	HarnessID string
	Fuzzer    string
}

func (s FuzzScope) Hash() string {
	return RawInputHash([]byte(s.TargetID + "|" + s.BuildID + "|" + s.HarnessID + "|" + s.Fuzzer))
}

func (s FuzzScope) label() string {
	return fmt.Sprintf("%s@%s/%s", s.TargetID, s.BuildID, s.HarnessID)
}

// CrashArtifact is one raw crash as emitted by the fuzzer.
type CrashArtifact struct {
	RawOutput []byte // the raw crash log / stderr
	Testcase  []byte // optional: the crashing input bytes
	ExitCode  int
	Signal    string
	InputRef  string
}

// CrashOutputHash is the byte-for-byte SHA-256 of the raw crash output.
func (a CrashArtifact) CrashOutputHash() string { return RawInputHash(a.RawOutput) }

// TestcaseHash is the byte-for-byte SHA-256 of the crashing input, or "" when the
// bytes were not provided.
func (a CrashArtifact) TestcaseHash() string {
	if len(a.Testcase) == 0 {
		return ""
	}
	return RawInputHash(a.Testcase)
}

// StableFrame is a run-stable stack frame: function plus source basename (never an
// absolute path) and, where derivable, a module. Addresses/offsets/line numbers
// are excluded so the frame is identical across runs.
type StableFrame struct {
	Module   string `json:"module,omitempty"`
	Function string `json:"function"`
	Source   string `json:"source,omitempty"`
}

func (f StableFrame) key() string { return f.Module + ":" + f.Function + ":" + f.Source }

// CrashSignature is the stable fingerprint of a crash: type + sanitizer access
// facts + top stable frames, hashed. Access type/size are included so two
// independent faults in the SAME function (e.g. a READ-of-1 header overflow vs a
// WRITE-of-4 length overflow) do not collapse into one signature.
type CrashSignature struct {
	Hash       string        `json:"hash"`
	CrashType  string        `json:"crash_type"`
	AccessType string        `json:"access_type,omitempty"`
	AccessSize uint64        `json:"access_size,omitempty"`
	Frames     []StableFrame `json:"frames,omitempty"`
}

// CrashGroupKey identifies a group within the dedup model.
type CrashGroupKey struct {
	ScopeHash     string
	SignatureHash string
}

func (k CrashGroupKey) GroupHash() string {
	return RawInputHash([]byte(k.ScopeHash + "|" + k.SignatureHash))
}

// CrashGroup is a set of artifacts sharing a signature WITHIN a scope. GroupHash
// is derived only from scope+signature, so which sample happens to be first never
// changes the group identity.
type CrashGroup struct {
	Scope             FuzzScope       `json:"scope"`
	GroupHash         string          `json:"group_hash"`
	Signature         CrashSignature  `json:"signature"`
	Interest          CrashInterest   `json:"interest"`
	Count             uint64          `json:"count"`
	MemberCrashHashes []string        `json:"member_crash_hashes,omitempty"` // capped; Count is exact
	Samples           []CrashArtifact `json:"-"`
}

// CrashInterest is the deterministic security-interest classification.
type CrashInterest string

const (
	InterestNoise     CrashInterest = "noise"
	InterestMemory    CrashInterest = "memory_safety"
	InterestPanic     CrashInterest = "panic"
	InterestHang      CrashInterest = "hang"
	InterestResource  CrashInterest = "resource_exhaustion"
	InterestInvariant CrashInterest = "invariant_violation"
	InterestUnknown   CrashInterest = "unknown"
)

// --- normalization ---------------------------------------------------------

var (
	reAddr      = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	reAsanPID   = regexp.MustCompile(`==\d+==`)
	rePID       = regexp.MustCompile(`(?i)\bpid[=: ]+\d+`)
	reThread    = regexp.MustCompile(`(?i)thread T\d+`)
	reTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?`)
	reTmpPath   = regexp.MustCompile(`/tmp/\S+|/var/folders/\S+`)
	reCorpus    = regexp.MustCompile(`crash-[0-9a-f]+|leak-[0-9a-f]+|oom-[0-9a-f]+|(?i)testcase[^ \t\n]*`)
	reLineCol   = regexp.MustCompile(`:\d+(:\d+)?\b`)
	reNumIdx    = regexp.MustCompile(`\[\d+\]|length \d+|len \d+`)
)

// Normalize strips run-specific noise so the same bug across runs normalizes to
// the same text. Used for the fallback signature material and for readable notes.
func Normalize(raw []byte) string {
	s := string(raw)
	s = reAddr.ReplaceAllString(s, "0xADDR")
	s = reAsanPID.ReplaceAllString(s, "==PID==")
	s = rePID.ReplaceAllString(s, "pid=PID")
	s = reThread.ReplaceAllString(s, "thread T")
	s = reTimestamp.ReplaceAllString(s, "TIMESTAMP")
	s = reTmpPath.ReplaceAllString(s, "/PATH")
	s = reCorpus.ReplaceAllString(s, "CORPUS")
	s = reLineCol.ReplaceAllString(s, "")
	s = reNumIdx.ReplaceAllString(s, "[N]")
	return s
}

// --- frame + access extraction ---------------------------------------------

var (
	reAsanFramePath = regexp.MustCompile(`(?m)^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(/\S+?)(?::\d+)*\s*$`)
	reAsanFrameFunc = regexp.MustCompile(`(?m)^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)`)
	reGoFrame       = regexp.MustCompile(`(?m)^([A-Za-z_][\w./]*(?:\.[\w*()]+)?)\(`)
	reAccess        = regexp.MustCompile(`(?i)\b(READ|WRITE)\b of size (\d+)`)
)

const topFramesN = 5

// extractFrames pulls up to topFramesN stable frames from the RAW output. Function
// names (and source basenames) are stable across runs; addresses/offsets/lines are
// not and are excluded.
func extractFrames(raw []byte) []StableFrame {
	s := string(raw)
	var frames []StableFrame
	add := func(f StableFrame) {
		if f.Function == "" || len(frames) >= topFramesN {
			return
		}
		frames = append(frames, f)
	}
	if m := reAsanFramePath.FindAllStringSubmatch(s, topFramesN*2); m != nil {
		for _, g := range m {
			add(StableFrame{Function: strings.TrimSpace(g[1]), Source: path.Base(g[2])})
		}
	}
	if len(frames) == 0 {
		for _, g := range reAsanFrameFunc.FindAllStringSubmatch(s, topFramesN*2) {
			add(StableFrame{Function: strings.TrimSpace(g[1])})
		}
	}
	if len(frames) == 0 {
		for _, g := range reGoFrame.FindAllStringSubmatch(s, topFramesN*2) {
			fn := strings.TrimSpace(g[1])
			mod := ""
			if i := strings.Index(fn, "."); i > 0 {
				mod = fn[:i]
			}
			add(StableFrame{Module: mod, Function: fn})
		}
	}
	return frames
}

// extractAccess returns the sanitizer access type ("read"/"write") and size, if
// present — a stable, discriminating fault feature.
func extractAccess(raw []byte) (string, uint64) {
	if m := reAccess.FindSubmatch(raw); m != nil {
		n, _ := strconv.ParseUint(string(m[2]), 10, 64)
		return strings.ToLower(string(m[1])), n
	}
	return "", 0
}

// --- classification --------------------------------------------------------

var (
	reAsanType  = regexp.MustCompile(`(?i)(?:AddressSanitizer|ERROR: libFuzzer): ([a-z0-9-]+)`)
	reSanitizer = regexp.MustCompile(`(?i)AddressSanitizer|MemorySanitizer|LeakSanitizer|use-after-free|buffer-overflow|use-of-uninitialized`)
	rePanicIdx  = regexp.MustCompile(`(?i)panic: runtime error: index out of range|slice bounds out of range`)
	rePanicNil  = regexp.MustCompile(`(?i)panic: runtime error: invalid memory address or nil pointer`)
	rePanic     = regexp.MustCompile(`(?im)^panic:`)
	reOOM       = regexp.MustCompile(`(?i)out-?of-?memory|runtime: out of memory`)
	reTimeout   = regexp.MustCompile(`(?i)\btimeout\b|libFuzzer: timeout`)
	reAssert    = regexp.MustCompile(`(?i)assertion .*failed|assertion failed|assert\(`)
	reSegv      = regexp.MustCompile(`(?i)SEGV on unknown address|deadly signal|SIGSEGV|SIGBUS`)
	reAbort     = regexp.MustCompile(`(?i)SIGABRT|abort\(\)`)
)

// classify returns the deterministic (interest, crashType). Order matters. A bare
// SIGSEGV/SIGBUS WITHOUT sanitizer evidence is deliberately NOT called
// memory_safety (it could be a nil deref, stack overflow, bad mmap, or a logic
// bug) — it is reported as unknown; only sanitizer evidence yields memory_safety.
// OOM (resource_exhaustion) and timeout (hang) are kept distinct: their triage
// differs. All patterns are precompiled for fuzz volume.
func classify(a CrashArtifact) (CrashInterest, string) {
	s := string(a.RawOutput)
	sig := strings.ToUpper(a.Signal)

	switch {
	case reSanitizer.MatchString(s):
		typ := "sanitizer"
		if m := reAsanType.FindStringSubmatch(s); m != nil {
			typ = strings.ToLower(m[1])
		} else if strings.Contains(strings.ToLower(s), "use-after-free") {
			typ = "use-after-free"
		}
		return InterestMemory, typ
	case rePanicIdx.MatchString(s):
		return InterestPanic, "index_out_of_range"
	case rePanicNil.MatchString(s):
		return InterestPanic, "nil_dereference"
	case rePanic.MatchString(s):
		return InterestPanic, "panic"
	case reOOM.MatchString(s):
		return InterestResource, "oom"
	case reTimeout.MatchString(s) || sig == "SIGALRM":
		return InterestHang, "timeout"
	case reAssert.MatchString(s):
		return InterestInvariant, "assertion"
	case sig == "SIGABRT" || reAbort.MatchString(s):
		return InterestInvariant, "abort"
	case sig == "SIGSEGV" || sig == "SIGBUS" || reSegv.MatchString(s):
		// No sanitizer evidence: do not over-claim memory_safety.
		return InterestUnknown, "segv"
	case a.Signal != "" || a.ExitCode != 0:
		return InterestUnknown, "unknown"
	default:
		return InterestNoise, "none"
	}
}

// --- signature + grouping --------------------------------------------------

// Signature builds the stable fingerprint for an artifact. The hash is over the
// crash type + sanitizer access facts + top stable frames — NOT the whole raw log
// — so the same bug across runs collapses, while a different access type/size or
// different frames does not.
func Signature(a CrashArtifact) CrashSignature {
	_, crashType := classify(a)
	accessType, accessSize := extractAccess(a.RawOutput)
	frames := extractFrames(a.RawOutput)

	var b strings.Builder
	b.WriteString(crashType)
	b.WriteString("|access=")
	b.WriteString(accessType)
	b.WriteString("/")
	b.WriteString(strconv.FormatUint(accessSize, 10))
	if len(frames) == 0 {
		b.WriteString("\n")
		b.WriteString(normalizedTopLine(a.RawOutput))
	} else {
		for _, f := range frames {
			b.WriteString("\n")
			b.WriteString(f.key())
		}
	}
	return CrashSignature{
		Hash:       RawInputHash([]byte(b.String())),
		CrashType:  crashType,
		AccessType: accessType,
		AccessSize: accessSize,
		Frames:     frames,
	}
}

func normalizedTopLine(raw []byte) string {
	for _, ln := range strings.Split(Normalize(raw), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			return ln
		}
	}
	return ""
}

// Group deduplicates artifacts within a scope into CrashGroups keyed by
// ScopeHash+SignatureHash. The same signature under a different BuildID/HarnessID
// (a different scope) forms a DIFFERENT group. Groups are returned in a stable
// order (by GroupHash), independent of input order.
func (p *FuzzProducer) Group(scope FuzzScope, artifacts []CrashArtifact) []CrashGroup {
	scopeHash := scope.Hash()
	byKey := map[CrashGroupKey]*CrashGroup{}
	for _, a := range artifacts {
		sig := Signature(a)
		key := CrashGroupKey{ScopeHash: scopeHash, SignatureHash: sig.Hash}
		g := byKey[key]
		if g == nil {
			interest, _ := classify(a)
			g = &CrashGroup{Scope: scope, GroupHash: key.GroupHash(), Signature: sig, Interest: interest}
			byKey[key] = g
		}
		g.Count++
		if len(g.MemberCrashHashes) < p.maxMembers {
			g.MemberCrashHashes = append(g.MemberCrashHashes, a.CrashOutputHash())
		}
		if len(g.Samples) < p.maxSamples {
			g.Samples = append(g.Samples, a)
		}
	}
	out := make([]CrashGroup, 0, len(byKey))
	for _, g := range byKey {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GroupHash < out[j].GroupHash })
	return out
}

// --- candidate production --------------------------------------------------

// Produce groups the crashes within a scope and emits one hypothesis Candidate per
// NON-noise group, tagged Origin{Kind:"fuzz"}. The candidate's
// provenance.RawInputHash is the GroupHash (the whole group's identity, not one
// representative crash), and structured Refs carry scope/signature/group hashes,
// count and type so the candidate can be queried and correlated without parsing
// the rationale.
func (p *FuzzProducer) Produce(scope FuzzScope, artifacts []CrashArtifact) []*Candidate {
	groups := p.Group(scope, artifacts)
	origin := Origin{Kind: OriginFuzz, ID: scope.label()}
	var candidates []*Candidate
	for _, g := range groups {
		if g.Interest == InterestNoise {
			continue
		}
		prov := newProvenance(string(OriginFuzz), scope.Hash(), "fuzz", g.GroupHash)
		short := g.GroupHash
		if len(short) > 12 {
			short = short[:12]
		}
		title := fmt.Sprintf("%s crash (%s) group=%s", g.Interest, g.Signature.CrashType, short)
		var frames []string
		for _, f := range g.Signature.Frames {
			frames = append(frames, f.Function)
		}
		rationale := fmt.Sprintf("Fuzz scope %s: %d crash(es); signature=%s group=%s type=%s access=%s/%d; top frames: %s",
			scope.label(), g.Count, g.Signature.Hash, g.GroupHash, g.Signature.CrashType,
			g.Signature.AccessType, g.Signature.AccessSize, strings.Join(frames, " -> "))
		c := NewHypothesis(p.newID(), string(g.Interest), title, "", rationale, origin, []string{"crash_input", "crash_reproduced"}, prov)
		c.Refs = map[string]string{
			"scope_hash":     g.Scope.Hash(),
			"signature_hash": g.Signature.Hash,
			"group_hash":     g.GroupHash,
			"count":          strconv.FormatUint(g.Count, 10),
			"crash_type":     g.Signature.CrashType,
			"access_type":    g.Signature.AccessType,
			"access_size":    strconv.FormatUint(g.Signature.AccessSize, 10),
		}
		candidates = append(candidates, c)
	}
	return candidates
}
