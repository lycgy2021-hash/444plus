package research

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// FuzzProducer (S8 v1) turns raw fuzzer crash output into research candidates,
// deterministically and with strict volume control. The pipeline is:
//
//	CrashArtifact → Normalize → CrashSignature → dedup into CrashGroup →
//	deterministic CrashInterest classification → (only non-noise groups) →
//	hypothesis Candidate{Origin{Kind:"fuzz"}} → the same Registry/Engine spine.
//
// Two hashes are kept strictly separate: a CrashArtifact's RawInputHash (the
// byte-for-byte SHA-256 of the raw crash output) and a CrashSignature's Hash (the
// SHA-256 of the NORMALIZED crash type + top stable frames, i.e. the dedup key).
// Classification is deterministic here; a later AI pass may explain, enrich, or
// suggest merges, but it can never decide a candidate's state. Crashes are grouped
// before any candidate is created, so a campaign that emits 100k crashes of one
// bug yields one candidate, not 100k.
type FuzzProducer struct {
	newID func() string
	// maxSamples caps retained samples per group (memory bound at high volume).
	maxSamples int
}

func NewFuzzProducer() *FuzzProducer {
	return &FuzzProducer{newID: SequentialIDs(time.Now().UTC().Year()), maxSamples: 3}
}

// WithIDFunc overrides the id generator (stable ids in tests).
func (p *FuzzProducer) WithIDFunc(fn func() string) *FuzzProducer {
	p.newID = fn
	return p
}

// CrashArtifact is one raw crash as emitted by the fuzzer. RawOutput is the raw
// crash log/stderr; InputRef references the fuzz input that triggered it (a path
// or the fuzzer's own hash). Its RawInputHash is the hash of the raw output —
// distinct from any signature hash.
type CrashArtifact struct {
	RawOutput []byte
	ExitCode  int
	Signal    string
	InputRef  string
}

// RawInputHash is the byte-for-byte SHA-256 of the raw crash output — the raw
// artifact's own hash, never the (normalized) signature hash.
func (a CrashArtifact) RawInputHash() string { return RawInputHash(a.RawOutput) }

// CrashSignature is the stable identity of a crash: its type plus the top stable
// frames, hashed. Hash is the dedup key.
type CrashSignature struct {
	Hash      string   `json:"hash"`
	TopFrames []string `json:"top_frames,omitempty"`
	CrashType string   `json:"crash_type"`
}

// CrashGroup is a set of artifacts that share a signature.
type CrashGroup struct {
	Signature CrashSignature  `json:"signature"`
	Interest  CrashInterest   `json:"interest"`
	Count     uint64          `json:"count"`
	Samples   []CrashArtifact `json:"-"`
}

// CrashInterest is the deterministic security-interest classification.
type CrashInterest string

const (
	InterestNoise     CrashInterest = "noise"
	InterestMemory    CrashInterest = "memory_safety"
	InterestPanic     CrashInterest = "panic"
	InterestHang      CrashInterest = "hang"
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

// Normalize strips run-specific noise (addresses, PIDs, timestamps, temp paths,
// corpus file names, line:col, concrete indices) so the same bug across different
// runs normalizes to the same text. It keeps crash type, function/module names,
// and structure.
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

// --- frame extraction ------------------------------------------------------

var (
	// ASAN/libFuzzer: "#3 0x... in func /path/file:line" (path optional).
	reAsanFrameWithPath = regexp.MustCompile(`(?m)^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+/`)
	reAsanFrameNoPath   = regexp.MustCompile(`(?m)^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)`)
	// Go panic: "main.parseInput(0x...)" at column 0.
	reGoFrame = regexp.MustCompile(`(?m)^([A-Za-z_][\w./]*(?:\.[\w*()]+)?)\(`)
)

const topFramesN = 5

// extractFrames pulls up to topFramesN stable frame identifiers (function/module
// names) from the RAW output. Function names are inherently stable across runs,
// so they, not addresses, anchor the signature.
func extractFrames(raw []byte) []string {
	s := string(raw)
	var frames []string
	add := func(f string) {
		f = strings.TrimSpace(f)
		if f == "" || len(frames) >= topFramesN {
			return
		}
		frames = append(frames, f)
	}
	for _, m := range reAsanFrameWithPath.FindAllStringSubmatch(s, topFramesN*2) {
		add(m[1])
	}
	if len(frames) == 0 {
		for _, m := range reAsanFrameNoPath.FindAllStringSubmatch(s, topFramesN*2) {
			add(m[1])
		}
	}
	if len(frames) == 0 {
		for _, m := range reGoFrame.FindAllStringSubmatch(s, topFramesN*2) {
			add(m[1])
		}
	}
	return frames
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

// classify returns the deterministic (interest, crashType) for an artifact. Order
// matters: the most specific/authoritative signal wins. All patterns are
// precompiled so classifying at fuzz volume does not recompile per crash.
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
		return InterestHang, "oom"
	case reTimeout.MatchString(s) || sig == "SIGALRM":
		return InterestHang, "timeout"
	case reAssert.MatchString(s):
		return InterestInvariant, "assertion"
	case sig == "SIGSEGV" || sig == "SIGBUS" || reSegv.MatchString(s):
		return InterestMemory, "segv"
	case sig == "SIGABRT" || reAbort.MatchString(s):
		return InterestInvariant, "abort"
	case a.Signal != "" || a.ExitCode != 0:
		return InterestUnknown, "unknown"
	default:
		return InterestNoise, "none"
	}
}

// --- signature + grouping --------------------------------------------------

// Signature builds the stable signature for an artifact: its crash type plus top
// frames, hashed. The hash is over the normalized identity, NOT the whole raw log,
// so the same bug across runs collapses to one signature. When no frames can be
// extracted, a normalized top line backstops the identity (still far more stable
// than hashing the full log).
func Signature(a CrashArtifact) CrashSignature {
	_, crashType := classify(a)
	frames := extractFrames(a.RawOutput)
	material := crashType + "\n" + strings.Join(frames, "\n")
	if len(frames) == 0 {
		material = crashType + "\n" + normalizedTopLine(a.RawOutput)
	}
	return CrashSignature{Hash: RawInputHash([]byte(material)), TopFrames: frames, CrashType: crashType}
}

func normalizedTopLine(raw []byte) string {
	for _, ln := range strings.Split(Normalize(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			return ln
		}
	}
	return ""
}

// Group deduplicates artifacts by signature hash into CrashGroups, each classified
// deterministically. Groups are returned in a stable order (by signature hash).
func (p *FuzzProducer) Group(artifacts []CrashArtifact) []CrashGroup {
	byHash := map[string]*CrashGroup{}
	var order []string
	for _, a := range artifacts {
		sig := Signature(a)
		g := byHash[sig.Hash]
		if g == nil {
			interest, _ := classify(a)
			g = &CrashGroup{Signature: sig, Interest: interest}
			byHash[sig.Hash] = g
			order = append(order, sig.Hash)
		}
		g.Count++
		if len(g.Samples) < p.maxSamples {
			g.Samples = append(g.Samples, a)
		}
	}
	out := make([]CrashGroup, 0, len(order))
	for _, h := range order {
		out = append(out, *byHash[h])
	}
	// Stable order regardless of input order.
	sortGroupsByHash(out)
	return out
}

func sortGroupsByHash(g []CrashGroup) {
	for i := 1; i < len(g); i++ {
		for j := i; j > 0 && g[j-1].Signature.Hash > g[j].Signature.Hash; j-- {
			g[j-1], g[j] = g[j], g[j-1]
		}
	}
}

// --- candidate production --------------------------------------------------

// Produce groups the crashes and emits one hypothesis Candidate per NON-noise
// group, tagged Origin{Kind:"fuzz"}. campaignRef labels the fuzz campaign for
// origin/provenance. provenance.RawInputHash is the raw hash of a representative
// crash artifact (a raw input hash), kept distinct from the group's SignatureHash
// (which is recorded in the candidate's rationale/title). A noise group never
// becomes a candidate.
func (p *FuzzProducer) Produce(artifacts []CrashArtifact, campaignRef string) []*Candidate {
	groups := p.Group(artifacts)
	origin := Origin{Kind: OriginFuzz, ID: campaignRef}
	var candidates []*Candidate
	for _, g := range groups {
		if g.Interest == InterestNoise {
			continue
		}
		rawHash := ""
		if len(g.Samples) > 0 {
			rawHash = g.Samples[0].RawInputHash()
		}
		prov := newProvenance(string(OriginFuzz), campaignRef, "fuzz", rawHash)
		short := g.Signature.Hash
		if len(short) > 12 {
			short = short[:12]
		}
		title := fmt.Sprintf("%s crash (%s) sig=%s", g.Interest, g.Signature.CrashType, short)
		rationale := fmt.Sprintf("Fuzz campaign %s: %d crash(es) with signature %s (type=%s); top frames: %s. Raw crash hash (representative): %s",
			campaignRef, g.Count, g.Signature.Hash, g.Signature.CrashType, strings.Join(g.Signature.TopFrames, " -> "), rawHash)
		required := []string{"crash_input", "crash_reproduced"}
		candidates = append(candidates, NewHypothesis(p.newID(), string(g.Interest), title, "", rationale, origin, required, prov))
	}
	return candidates
}
