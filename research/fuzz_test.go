package research

import (
	"context"
	"fmt"
	"testing"

	"gopoc/internal/model"
)

// Same heap-buffer-overflow bug, two runs: different addresses, PIDs, thread ids,
// source line:col. Must normalize to ONE signature.
const asanRun1 = `==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000075 at pc 0x0000004a1b2c bp 0x7ffd0001 sp 0x7ffd0002
READ of size 1 at 0x602000000075 thread T0
    #0 0x4a1b2b in parse_header /src/parser.c:123:45
    #1 0x4a2c3d in handle_request /src/server.c:88:12
    #2 0x7f1234 in main /src/main.c:10:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:123:45 in parse_header`

const asanRun2 = `==67890==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000abc at pc 0x0000005b2d3e bp 0x7ffdaaaa sp 0x7ffdbbbb
READ of size 1 at 0x603000000abc thread T1
    #0 0x5b2d3d in parse_header /src/parser.c:130:40
    #1 0x5b3e4f in handle_request /src/server.c:90:15
    #2 0x7f5678 in main /src/main.c:10:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:130:40 in parse_header`

// Same function/frames as run1, but a WRITE of size 4 (a distinct fault) — must
// NOT merge with run1.
const asanWriteSameFrames = `==22222==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x604000000090 at pc 0x0000006c3f4a
WRITE of size 4 at 0x604000000090 thread T0
    #0 0x6c3f49 in parse_header /src/parser.c:200:10
    #1 0x6c4a5b in handle_request /src/server.c:88:12
    #2 0x7f9abc in main /src/main.c:10:3
SUMMARY: AddressSanitizer: heap-buffer-overflow in parse_header`

// Same frames as run1, but a different crash TYPE (use-after-free) — must NOT
// merge with run1.
const asanUAFSameFrames = `==33333==ERROR: AddressSanitizer: heap-use-after-free on address 0x605000000010 at pc 0x0000007d4e5b
READ of size 1 at 0x605000000010 thread T0
    #0 0x7d4e5a in parse_header /src/parser.c:150:5
    #1 0x7d5f6c in handle_request /src/server.c:88:12
    #2 0x7fabcd in main /src/main.c:10:3
SUMMARY: AddressSanitizer: heap-use-after-free in parse_header`

const goPanic = `panic: runtime error: index out of range [5] with length 3

goroutine 1 [running]:
main.parseInput(0xc0000140a0, 0x3)
	/src/main.go:42 +0x1a5
main.main()
	/src/main.go:12 +0x65`

func sigHash(raw string) string { return Signature(CrashArtifact{RawOutput: []byte(raw)}).Hash }

func TestSignatureDedupAndAntiMerge(t *testing.T) {
	// Same bug across runs -> same signature.
	if sigHash(asanRun1) != sigHash(asanRun2) {
		t.Fatal("same bug across runs must share a signature")
	}
	// Same function, different access type/size -> different signature.
	if sigHash(asanRun1) == sigHash(asanWriteSameFrames) {
		t.Fatal("READ-of-1 vs WRITE-of-4 in the same function must NOT merge")
	}
	// Same frames, different crash type -> different signature.
	if sigHash(asanRun1) == sigHash(asanUAFSameFrames) {
		t.Fatal("overflow vs use-after-free with same frames must NOT merge")
	}
	s := Signature(CrashArtifact{RawOutput: []byte(asanRun1)})
	if s.AccessType != "read" || s.AccessSize != 1 || len(s.Frames) < 2 || s.Frames[0].Function != "parse_header" {
		t.Fatalf("signature facts wrong: %+v", s)
	}
	if s.Frames[0].Source != "parser.c" {
		t.Errorf("frame source basename = %q, want parser.c", s.Frames[0].Source)
	}
}

func TestScopeSeparatesGroups(t *testing.T) {
	p := NewFuzzProducer()
	art := CrashArtifact{RawOutput: []byte(asanRun1)}
	buildA := FuzzScope{TargetID: "t", BuildID: "A", HarnessID: "h", Fuzzer: "libfuzzer"}
	buildB := FuzzScope{TargetID: "t", BuildID: "B", HarnessID: "h", Fuzzer: "libfuzzer"}
	harnessH2 := FuzzScope{TargetID: "t", BuildID: "A", HarnessID: "h2", Fuzzer: "libfuzzer"}

	gA := p.Group(buildA, []CrashArtifact{art})[0]
	gB := p.Group(buildB, []CrashArtifact{art})[0]
	gH := p.Group(harnessH2, []CrashArtifact{art})[0]

	// Same signature (it's the same crash)...
	if gA.Signature.Hash != gB.Signature.Hash || gA.Signature.Hash != gH.Signature.Hash {
		t.Fatal("signature should be identical across scopes (same crash fingerprint)")
	}
	// ...but different groups (scope differs), so never merged across build/harness.
	if gA.GroupHash == gB.GroupHash {
		t.Fatal("different BuildID must yield a different group")
	}
	if gA.GroupHash == gH.GroupHash {
		t.Fatal("different HarnessID must yield a different group")
	}
}

func TestFuzzGroupDedupAndProvenance(t *testing.T) {
	p := NewFuzzProducer()
	scope := FuzzScope{TargetID: "t", BuildID: "A", HarnessID: "h", Fuzzer: "libfuzzer"}
	var arts []CrashArtifact
	for i := 0; i < 1000; i++ {
		raw := fmt.Sprintf("%s\nnonce 0x%x", asanRun1, i) // vary a run-specific address
		arts = append(arts, CrashArtifact{RawOutput: []byte(raw)})
	}
	arts = append(arts, CrashArtifact{RawOutput: []byte(asanUAFSameFrames)})
	groups := p.Group(scope, arts)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	var big *CrashGroup
	for i := range groups {
		if groups[i].Count > 1 {
			big = &groups[i]
		}
	}
	if big == nil || big.Count != 1000 {
		t.Fatalf("1000 same-bug crashes must collapse to one group with exact count: %+v", groups)
	}
	if len(big.Samples) > p.maxSamples {
		t.Fatalf("samples not capped: %d", len(big.Samples))
	}
	if len(big.MemberCrashHashes) == 0 || len(big.MemberCrashHashes) > p.maxMembers {
		t.Fatalf("member provenance must be traceable but capped: %d", len(big.MemberCrashHashes))
	}

	// GroupHash is representative-independent: reversing input order yields the
	// same group identity.
	rev := make([]CrashArtifact, len(arts))
	for i := range arts {
		rev[len(arts)-1-i] = arts[i]
	}
	groups2 := p.Group(scope, rev)
	if groups[0].GroupHash != groups2[0].GroupHash || groups[1].GroupHash != groups2[1].GroupHash {
		t.Fatal("GroupHash must not depend on input/representative order")
	}
}

func TestFourHashesDistinct(t *testing.T) {
	scope := FuzzScope{TargetID: "t", BuildID: "A", HarnessID: "h", Fuzzer: "libfuzzer"}
	a := CrashArtifact{RawOutput: []byte(asanRun1), Testcase: []byte("\x00crashing input bytes\xff")}
	testcase := a.TestcaseHash()
	crashOut := a.CrashOutputHash()
	sig := Signature(a).Hash
	group := CrashGroupKey{ScopeHash: scope.Hash(), SignatureHash: sig}.GroupHash()
	all := []string{testcase, crashOut, sig, group}
	for i := range all {
		if all[i] == "" {
			t.Fatalf("hash %d empty", i)
		}
		for j := i + 1; j < len(all); j++ {
			if all[i] == all[j] {
				t.Fatalf("hashes %d and %d must differ (testcase/crashOutput/signature/group)", i, j)
			}
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		art  CrashArtifact
		want CrashInterest
	}{
		{"asan", CrashArtifact{RawOutput: []byte(asanRun1)}, InterestMemory},
		{"go_panic_index", CrashArtifact{RawOutput: []byte(goPanic)}, InterestPanic},
		{"timeout", CrashArtifact{RawOutput: []byte("==1==ERROR: libFuzzer: timeout after 60s")}, InterestHang},
		{"oom_is_resource_not_hang", CrashArtifact{RawOutput: []byte("==1==ERROR: libFuzzer: out-of-memory (used: 2048Mb)")}, InterestResource},
		{"assertion", CrashArtifact{RawOutput: []byte("app: assertion `p != NULL' failed.")}, InterestInvariant},
		{"bare_segv_is_unknown_not_memory", CrashArtifact{Signal: "SIGSEGV", RawOutput: []byte("Segmentation fault")}, InterestUnknown},
		{"abort_signal", CrashArtifact{Signal: "SIGABRT", RawOutput: []byte("Aborted")}, InterestInvariant},
		{"noise", CrashArtifact{ExitCode: 0, RawOutput: []byte("Done: 1000 runs, 0 crashes")}, InterestNoise},
		{"unknown", CrashArtifact{ExitCode: 1, RawOutput: []byte("weird nonzero exit, no known marker")}, InterestUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := classify(tc.art); got != tc.want {
				t.Errorf("classify = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestFuzzProducerCandidates(t *testing.T) {
	p := NewFuzzProducer().WithIDFunc(SequentialIDs(2026))
	scope := FuzzScope{TargetID: "t", BuildID: "A", HarnessID: "h", Fuzzer: "libfuzzer"}
	arts := []CrashArtifact{
		{RawOutput: []byte(asanRun1)},
		{RawOutput: []byte(asanRun2)}, // same group as run1
		{RawOutput: []byte(goPanic)},
		{ExitCode: 0, RawOutput: []byte("no crash here")}, // noise -> no candidate
	}
	cands := p.Produce(scope, arts)
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates (asan + panic), got %d", len(cands))
	}
	for _, c := range cands {
		if c.State != Hypothesis || c.Origin.Kind != OriginFuzz {
			t.Errorf("bad candidate: state=%s origin=%+v", c.State, c.Origin)
		}
		// Provenance traces the whole GROUP, not one crash: RawInputHash == GroupHash.
		if c.Provenance().RawInputHash != c.Refs["group_hash"] {
			t.Errorf("provenance must point at the group hash, got %q vs %q", c.Provenance().RawInputHash, c.Refs["group_hash"])
		}
		// Structured, queryable refs — not just rationale.
		for _, k := range []string{"scope_hash", "signature_hash", "group_hash", "count", "crash_type"} {
			if c.Refs[k] == "" {
				t.Errorf("missing structured ref %q", k)
			}
		}
		// The two hashes must stay distinct.
		if c.Refs["group_hash"] == c.Refs["signature_hash"] {
			t.Error("group hash and signature hash must not be equal")
		}
	}
}

func TestFuzzCandidateFlowsThroughSpine(t *testing.T) {
	scope := FuzzScope{TargetID: "t", BuildID: "A", HarnessID: "h", Fuzzer: "libfuzzer"}
	cands := NewFuzzProducer().Produce(scope, []CrashArtifact{{RawOutput: []byte(asanRun1)}})
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	e := NewEngine(NewRegistry(NewHTTPDifferentialValidator(nil))) // won't match a fuzz candidate
	results, err := e.Validate(context.Background(), model.Target{}, cands[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 || cands[0].State != Hypothesis {
		t.Fatalf("fuzz candidate must stay hypothesis with no matching validator; state=%s", cands[0].State)
	}
}
