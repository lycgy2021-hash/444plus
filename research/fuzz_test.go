package research

import (
	"context"
	"fmt"
	"testing"

	"gopoc/internal/model"
)

// Same heap-buffer-overflow bug, two runs: different addresses, PIDs, thread ids
// and source line:col. Must normalize to ONE signature.
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

// A different bug: different top frames.
const asanOther = `==11111==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x0000004c1d2e
    #0 0x4c1d2d in free_session /src/session.c:55:1
    #1 0x4c2e3f in cleanup /src/server.c:200:2
SUMMARY: AddressSanitizer: heap-use-after-free in free_session`

const goPanic = `panic: runtime error: index out of range [5] with length 3

goroutine 1 [running]:
main.parseInput(0xc0000140a0, 0x3)
	/src/main.go:42 +0x1a5
main.main()
	/src/main.go:12 +0x65`

func TestSignatureDedupStability(t *testing.T) {
	s1 := Signature(CrashArtifact{RawOutput: []byte(asanRun1)})
	s2 := Signature(CrashArtifact{RawOutput: []byte(asanRun2)})
	if s1.Hash != s2.Hash {
		t.Fatalf("same bug across runs got different signatures:\n s1=%+v\n s2=%+v", s1, s2)
	}
	if s1.CrashType != "heap-buffer-overflow" {
		t.Errorf("crash type = %q", s1.CrashType)
	}
	if len(s1.TopFrames) < 2 || s1.TopFrames[0] != "parse_header" {
		t.Errorf("top frames = %v", s1.TopFrames)
	}
	other := Signature(CrashArtifact{RawOutput: []byte(asanOther)})
	if other.Hash == s1.Hash {
		t.Fatal("different bugs must not collapse to one signature")
	}
}

func TestFuzzGroupDedup(t *testing.T) {
	p := NewFuzzProducer()
	// 1000 copies of the same bug (varying addresses), plus one different bug.
	var arts []CrashArtifact
	for i := 0; i < 1000; i++ {
		raw := fmt.Sprintf("%s\nnonce 0x%x", asanRun1, i) // vary an address each time
		arts = append(arts, CrashArtifact{RawOutput: []byte(raw)})
	}
	arts = append(arts, CrashArtifact{RawOutput: []byte(asanOther)})
	groups := p.Group(arts)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (1 bug x1000 + 1 other), got %d", len(groups))
	}
	var big *CrashGroup
	for i := range groups {
		if groups[i].Count > 1 {
			big = &groups[i]
		}
	}
	if big == nil || big.Count != 1000 {
		t.Fatalf("dedup failed to collapse 1000 same-bug crashes into one group: %+v", groups)
	}
	if len(big.Samples) > p.maxSamples {
		t.Fatalf("samples not capped: %d", len(big.Samples))
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
		{"assertion", CrashArtifact{RawOutput: []byte("app: assertion `p != NULL' failed.")}, InterestInvariant},
		{"segv_signal", CrashArtifact{Signal: "SIGSEGV", RawOutput: []byte("Segmentation fault")}, InterestMemory},
		{"abort_signal", CrashArtifact{Signal: "SIGABRT", RawOutput: []byte("Aborted")}, InterestInvariant},
		{"noise", CrashArtifact{ExitCode: 0, RawOutput: []byte("Done: 1000 runs, 0 crashes")}, InterestNoise},
		{"unknown", CrashArtifact{ExitCode: 1, RawOutput: []byte("weird nonzero exit, no known marker")}, InterestUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := classify(tc.art)
			if got != tc.want {
				t.Errorf("classify = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestFuzzProducerCandidates(t *testing.T) {
	p := NewFuzzProducer().WithIDFunc(SequentialIDs(2026))
	arts := []CrashArtifact{
		{RawOutput: []byte(asanRun1)},
		{RawOutput: []byte(asanRun2)}, // same bug as run1 -> same group
		{RawOutput: []byte(goPanic)},
		{ExitCode: 0, RawOutput: []byte("no crash here")}, // noise -> no candidate
	}
	cands := p.Produce(arts, "campaign-42")
	if len(cands) != 2 { // asan group + panic group; noise excluded
		t.Fatalf("expected 2 candidates (asan + panic), got %d: %+v", len(cands), cands)
	}
	for _, c := range cands {
		if c.State != Hypothesis {
			t.Errorf("fuzz candidate born at %s, want hypothesis", c.State)
		}
		if c.Origin.Kind != OriginFuzz || c.Origin.ID != "campaign-42" {
			t.Errorf("origin = %+v", c.Origin)
		}
		if c.Provenance().ProducerKind != "fuzz" || c.Provenance().RawInputHash == "" {
			t.Errorf("provenance not stamped: %+v", c.Provenance())
		}
		// Boundary: the two hashes must not be mixed — provenance carries the RAW
		// crash hash, never the (normalized) signature hash.
		if c.Type == string(InterestMemory) {
			sig := Signature(CrashArtifact{RawOutput: []byte(asanRun1)})
			if c.Provenance().RawInputHash == sig.Hash {
				t.Error("provenance RawInputHash must differ from the signature hash")
			}
			if c.Provenance().RawInputHash != RawInputHash([]byte(asanRun1)) {
				t.Error("provenance RawInputHash must be the raw crash artifact hash")
			}
		}
	}
}

// A fuzz-origin candidate flows through the SAME spine; with no fuzz validator
// registered it correctly stays a hypothesis (no auto-promotion, no exploitability
// judgment).
func TestFuzzCandidateFlowsThroughSpine(t *testing.T) {
	cands := NewFuzzProducer().Produce([]CrashArtifact{{RawOutput: []byte(asanRun1)}}, "c1")
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
