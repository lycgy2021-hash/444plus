package research

import (
	"context"
	"testing"

	"gopoc/internal/model"
)

const authDiff = `diff --git a/server/handler.go b/server/handler.go
index 111..222 100644
--- a/server/handler.go
+++ b/server/handler.go
@@ -10,6 +10,9 @@ func handle(w http.ResponseWriter, r *http.Request) {
 	id := r.URL.Query().Get("id")
+	if !currentUser(r).HasRole("admin") {
+		http.Error(w, "forbidden", http.StatusForbidden)
+		return
+	}
 	render(w, id)
`

const boundsDiff = `--- a/buf.c
+++ b/buf.c
@@ -1,3 +1,5 @@
 void copy(char *dst, char *src, int n) {
+	if (n > sizeof(buffer)) {
+		return;
+	}
 	memcpy(dst, src, n);
`

const dangerousDiff = `--- a/run.py
+++ b/run.py
@@ -1,2 +1,2 @@
-	os.system("ping " + host)
+	subprocess.run(["ping", host], check=True)
`

const noiseDiff = `--- a/readme.md
+++ b/readme.md
@@ -1,1 +1,2 @@
 # Title
+Added a documentation sentence, nothing security relevant.
`

func TestDiffProducerClassifies(t *testing.T) {
	cases := []struct {
		name    string
		diff    string
		wantCat string
	}{
		{"auth", authDiff, CatAuthCheck},
		{"bounds", boundsDiff, CatBoundsCheck},
		{"dangerous_api", dangerousDiff, CatDangerousAPIRepl},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewDiffProducer().WithIDFunc(SequentialIDs(2026))
			cands := p.Produce([]byte(tc.diff), "abc123..def456")
			if len(cands) == 0 {
				t.Fatalf("no candidates for %s diff", tc.name)
			}
			found := false
			for _, c := range cands {
				if c.Type == tc.wantCat {
					found = true
				}
				if c.State != Hypothesis {
					t.Errorf("candidate born at %s, want hypothesis", c.State)
				}
				if c.Origin.Kind != OriginDiff {
					t.Errorf("origin kind = %s, want diff", c.Origin.Kind)
				}
				if c.Provenance.ProducerKind != "diff" || c.Provenance.InputHash != InputHash([]byte(tc.diff)) {
					t.Errorf("provenance not stamped to the exact diff: %+v", c.Provenance)
				}
			}
			if !found {
				t.Fatalf("no candidate of type %s; got %+v", tc.wantCat, cands)
			}
		})
	}
}

func TestDiffProducerIgnoresNoise(t *testing.T) {
	cands := NewDiffProducer().Produce([]byte(noiseDiff), "ref")
	if len(cands) != 0 {
		t.Fatalf("noise diff produced %d candidates: %+v", len(cands), cands)
	}
}

// A diff-origin candidate flows into the SAME spine: with no diff validator
// registered yet, the Engine matches nothing and it correctly stays a hypothesis
// (no second pipeline, no auto-promotion).
func TestDiffCandidateFlowsThroughSpine(t *testing.T) {
	cands := NewDiffProducer().Produce([]byte(authDiff), "ref")
	if len(cands) == 0 {
		t.Fatal("expected a candidate")
	}
	e := NewEngine(NewRegistry(NewHTTPDifferentialValidator(nil))) // only an http validator; won't match a diff candidate
	results, err := e.Validate(context.Background(), model.Target{}, cands[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 || cands[0].State != Hypothesis {
		t.Fatalf("diff candidate with no matching validator must stay hypothesis, got state=%s results=%d", cands[0].State, len(results))
	}
}
