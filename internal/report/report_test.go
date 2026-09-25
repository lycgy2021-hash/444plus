package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	"gopoc/internal/model"
)

func TestSQLiteAppendRoundTripAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "扫描 report #1.db")
	target, _ := model.ParseTarget("http://localhost")
	r := New(model.ModePassive, []model.Target{target}, nil)
	r.Finish([]model.Finding{{ID: "CVE-2021-41773", Target: target.BaseURL, Verdict: model.VerdictLikely, Confidence: 85, Evidence: model.Evidence{Message: "quoted ' ; text"}}}, false)
	if err := WriteSQLite(context.Background(), path, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteSQLite(context.Background(), path, r); err == nil {
		t.Fatal("duplicate run accepted")
	}
	second := New(model.ModePassive, []model.Target{target}, nil)
	second.Finish(r.Findings, true)
	if err := WriteSQLite(context.Background(), path, second); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{"scans", "findings"} {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 2 {
			t.Fatalf("%s: %d %v", table, n, err)
		}
	}
	var raw string
	if err := db.QueryRow("SELECT report_json FROM scans WHERE run_id=?", r.RunID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var restored Report
	if err := json.Unmarshal([]byte(raw), &restored); err != nil || restored.Findings[0].Evidence.Message != r.Findings[0].Evidence.Message {
		t.Fatalf("round trip failed: %v", err)
	}
}
