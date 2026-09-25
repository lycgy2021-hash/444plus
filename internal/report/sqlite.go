package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// WriteSQLite appends one complete scan in a transaction. A failed write never
// leaves a partially inserted run. JSON preserves all evidence alongside indexes.
func WriteSQLite(ctx context.Context, path string, r Report) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	uriPath := filepath.ToSlash(abs)
	if len(uriPath) > 1 && uriPath[1] == ':' {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS scans (
  run_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,
  mode TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
  cancelled INTEGER NOT NULL, report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  run_id TEXT NOT NULL REFERENCES scans(run_id), ordinal INTEGER NOT NULL,
  cve TEXT NOT NULL, target TEXT NOT NULL, verdict TEXT NOT NULL,
  confidence INTEGER NOT NULL, finding_json TEXT NOT NULL,
  PRIMARY KEY (run_id, ordinal)
);
CREATE INDEX IF NOT EXISTS findings_cve_verdict ON findings(cve, verdict);
CREATE INDEX IF NOT EXISTS findings_target ON findings(target);`)
	if err != nil {
		return fmt.Errorf("initializing report schema: %w", err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)`, r.RunID, r.SchemaVersion, r.Mode, r.StartedAt.Format(time.RFC3339Nano), r.FinishedAt.Format(time.RFC3339Nano), r.Cancelled, string(data))
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for ordinal, f := range r.Findings {
		finding, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, r.RunID, ordinal, f.ID, f.Target, f.Verdict, f.Confidence, string(finding)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
