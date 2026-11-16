package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestExportCompactLedger(t *testing.T) {
	dir := t.TempDir()
	dbFile = filepath.Join(dir, "proof_of_work.db")
	if err := initDB(); err != nil {
		t.Fatal(err)
	}
	db, err := connectDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.conn.Close()

	big := make([]byte, 5*1024*1024)
	for i := range big {
		big[i] = 'a'
	}
	if _, err := db.conn.Exec(`INSERT INTO file_snapshots (timestamp,file_path,content_diff,current_hash,previous_hash) VALUES (1,'x',?, 'h','p')`, string(big)); err != nil {
		t.Fatal(err)
	}
	prev := "0000000000000000000000000000000000000000000000000000000000000000"
	for _, id := range []string{"vc1", "vc2"} {
		h := computeSHA256(id + "|" + prev + "|{}")
		if _, err := db.conn.Exec(`INSERT INTO session_credentials (vc_id,timestamp,project_context,ai_insight,skill_tags,file_paths,full_vc_json,status,vc_hash,prev_vc_hash) VALUES (?,1,'c','a','t','f','{}',1,?,?)`, id, h, prev); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
	db.UpsertBroadcastJob("vc1", "gist")
	db.UpdateBroadcastStatus("vc1", "gist", "success", "rid", "http://x", "")

	out := filepath.Join(dir, "export.db")
	if err := db.ExportCompactLedger(out); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(out)
	t.Logf("export size = %d bytes", st.Size())
	if st.Size() > 200*1024 {
		t.Fatalf("export too large: %d", st.Size())
	}

	// Re-open exported file as a normal ledger and verify chain.
	dbFile = out
	if err := initDB(); err != nil {
		t.Fatal(err)
	}
	e, _ := sql.Open("sqlite", out)
	defer e.Close()
	ev := &VeriHashDB{conn: e}
	res := ev.VerifyChainIntegrity()
	if !res.Intact || res.TotalBlocks != 2 {
		t.Fatalf("chain not intact: %+v", res)
	}
	var n int
	e.QueryRow(`SELECT COUNT(*) FROM broadcast_publications`).Scan(&n)
	if n != 1 {
		t.Fatalf("broadcast rows = %d", n)
	}
	e.QueryRow(`SELECT COUNT(*) FROM file_snapshots`).Scan(&n)
	if n != 0 {
		t.Fatalf("snapshots should be empty, got %d", n)
	}
}
