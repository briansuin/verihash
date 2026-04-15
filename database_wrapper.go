package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const dbFile = "proof_of_work.db"

func initDB() error {
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return err
	}
	defer db.Close()

	queries := []string{
		`CREATE TABLE IF NOT EXISTS file_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp REAL NOT NULL,
			file_path TEXT NOT NULL,
			content_diff TEXT NOT NULL,
			current_hash TEXT NOT NULL,
			previous_hash TEXT NOT NULL,
			signature TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS session_credentials (
			vc_id TEXT PRIMARY KEY,
			timestamp REAL NOT NULL,
			project_context TEXT NOT NULL,
			ai_insight TEXT NOT NULL,
			skill_tags TEXT NOT NULL,
			file_paths TEXT NOT NULL,
			full_vc_json TEXT NOT NULL,
			status INTEGER DEFAULT 1
		);`,
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout = 5000;`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %q: %v", query, err)
		}
	}

	// Migration: add columns incrementally — safe to ignore errors if column already exists
	db.Exec(`ALTER TABLE session_credentials ADD COLUMN status INTEGER DEFAULT 1;`)
	db.Exec(`ALTER TABLE session_credentials ADD COLUMN vc_hash TEXT DEFAULT '';`)
	db.Exec(`ALTER TABLE session_credentials ADD COLUMN prev_vc_hash TEXT DEFAULT '';`)
	return nil
}

// VeriHashDB wrapper
type VeriHashDB struct {
	conn *sql.DB
}

func connectDB() (*VeriHashDB, error) {
	// _journal=WAL avoids writer/reader conflicts.
	// _busy_timeout=5000 retries for up to 5s before returning SQLITE_BUSY.
	// SetMaxOpenConns(1) ensures SQLite's single-writer model is respected.
	dsn := dbFile + "?_journal=WAL&_busy_timeout=5000&_synchronous=NORMAL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &VeriHashDB{conn: db}, nil
}

// GetLatestHash retrieves the last hash from the chain
func (db *VeriHashDB) GetLatestHash() string {
	var hash string
	err := db.conn.QueryRow("SELECT current_hash FROM file_snapshots ORDER BY id DESC LIMIT 1").Scan(&hash)
	if err != nil {
		// If table is empty or other error, return genesis state
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	return hash
}

// CommitSnapshot calculates hash, signs it, and writes to SQLite
func (db *VeriHashDB) CommitSnapshot(filePath, contentDiff string, privKey ed25519.PrivateKey) (string, error) {
	timestamp := float64(time.Now().UnixNano()) / 1e9 // equivalent to Python's time.time()
	prevHash := db.GetLatestHash()

	// Cryptographic Iron Rule: hash(timestamp + content_diff + previous_hash)
	rawString := fmt.Sprintf("%f%s%s", timestamp, contentDiff, prevHash)
	
	h := sha256.New()
	h.Write([]byte(rawString))
	currentHashBytes := h.Sum(nil)
	currentHash := hex.EncodeToString(currentHashBytes)

	// Sign the hash with Ed25519
	signature := ""
	if len(privKey) == ed25519.PrivateKeySize {
		sigBytes := ed25519.Sign(privKey, currentHashBytes)
		signature = hex.EncodeToString(sigBytes)
	}

	// Insert into DB
	_, err := db.conn.Exec(`
		INSERT INTO file_snapshots 
		(timestamp, file_path, content_diff, current_hash, previous_hash, signature)
		VALUES (?, ?, ?, ?, ?, ?)
	`, timestamp, filePath, contentDiff, currentHash, prevHash, signature)

	if err != nil {
		return "", err
	}

	return currentHash, nil
}

// GetLatestVCHash returns the vc_hash of the most recently inserted credential.
// Returns the genesis hash (all zeros) if the ledger is empty.
func (db *VeriHashDB) GetLatestVCHash() string {
	var hash string
	err := db.conn.QueryRow(
		`SELECT vc_hash FROM session_credentials ORDER BY rowid DESC LIMIT 1`,
	).Scan(&hash)
	if err != nil || hash == "" {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	return hash
}

// ChainVerifyResult holds the result of a full chain integrity check
type ChainVerifyResult struct {
	Intact        bool   `json:"intact"`
	TotalBlocks   int    `json:"total_blocks"`
	ActiveBlocks  int    `json:"active_blocks"`
	RevokedBlocks int    `json:"revoked_blocks"`
	BreakAtVcID   string `json:"break_at_vc_id"`
	Message       string `json:"message"`
}

// VerifyChainIntegrity walks every credential in insertion order and validates
// the SHA256 hash chain. Revoked records are included (status=0 does not break
// the chain). Any modification to any past record will cause a mismatch.
func (db *VeriHashDB) VerifyChainIntegrity() ChainVerifyResult {
	rows, err := db.conn.Query(`
		SELECT rowid, vc_id, vc_hash, prev_vc_hash, full_vc_json, status
		FROM session_credentials
		ORDER BY rowid ASC
	`)
	if err != nil {
		return ChainVerifyResult{Intact: false, Message: "Query error: " + err.Error()}
	}
	defer rows.Close()

	result := ChainVerifyResult{Intact: true}
	genesisHash := "0000000000000000000000000000000000000000000000000000000000000000"
	expectedPrevHash := genesisHash

	for rows.Next() {
		var rowID int
		var vcID, vcHash, prevVCHash, fullJSON string
		var status int
		if err := rows.Scan(&rowID, &vcID, &vcHash, &prevVCHash, &fullJSON, &status); err != nil {
			continue
		}
		result.TotalBlocks++
		if status == 1 {
			result.ActiveBlocks++
		} else {
			result.RevokedBlocks++
		}

		// Legacy record with no chain hash — cannot verify, treat as break
		if vcHash == "" || prevVCHash == "" {
			result.Intact = false
			result.BreakAtVcID = vcID
			result.Message = "Record missing chain hash. Re-mint to establish chain."
			return result
		}

		// 1. Verify prev_vc_hash links correctly to the previous block
		if prevVCHash != expectedPrevHash {
			result.Intact = false
			result.BreakAtVcID = vcID
			result.Message = "Chain linkage broken — previous hash mismatch."
			return result
		}

		// 2. Recompute and verify the record's own hash
		computed := computeSHA256(vcID + "|" + prevVCHash + "|" + fullJSON)
		if computed != vcHash {
			result.Intact = false
			result.BreakAtVcID = vcID
			result.Message = "Record hash invalid — content has been tampered with."
			return result
		}

		expectedPrevHash = vcHash
	}

	if result.TotalBlocks == 0 {
		result.Message = "Ledger is empty — genesis state."
	} else {
		result.Message = fmt.Sprintf("%d block(s) verified.", result.TotalBlocks)
	}
	return result
}

// GetSnapshotsByPaths fetches the latest snapshots for specific file paths
func (db *VeriHashDB) GetSnapshotsByPaths(paths []string) ([]Snapshot, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	// Dynamic IN clause building
	placeholders := ""
	args := make([]interface{}, len(paths))
	for i, path := range paths {
		if i > 0 {
			placeholders += ", "
		}
		placeholders += "?"
		args[i] = path // Allow exact match of what JS sends, which will match what DB sent to JS
	}

	query := fmt.Sprintf("SELECT id, timestamp, file_path, content_diff, current_hash, previous_hash FROM file_snapshots WHERE file_path IN (%s) ORDER BY id DESC", placeholders)
	
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snaps []Snapshot
	for rows.Next() {
		var s Snapshot
		if err := rows.Scan(&s.ID, &s.Timestamp, &s.FilePath, &s.ContentDiff, &s.CurrentHash, &s.PreviousHash); err != nil {
			return nil, err
		}
		snaps = append(snaps, s)
	}
	return snaps, nil
}
