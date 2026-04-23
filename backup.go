package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ── .vhb Cold Backup Format ───────────────────────────────────────────────────
//
// A .vhb (VeriHash Backup) file is an AES-256-GCM encrypted JSON (EncryptedBundle)
// whose plaintext is a ZIP archive containing:
//   - proof_of_work.db   — the full credential ledger
//   - node_identity.json — the public DID profile (NO private key)
//
// The encryption key is derived from the user's BACKUP PASSWORD via Argon2id.
// This password is INDEPENDENT of the vault password — deliberately so.
// The private key is never included; identity recovery uses the 12-word mnemonic.
//
// Import flow on a new machine:
//   ① Select .vhb + enter backup password → restore ledger DB
//   ② Enter 12-word mnemonic → rebuild private key mathematically
//   ③ Set new vault password → encrypt rebuilt key to disk

const (
	// dbFile is declared in database_wrapper.go
	vhbNote       = "VeriHash Cold Backup (.vhb) — Ledger + Public Identity. NO private key. Restore identity via mnemonic."
	vhbVersion    = "v2-encrypted"
	vhbDBEntry    = "proof_of_work.db"
	vhbIdentEntry = "node_identity.json"
)

// VHBManifest is stored inside the zip as manifest.json, providing metadata
// for integrity checks and user-facing information at import time.
type VHBManifest struct {
	VHBVersion    string `json:"vhb_version"`    // "1.0"
	DID           string `json:"did"`
	ExportedAt    string `json:"exported_at"`
	CredentialCount int   `json:"credential_count"`
	DBSizeBytes   int64  `json:"db_size_bytes"`
}

// createVHBArchive builds the in-memory ZIP containing the DB, identity, and manifest.
func createVHBArchive(db *VeriHashDB, did string) ([]byte, error) {
	// 1. Checkpoint the WAL so the DB file is fully consistent before we read it.
	if _, err := db.conn.Exec(`PRAGMA wal_checkpoint(FULL);`); err != nil {
		// Non-fatal — proceed anyway; SQLite will still give a consistent snapshot
		_ = err
	}

	// 2. Count credentials for manifest
	var credCount int
	db.conn.QueryRow(`SELECT COUNT(*) FROM session_credentials`).Scan(&credCount)

	// 3. Read the DB file bytes
	dbBytes, err := os.ReadFile(dbFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read database: %w", err)
	}

	// 4. Read the identity file bytes
	identBytes, err := os.ReadFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read identity file: %w", err)
	}

	// 5. Build manifest
	manifest := VHBManifest{
		VHBVersion:      "1.0",
		DID:             did,
		ExportedAt:      time.Now().UTC().Format(time.RFC3339),
		CredentialCount: credCount,
		DBSizeBytes:     int64(len(dbBytes)),
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	// 6. Build in-memory ZIP
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addFile := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}

	if err := addFile(vhbDBEntry, dbBytes); err != nil {
		return nil, fmt.Errorf("zip DB: %w", err)
	}
	if err := addFile(vhbIdentEntry, identBytes); err != nil {
		return nil, fmt.Errorf("zip identity: %w", err)
	}
	if err := addFile("manifest.json", manifestBytes); err != nil {
		return nil, fmt.Errorf("zip manifest: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zip close: %w", err)
	}
	return buf.Bytes(), nil
}

// ExportVHB creates a .vhb cold backup and writes it to the user-chosen path.
// backupPassword is independent of the vault password. confirmPassword must match.
// Returns the path of the saved file on success.
func ExportVHB(db *VeriHashDB, did, backupPassword, confirmPassword string) (string, error) {
	if backupPassword == "" {
		return "", fmt.Errorf("backup password cannot be empty")
	}
	if len(backupPassword) < 6 {
		return "", fmt.Errorf("backup password must be at least 6 characters")
	}
	if backupPassword != confirmPassword {
		return "", fmt.Errorf("passwords do not match")
	}

	// Build zip archive in memory
	zipBytes, err := createVHBArchive(db, did)
	if err != nil {
		return "", fmt.Errorf("archive creation failed: %w", err)
	}

	// Encrypt the zip archive using the backup password
	encJSON, err := encryptBundleData(zipBytes, backupPassword, did)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	// Use a timestamped default filename in the current working directory
	ts := time.Now().Format("2006-01-02_1504")
	filename := fmt.Sprintf("verihash_backup_%s.vhb", ts)
	savePath := filepath.Join(".", filename)

	if err := os.WriteFile(savePath, encJSON, 0600); err != nil {
		return "", fmt.Errorf("cannot write backup file: %w", err)
	}
	absPath, _ := filepath.Abs(savePath)
	return absPath, nil
}

// ImportVHB decrypts and restores a .vhb cold backup file.
//
// The restore is deliberately CONSERVATIVE:
//   - It writes to a staging path first and only renames on success.
//   - The active DB and identity file are backed up to .bak before overwrite.
//   - The private key and vault password are NEVER touched — caller must
//     prompt for mnemonic re-entry separately.
//
// Returns the VHBManifest on success so the UI can display what was restored.
func ImportVHB(vhbPath, backupPassword string) (*VHBManifest, error) {
	if backupPassword == "" {
		return nil, fmt.Errorf("backup password cannot be empty")
	}

	// 1. Read and decrypt the .vhb file
	encData, err := os.ReadFile(vhbPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open backup file: %w", err)
	}
	zipBytes, err := decryptBundleData(encData, backupPassword)
	if err != nil {
		return nil, err // user-friendly message already set by decryptBundleData
	}

	// 2. Open the decrypted ZIP archive
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("invalid backup archive (not a zip)")
	}

	// 3. Extract required entries
	fileMap := make(map[string][]byte)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("cannot read archive entry %q: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("cannot read archive entry %q: %w", f.Name, err)
		}
		fileMap[f.Name] = data
	}

	// Validate required files exist
	dbData, ok := fileMap[vhbDBEntry]
	if !ok {
		return nil, fmt.Errorf("backup archive is missing the database file")
	}
	identData, ok := fileMap[vhbIdentEntry]
	if !ok {
		return nil, fmt.Errorf("backup archive is missing the identity file")
	}

	// Parse manifest (optional but informative)
	var manifest VHBManifest
	if manifestData, ok := fileMap["manifest.json"]; ok {
		_ = json.Unmarshal(manifestData, &manifest)
	}

	// 4. Write to staging files first
	stagingDB := dbFile + ".vhb_staging"
	stagingIdent := identityFile + ".vhb_staging"

	if err := os.WriteFile(stagingDB, dbData, 0644); err != nil {
		return nil, fmt.Errorf("staging write failed: %w", err)
	}
	if err := os.WriteFile(stagingIdent, identData, 0644); err != nil {
		os.Remove(stagingDB)
		return nil, fmt.Errorf("staging write failed: %w", err)
	}

	// 5. Backup active files (best-effort)
	if existing, err := os.ReadFile(dbFile); err == nil {
		_ = os.WriteFile(dbFile+".bak", existing, 0644)
	}
	if existing, err := os.ReadFile(identityFile); err == nil {
		_ = os.WriteFile(identityFile+".bak", existing, 0644)
	}

	// 6. Atomic rename: staging → live
	if err := os.Rename(stagingDB, dbFile); err != nil {
		os.Remove(stagingDB)
		os.Remove(stagingIdent)
		return nil, fmt.Errorf("cannot activate restored database: %w", err)
	}
	if err := os.Rename(stagingIdent, identityFile); err != nil {
		// DB already renamed; try to roll back
		if bak, e2 := os.ReadFile(dbFile + ".bak"); e2 == nil {
			_ = os.WriteFile(dbFile, bak, 0644)
		}
		os.Remove(stagingIdent)
		return nil, fmt.Errorf("cannot activate restored identity: %w", err)
	}

	return &manifest, nil
}
