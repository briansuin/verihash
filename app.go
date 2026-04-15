package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/zalando/go-keyring"
)

// Config represents persistent application settings
type Config struct {
	Workspaces []string `json:"workspaces"`
	AIEngine   string   `json:"ai_engine"`
	ModelName  string   `json:"model_name"`
	APIKey     string   `json:"api_key"`
	BaseURL        string   `json:"base_url"`
	AutoStart      bool     `json:"auto_start"`
	CloudSyncDirs  []string `json:"cloud_sync_dirs"`
}

// LedgerEntry is a summary row of a past minting session
type LedgerEntry struct {
	VcID           string  `json:"vc_id"`
	Timestamp      float64 `json:"timestamp"`
	ProjectContext string  `json:"project_context"`
	AiInsight      string  `json:"ai_insight"`
	FilePaths      string  `json:"file_paths"`
	Status         int     `json:"status"`
	VcHash         string  `json:"vc_hash"`
	AiEngine       string  `json:"ai_engine"`
}

// App struct
type App struct {
	ctx          context.Context
	db           *VeriHashDB
	pubKey       ed25519.PublicKey
	privKey      ed25519.PrivateKey
	walletStatus WalletStatus // current key file state
	mnemonic     string       // temporary storage for new wallet mnemonic
	watchDirs    []string
	aiEngine     string
	modelName    string
	apiKey       string
	baseURL       string
	cloudSyncDirs []string
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// 1. Initialize DB
	err := initDB()
	if err != nil {
		log.Fatalf("Fatal Error: Failed to initialize DB: %v\n", err)
	}
	db, err := connectDB()
	if err != nil {
		log.Fatalf("Fatal Error: Database connection failed: %v", err)
	}
	a.db = db

	// 2. Initialize Crypto — detect key file state
	pubKey, privKey, status, mnemonic, cryptoErr := initCrypto()
	if cryptoErr != nil {
		log.Fatalf("Fatal Error: Crypto initialization failed: %v", cryptoErr)
	}
	a.walletStatus = status
	a.mnemonic = mnemonic
	switch status {
	case WalletStatusNew:
		// New keypair in memory; will be persisted when user sets wallet password
		a.pubKey = pubKey
		a.privKey = privKey
	case WalletStatusEncrypted:
		// Attempt Auto-Unlock from persistent Keyring
		pwd, err := keyring.Get("VeriHash", "vault_password")
		if err == nil && pwd != "" {
			pubKey, privKey, err := loadEncryptedKey(pwd)
			if err == nil {
				a.pubKey = pubKey
				a.privKey = privKey
			} else {
				a.pubKey = pubKey // Keep pubKey for DID display
				a.privKey = nil   // Stay locked
			}
		} else {
			// Key on disk is encrypted; wait for UnlockWallet() call from UI
			a.pubKey = pubKey // Keep pubKey for DID display
			a.privKey = nil
		}
	case WalletStatusPlaintext:
		// Legacy plaintext key loaded; UI will prompt migration
		a.pubKey = pubKey
		a.privKey = privKey
	}

	setupSystemTray(ctx)
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[SYSTEM] Booting VeriHash Core...", "type": "sys"})

	// 3. Load config so cloudSyncDirs are available at startup
	a.LoadConfig()

	// 4. Silently repair the historic JSON chain on all bound cloud directories in background
	if len(a.cloudSyncDirs) > 0 {
		go func() {
			for _, dir := range a.cloudSyncDirs {
				a.SyncHistoricLedger(dir)
			}
		}()
	}
}

// GetWalletStatus returns the wallet state for the frontend to act on.
// Returns: "new" (first run), "encrypted" (needs unlock), "plaintext" (needs migration), or "unlocked"
func (a *App) GetWalletStatus() string {
	switch a.walletStatus {
	case WalletStatusNew:
		return "new"
	case WalletStatusEncrypted:
		if a.privKey != nil {
			return "unlocked"
		}
		return "encrypted"
	case WalletStatusPlaintext:
		return "plaintext"
	}
	return "unlocked"
}

// walletIsLocked returns true when no private key is loaded.
func (a *App) walletIsLocked() bool {
	return a.privKey == nil
}

// InitWallet is called on first run to set a wallet password and persist the new key.
func (a *App) InitWallet(password, confirm string) string {
	if a.walletStatus != WalletStatusNew {
		return `{"error": "Wallet already initialized."}`
	}
	if password == "" {
		return `{"error": "A wallet password is required."}`
	}
	if len(password) < 8 {
		return `{"error": "Password must be at least 8 characters."}`
	}
	if password != confirm {
		return `{"error": "Passwords do not match."}`
	}
	if a.privKey == nil {
		return `{"error": "No key in memory. Please restart the app."}`
	}
	if err := saveEncryptedKeyFile(a.privKey, a.pubKey, password); err != nil {
		return `{"error": "Failed to save encrypted key: ` + err.Error() + `"}`
	}
	// Securely park token in OS keychain for auto-boot
	keyring.Set("VeriHash", "vault_password", password)
	
	a.walletStatus = WalletStatusEncrypted
	did := pubKeyToDIDKey(a.pubKey)
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[SYSTEM] Wallet initialized with encryption. Identity: " + did[:32] + "...", "type": "sys"})
	return `{"status": "initialized", "did": "` + did + `"}`
}

// UnlockWallet decrypts the key file with the given password and loads the keypair into memory.
func (a *App) UnlockWallet(password string) string {
	if password == "" {
		return `{"error": "Password is required."}`
	}
	pubKey, privKey, err := loadEncryptedKey(password)
	if err != nil {
		return `{"error": "` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	a.pubKey = pubKey
	a.privKey = privKey
	a.walletStatus = WalletStatusEncrypted // stays encrypted on disk
	
	// Securely park token in OS keychain for auto-boot
	keyring.Set("VeriHash", "vault_password", password)
	
	did := pubKeyToDIDKey(pubKey)
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[SYSTEM] Identity Loaded: " + did[:32] + "...", "type": "sys"})
	return `{"status": "unlocked", "did": "` + did + `"}`
}

// MigrateWallet encrypts an existing plaintext key file using a new wallet password.
func (a *App) MigrateWallet(password, confirm string) string {
	if a.walletStatus != WalletStatusPlaintext {
		return `{"error": "Migration only applies to existing plaintext key files."}`
	}
	if password == "" {
		return `{"error": "A wallet password is required."}`
	}
	if len(password) < 8 {
		return `{"error": "Password must be at least 8 characters."}`
	}
	if password != confirm {
		return `{"error": "Passwords do not match."}`
	}
	if a.privKey == nil {
		return `{"error": "No key loaded. Please restart the app."}`
	}
	if err := saveEncryptedKeyFile(a.privKey, a.pubKey, password); err != nil {
		return `{"error": "Failed to encrypt key file: ` + err.Error() + `"}`
	}
	// Securely park token in OS keychain for auto-boot
	keyring.Set("VeriHash", "vault_password", password)
	
	a.walletStatus = WalletStatusEncrypted
	did := pubKeyToDIDKey(a.pubKey)
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[SYSTEM] Key file migrated to encrypted format.", "type": "sys"})
	return `{"status": "migrated", "did": "` + did + `"}`
}

// GetMnemonic returns the generated mnemonic for a NEW wallet.
// It clears it from memory after being called for security.
func (a *App) GetMnemonic() string {
	m := a.mnemonic
	a.mnemonic = "" // Clear after one-time retrieval
	return m
}

// LockVault manually locks the workspace and removes auto-boot keychain tokens.
func (a *App) LockVault() string {
	a.privKey = nil // Only clear private security context
	keyring.Delete("VeriHash", "vault_password")
	return `{"status": "locked"}`
}

// GetDID returns the W3C-compliant did:key identifier for this node
func (a *App) GetDID() string {
	if a.pubKey != nil {
		return pubKeyToDIDKey(a.pubKey)
	}
	return "UNKNOWN_IDENTITY"
}

// LoadConfig loads memory from disk
func (a *App) LoadConfig() Config {
	var cfg Config
	bytes, err := os.ReadFile("verihash_config.json")
	if err == nil {
		json.Unmarshal(bytes, &cfg)
		a.watchDirs = cfg.Workspaces
		a.aiEngine = cfg.AIEngine
		a.modelName = cfg.ModelName
		a.apiKey = cfg.APIKey
		a.baseURL = cfg.BaseURL
		a.cloudSyncDirs = cfg.CloudSyncDirs
	}
	return cfg
}

// SelectDirectory opens the native OS directory selector
func (a *App) SelectDirectory() string {
	dir, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Workspace to Monitor",
	})
	if err != nil || dir == "" {
		return ""
	}
	return dir
}

// SaveConfig stores the AI and UI configuration in memory and JSON disk
func (a *App) SaveConfig(workspaces []string, engine, modelName, key, baseURL string, cloudSyncDirs []string) string {
	a.watchDirs = workspaces
	a.aiEngine = engine
	a.modelName = modelName
	a.apiKey = key
	a.baseURL = baseURL
	a.cloudSyncDirs = cloudSyncDirs

	// Preserve fields not managed by this call (e.g. AutoStart set by ToggleAutoStart)
	var existingCfg Config
	if existingBytes, err := os.ReadFile("verihash_config.json"); err == nil {
		json.Unmarshal(existingBytes, &existingCfg)
	}

	cfg := Config{
		Workspaces:    workspaces,
		AIEngine:      engine,
		ModelName:     modelName,
		APIKey:        key,
		BaseURL:       baseURL,
		CloudSyncDirs: cloudSyncDirs,
		AutoStart:     existingCfg.AutoStart, // preserve existing toggle state
	}
	bytes, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("verihash_config.json", bytes, 0644)
	return "OK"
}

// StartWatchdog starts the physical directory monitoring for all active workspaces
func (a *App) StartWatchdog() string {
	if len(a.watchDirs) == 0 {
		return "Error: No directories to monitor"
	}
	// Note: You must stop old watchdogs if restarting, but for now we launch new ones
	// A proper implementation should manage watchdog lifecycles per directory.
	for _, dir := range a.watchDirs {
		go startWatchdog(a.ctx, dir, a.db, a.privKey)
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[WATCHDOG] Active Target Hooked: " + filepath.Base(dir), "type": "sys"})
	}
	return "Started"
}

// TriggerMint runs the Oracle evaluation for specifically checked files
func (a *App) TriggerMint(selectedFiles []string, workspacePath string) string {
	if a.walletIsLocked() {
		return `{"error": "Wallet is locked. Enter your wallet password to unlock."}`
	}
	if len(selectedFiles) == 0 {
		return `{"error": "No files selected for contextual minting"}`
	}
	engineParam := a.aiEngine
	if a.aiEngine != "ollama" && a.modelName != "" {
		engineParam = a.aiEngine + ":" + a.modelName
	}
	result := MintCredential(a.ctx, a.db, a.pubKey, a.privKey, engineParam, a.apiKey, a.baseURL, selectedFiles, workspacePath)
	
	// If successful and we have Cloud Sync Dirs configured, trigger replication
	if !strings.Contains(result, `"error":`) && len(a.cloudSyncDirs) > 0 {
		var parseResult map[string]interface{}
		if err := json.Unmarshal([]byte(result), &parseResult); err == nil {
			// VC JSON uses "id" not "vc_id"
			if vcID, ok := parseResult["id"].(string); ok {
				go a.replicateToCloud(vcID, selectedFiles)
			}
		}
	}
	
	return result
}

// GetWorkspaceFiles returns uniquely modified files for a requested workspace
func (a *App) GetWorkspaceFiles(workspace string) []string {
	workspacePath := filepath.ToSlash(workspace)
	if !strings.HasSuffix(workspacePath, "/") {
		workspacePath += "/"
	}
	
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[DEBUG-TRACE] Resolving workspace: %s", workspacePath), "type": "sys"})

	var finalFiles []string
	
	// Physically scan the actual disk so the UI shows ALL files, not just modified ones.
	var scanDir func(string)
	scanDir = func(currentDir string) {
		entries, err := os.ReadDir(currentDir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			// Skip hidden files/folders (e.g. .git, .idea)
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			
			fullPath := filepath.Join(currentDir, entry.Name())
			if entry.IsDir() {
				scanDir(fullPath)
			} else {
				// Only add valid files
				finalFiles = append(finalFiles, filepath.ToSlash(fullPath))
			}
		}
	}
	
	scanDir(workspace)
	
	hitCount := len(finalFiles)
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[DEBUG-TRACE] Physical scan returned %d active files for UI", hitCount), "type": "sys"})
	return finalFiles
}

// GetLedger returns all active credentials from the database, ordered newest first
func (a *App) GetLedger() []LedgerEntry {
	rows, err := a.db.conn.Query(`
		SELECT vc_id, timestamp, project_context, ai_insight, file_paths, status, COALESCE(vc_hash, ''), full_vc_json
		FROM session_credentials
		WHERE status = 1
		ORDER BY timestamp DESC
	`)
	if err != nil {
		return []LedgerEntry{}
	}
	defer rows.Close()

	var entries []LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		var fullJsonStr string
		if err := rows.Scan(&e.VcID, &e.Timestamp, &e.ProjectContext, &e.AiInsight, &e.FilePaths, &e.Status, &e.VcHash, &fullJsonStr); err != nil {
			continue
		}
		
		// Parse AI engine from full VC JSON
		var vc VCSchema
		if err := json.Unmarshal([]byte(fullJsonStr), &vc); err == nil {
			e.AiEngine = vc.CredentialSubject.ProofOfWork.AIEngine
		}

		entries = append(entries, e)
	}
	return entries
}

// VerifyCredential cryptographically verifies the Ed25519 signature of an exported VC JSON.
// Works for credentials minted by this node or received externally.
func (a *App) VerifyCredential(vcJSON string) string {
	valid, errMsg := verifyCredentialDoc(vcJSON)
	if errMsg != "" {
		return `{"valid": false, "error": "` + strings.ReplaceAll(errMsg, `"`, `'`) + `"}`
	}
	if valid {
		return `{"valid": true}`
	}
	return `{"valid": false, "error": "Signature mismatch"}`
}

func (a *App) VerifyChain() string {
	result := a.db.VerifyChainIntegrity()
	bytes, _ := json.Marshal(result)
	return string(bytes)
}

// ExportCredentialJSON returns the full VC JSON for a given credential ID.
// IMPORTANT: This version contains Private Local Metadata (full paths).
func (a *App) ExportCredentialJSON(vcID string) string {
	var fullJSON string
	err := a.db.conn.QueryRow(
		`SELECT full_vc_json FROM session_credentials WHERE vc_id = ?`, vcID,
	).Scan(&fullJSON)
	if err != nil {
		return `{"error": "Credential not found"}`
	}
	return fullJSON
}

// ExportSanitizedJSON returns a privacy-scrubbed version of the VC JSON.
// It removes the localMetadata block (containing full paths) so it's safe for public sharing.
func (a *App) ExportSanitizedJSON(vcID string) string {
	rawJSON := a.ExportCredentialJSON(vcID)
	if strings.Contains(rawJSON, `"error"`) {
		return rawJSON
	}

	var vc VCSchema
	if err := json.Unmarshal([]byte(rawJSON), &vc); err != nil {
		return `{"error": "Failed to parse credential: ` + err.Error() + `"}`
	}

	// Scrub Private Data
	vc.LocalMetadata = nil

	sanitized, _ := json.MarshalIndent(vc, "", "  ")
	return string(sanitized)
}

// RestoreDataFromSync deep-scans all linked cloud sync directories to reconstruct
// the local SQLite ledger from discovered JSON credentials.
func (a *App) RestoreDataFromSync() string {
	if a.pubKey == nil {
		return `{"error": "Identity is locked. Please unlock to verify and restore data."}`
	}
	currentDID := pubKeyToDIDKey(a.pubKey)
	
	totalFound := 0
	totalRestored := 0
	
	for _, syncDir := range a.cloudSyncDirs {
		archiveDir := filepath.Join(syncDir, "VeriHash_Archive")
		if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
			continue
		}

		files, _ := os.ReadDir(archiveDir)
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			totalFound++

			filePath := filepath.Join(archiveDir, f.Name())
			data, err := os.ReadFile(filePath)
			if err != nil { continue }

			// 1. Cryptographic Verification
			valid, _ := verifyCredentialDoc(string(data))
			if !valid { continue }

			// 2. Identity Match Check
			var vc VCSchema
			json.Unmarshal(data, &vc)
			if vc.Issuer != currentDID { continue }

			// 3. Check for existence in local DB
			var exists int
			a.db.conn.QueryRow(`SELECT COUNT(*) FROM session_credentials WHERE vc_id = ?`, vc.ID).Scan(&exists)
			if exists > 0 { continue }

			// 4. Reconstruction and Injection
			// Extract paths from LocalMetadata (for personal reference) or fallback to Files manifest
			pathStr := ""
			if vc.LocalMetadata != nil && len(vc.LocalMetadata.FullPaths) > 0 {
				pathStr = strings.Join(vc.LocalMetadata.FullPaths, ",")
			} else {
				var names []string
				for _, f := range vc.CredentialSubject.ProofOfWork.Files {
					names = append(names, f.Name)
				}
				pathStr = strings.Join(names, ",")
			}

			vcHash := computeSHA256(vc.ID + "|" + vc.Proof.PreviousVCHash + "|" + string(data))

			_, dbErr := a.db.conn.Exec(`
				INSERT INTO session_credentials
				(vc_id, timestamp, project_context, ai_insight, skill_tags, file_paths, full_vc_json, status, vc_hash, prev_vc_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
			`, 
				vc.ID,
				float64(time.Now().UnixNano())/1e9, // record approximate restoration time
				"", // project context lost in JSON, but metadata could be expanded later
				vc.CredentialSubject.ProofOfWork.AIEvaluation,
				"",
				pathStr,
				string(data),
				vcHash,
				vc.Proof.PreviousVCHash,
			)

			if dbErr == nil {
				totalRestored++
			}
		}
	}

	result := fmt.Sprintf(`{"found": %d, "restored": %d}`, totalFound, totalRestored)
	runtime.EventsEmit(a.ctx, "log", map[string]string{
		"msg": fmt.Sprintf("[RESTORE] Scan complete. %d records found, %d uniquely reconstructed.", totalFound, totalRestored),
		"type": "sys",
	})
	return result
}

func (a *App) GenerateHistoricReports() {
}

// GenerateHTMLReport manually triggers the professional HTML report generation
// for a historical credential stored in the ledger.
func (a *App) GenerateHTMLReport(vcID string, customTitle string) string {
	rawJSON := a.ExportCredentialJSON(vcID)
	if strings.Contains(rawJSON, `"error"`) {
		return rawJSON
	}

	var vc VCSchema
	if err := json.Unmarshal([]byte(rawJSON), &vc); err != nil {
		return `{"error": "Failed to parse credential: ` + err.Error() + `"}`
	}

	err := GenerateReport(vc, customTitle)
	if err != nil {
		return `{"error": "Failed to generate HTML: ` + err.Error() + `"}`
	}

	return `{"status": "OK"}`
}

// RevokeCredential soft-deletes a credential by setting status = 0.
// The record remains in the database to preserve hash chain integrity.
func (a *App) RevokeCredential(vcID string) string {
	_, err := a.db.conn.Exec(
		`UPDATE session_credentials SET status = 0 WHERE vc_id = ?`, vcID,
	)
	if err != nil {
		return `{"error": "` + err.Error() + `"}`
	}
	
	// Ensure cloud sync consistency: delete the revoked JSON from all mapped cloud drives
	cleanVcID := strings.ReplaceAll(vcID, ":", "_")
	for _, syncDir := range a.cloudSyncDirs {
		jsonPath := filepath.Join(syncDir, "VeriHash_Archive", fmt.Sprintf("VeriHash_%s.json", cleanVcID))
		_ = os.Remove(jsonPath) // silently ignore if file not found
	}
	
	return `{"status": "OK"}`
}


// SaveToFile opens the native OS Save-As dialog and writes content to the chosen path.
// Returns the saved path on success, or a JSON error string on failure / cancellation.
func (a *App) SaveToFile(defaultFilename, content string) string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: defaultFilename,
		Title:           "Save File",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON Files (*.json)", Pattern: "*.json"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return `{"error": "Dialog error: ` + err.Error() + `"}`
	}
	if path == "" {
		// User cancelled
		return `{"cancelled": true}`
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return `{"error": "Write failed: ` + err.Error() + `"}`
	}
	return `{"saved": true, "path": "` + strings.ReplaceAll(path, `\`, `\\`) + `"}`
}


// IdentityBundle is the portable identity package for cross-machine migration
type IdentityBundle struct {
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKey     string `json:"public_key"`
	DID           string `json:"did"`
	CreatedAt     string `json:"created_at"`
	ExportedAt    string `json:"exported_at"`
	Note          string `json:"note"`
}

// ExportIdentityBundle encrypts the private key with the current vault password
// and returns an AES-256-GCM encrypted bundle JSON.
func (a *App) ExportIdentityBundle() string {
	if a.walletIsLocked() {
		return `{"error": "Wallet is locked. Please unlock your vault before exporting."}`
	}

	// Retrieve current password from OS Keyring
	password, err := keyring.Get("VeriHash", "vault_password")
	if err != nil || password == "" {
		return `{"error": "Could not retrieve vault password from secure storage. Please re-enter your password to unlock."}`
	}

	privHex, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return `{"error": "Cannot read private key file. File may not exist."}`
	}
	identityBytes, err := os.ReadFile(identityFile)
	if err != nil {
		return `{"error": "Cannot read identity file."}`
	}
	var identity NodeIdentity
	if err := json.Unmarshal(identityBytes, &identity); err != nil {
		return `{"error": "Identity file is corrupted."}`
	}

	inner := IdentityBundle{
		PrivateKeyHex: string(privHex),
		PublicKey:     identity.PublicKey,
		DID:           pubKeyToDIDKey(a.pubKey),
		CreatedAt:     identity.CreatedAt,
		ExportedAt:    time.Now().Format(time.RFC3339),
		Note:          "VeriHash Identity Bundle — Keep this file safe and NEVER share it.",
	}
	innerJSON, err := json.Marshal(inner)
	if err != nil {
		return `{"error": "Failed to serialize identity bundle."}`
	}

	// Encrypt with Argon2id + AES-256-GCM
	encryptedJSON, err := encryptBundleData(innerJSON, password, pubKeyToDIDKey(a.pubKey))
	if err != nil {
		return `{"error": "Encryption failed: ` + err.Error() + `"}`
	}
	return string(encryptedJSON)
}

// ImportIdentityBundle decrypts an encrypted identity bundle and restores the private key.
// The same backup password used during export is required to decrypt.
func (a *App) ImportIdentityBundle(jsonContent, password string) string {
	if password == "" {
		return `{"error": "Bundle password is required to import."}`
	}

	// 1. Decrypt the bundle
	plaintext, err := decryptBundleData([]byte(jsonContent), password)
	if err != nil {
		return `{"error": "` + err.Error() + `"}`
	}

	// 2. Parse the inner IdentityBundle
	var bundle IdentityBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return `{"error": "Decrypted data is not a valid identity bundle."}`
	}
	if bundle.PrivateKeyHex == "" {
		return `{"error": "Bundle is missing private key data."}`
	}

	// 3. Validate private key integrity
	privBytes, err := hex.DecodeString(bundle.PrivateKeyHex)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return `{"error": "Bundle private key is invalid or corrupted."}`
	}
	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)
	derived := pubKeyToDIDKey(pubKey)
	// Accept both legacy hex format and new base58btc format for backward compat
	if bundle.DID != "" && bundle.DID != derived {
		// Re-derive with legacy format for backward compat
		legacy := "did:key:ed25519:" + hex.EncodeToString(pubKey)
		if bundle.DID != legacy {
			return `{"error": "Bundle integrity check FAILED: private key does not match the DID."}`
		}
	}

	// 4. Backup existing keys before overwriting
	if _, err := os.Stat(privateKeyFile); err == nil {
		os.Rename(privateKeyFile, privateKeyFile+".bak")
	}
	if _, err := os.Stat(identityFile); err == nil {
		os.Rename(identityFile, identityFile+".bak")
	}

	// 5. Write new keys
	if err := os.WriteFile(privateKeyFile, []byte(bundle.PrivateKeyHex), 0600); err != nil {
		return fmt.Sprintf(`{"error": "Failed to write private key: %v"}`, err)
	}
	pubHex := hex.EncodeToString(pubKey)
	newIdentity := NodeIdentity{
		PublicKey: pubHex,
		DID:       derived,
		CreatedAt: bundle.CreatedAt,
	}
	newIdentityBytes, _ := json.MarshalIndent(newIdentity, "", "  ")
	if err := os.WriteFile(identityFile, newIdentityBytes, 0644); err != nil {
		return fmt.Sprintf(`{"error": "Failed to write identity file: %v"}`, err)
	}

	return `{"status": "OK", "did": "` + derived + `"}`
}

// ImportMnemonic decrypts the BIP39 mathematical seed to restore an identity.
// The new identity is then locally encrypted using the provided newPassword.
func (a *App) ImportMnemonic(mnemonic, newPassword, confirm string) string {
	if mnemonic == "" {
		return `{"error": "Recovery phrase is required."}`
	}
	if newPassword == "" {
		return `{"error": "A new vault password is required to encrypt the restored identity."}`
	}
	if len(newPassword) < 8 {
		return `{"error": "Password must be at least 8 characters."}`
	}
	if newPassword != confirm {
		return `{"error": "Passwords do not match."}`
	}

	pubKey, privKey, err := restoreKeypairFromMnemonic(mnemonic)
	if err != nil {
		return `{"error": "` + err.Error() + `"}`
	}

	// Backup existing keys before overwriting
	if _, err := os.Stat(privateKeyFile); err == nil {
		os.Rename(privateKeyFile, privateKeyFile+".bak")
	}
	if _, err := os.Stat(identityFile); err == nil {
		os.Rename(identityFile, identityFile+".bak")
	}

	// Encrypt & Save new keys
	err = saveEncryptedKeyFile(privKey, pubKey, newPassword)
	if err != nil {
		return `{"error": "Failed to encrypt restored key: ` + err.Error() + `"}`
	}

	// Refresh Context & OS Keyring
	keyring.Set("VeriHash", "vault_password", newPassword)
	
	// Force the internal context to drop the running key and demand a restart, or just inject it.
	// We'll return OK and let the frontend reboot.
	return `{"status": "OK", "did": "` + pubKeyToDIDKey(pubKey) + `"}`
}

// replicateToCloud writes the signed JSON credential directly into the flat
// VeriHash_Archive directory in each configured cloud sync folder.
func (a *App) replicateToCloud(vcID string, sourceFiles []string) {
	// Fetch the full constructed JSON from DB
	var fullJsonStr string
	err := a.db.conn.QueryRow(`SELECT full_vc_json FROM session_credentials WHERE vc_id = ?`, vcID).Scan(&fullJsonStr)
	if err != nil || fullJsonStr == "" {
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[CLOUD-SYNC] Warning: Could not locate VC JSON for %s", vcID), "type": "err"})
		return
	}

	cleanVcID := strings.ReplaceAll(vcID, ":", "_")

	for _, syncDir := range a.cloudSyncDirs {
		archiveDir := filepath.Join(syncDir, "VeriHash_Archive")
		if err := os.MkdirAll(archiveDir, 0755); err != nil {
			runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[CLOUD-SYNC] Failed to create archive dir: %v", err), "type": "err"})
			continue
		}

		jsonName := fmt.Sprintf("VeriHash_%s.json", cleanVcID)
		_ = os.WriteFile(filepath.Join(archiveDir, jsonName), []byte(fullJsonStr), 0644)

		runtime.EventsEmit(a.ctx, "log", map[string]string{
			"msg":  fmt.Sprintf("[CLOUD-SYNC] ✓ Synced %s.json → %s", cleanVcID[:20]+"...", filepath.Base(syncDir)),
			"type": "sys",
		})
	}
}

// SyncHistoricLedger extracts ALL previously minted VC JSONs from the database
// and writes them flat into the VeriHash_Archive directory of the specified path.
// This ensures the cryptographic PreviousVCHash chain is physically continuous
// in the cloud even if the directory was bound after minting began.
func (a *App) SyncHistoricLedger(targetDir string) string {
	rows, err := a.db.conn.Query(`SELECT vc_id, full_vc_json FROM session_credentials WHERE status = 1`)
	if err != nil {
		return `{"error": "Failed to query historic ledger: ` + err.Error() + `"}`
	}
	defer rows.Close()

	archiveDir := filepath.Join(targetDir, "VeriHash_Archive")
	_ = os.MkdirAll(archiveDir, 0755)

	count := 0
	for rows.Next() {
		var vcID, fullJsonStr string
		if err := rows.Scan(&vcID, &fullJsonStr); err == nil && fullJsonStr != "" {
			cleanVcID := strings.ReplaceAll(vcID, ":", "_")
			jsonPath := filepath.Join(archiveDir, fmt.Sprintf("VeriHash_%s.json", cleanVcID))

			// Only write if not already present
			if _, statErr := os.Stat(jsonPath); os.IsNotExist(statErr) {
				_ = os.WriteFile(jsonPath, []byte(fullJsonStr), 0644)
				count++
			}
		}
	}

	msg := fmt.Sprintf("[CLOUD-SYNC] Historic chain repair complete: %d credential(s) pushed to %s", count, filepath.Base(targetDir))
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": msg, "type": "sys"})
	return fmt.Sprintf(`{"status": "OK", "synced": %d}`, count)
}
