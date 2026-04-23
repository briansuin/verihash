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
	"strconv"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/zalando/go-keyring"
)

// Config represents persistent application settings
type Config struct {
	Workspaces      []string            `json:"workspaces"`
	AIEngine        string              `json:"ai_engine"`
	ModelName       string              `json:"model_name"`
	APIKey          string              `json:"api_key"`
	BaseURL         string              `json:"base_url"`
	AutoStart       bool                `json:"auto_start"`
	CloudSyncDirs   []string            `json:"cloud_sync_dirs"`
	IgnoredPatterns []string            `json:"ignored_patterns"`
	SessionIgnores  map[string][]string `json:"session_ignores"`
	GitHubPAT       string              `json:"github_pat"`       // GitHub Personal Access Token (gist scope)
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
	FullVcJson     string  `json:"full_vc_json"` // full signed VC JSON, used by UI to render FileManifest with FileDates
}

// App struct
type App struct {
	ctx              context.Context
	db               *VeriHashDB
	pubKey           ed25519.PublicKey
	privKey          ed25519.PrivateKey
	walletStatus     WalletStatus // current key file state
	mnemonic         string       // temporary storage for new wallet mnemonic
	watchDirs        []string
	aiEngine         string
	modelName        string
	apiKey           string
	baseURL          string
	cloudSyncDirs    []string
	ignoredPatterns  []string
	broadcastManager *BroadcastManager
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
	cfg := a.LoadConfig()

	// 4. Initialize BroadcastManager with registered channels
	a.broadcastManager = NewBroadcastManager(a.db)
	if cfg.GitHubPAT != "" {
		a.broadcastManager.RegisterBroadcaster(NewGitHubGistBroadcaster(cfg.GitHubPAT))
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[BROADCAST] GitHub Gist channel registered.", "type": "sys"})
	}

	// 5. Silently repair the historic JSON chain on all bound cloud directories in background
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
		a.ignoredPatterns = cfg.IgnoredPatterns
		// Re-register GitHub Gist broadcaster whenever config reloads
		if a.broadcastManager != nil && cfg.GitHubPAT != "" {
			a.broadcastManager.RegisterBroadcaster(NewGitHubGistBroadcaster(cfg.GitHubPAT))
		}
	}
	return cfg
}

// isPathIgnored checks if a path should be skipped based on hidden status, 
// system files, or manual exclusion patterns.
func isPathIgnored(fullPath string, ignoredPatterns []string) bool {
	// Standardize path slashes
	cleanPath := filepath.ToSlash(fullPath)
	parts := strings.Split(cleanPath, "/")

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}

		// 1. Hidden file/folder check (recursive)
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return true
		}

		// 2. System defaults (case-insensitive)
		lowerPart := strings.ToLower(part)
		if lowerPart == "desktop.ini" || lowerPart == "thumbs.db" || lowerPart == ".ds_store" {
			return true
		}

		// 3. Manual exclusion patterns (case-insensitive)
		for _, pattern := range ignoredPatterns {
			if pattern != "" && strings.EqualFold(part, pattern) {
				return true
			}
		}
	}
	return false
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

// ResolveDroppedPath checks whether a drag-and-dropped path is a file or directory.
// If it is a regular file, the parent directory is returned along with a "file" type hint.
// If it is already a directory, it is returned as-is with a "dir" type hint.
// Returns a JSON object: { "path": "...", "type": "dir"|"file", "name": "..." }
func (a *App) ResolveDroppedPath(droppedPath string) string {
	info, err := os.Stat(droppedPath)
	if err != nil {
		return `{"error": "Path not found: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	if info.IsDir() {
		name := filepath.Base(droppedPath)
		return `{"path": ` + jsonString(droppedPath) + `, "type": "dir", "name": ` + jsonString(name) + `}`
	}
	// It's a file — return parent directory and the original filename as context
	parentDir := filepath.Dir(droppedPath)
	name := info.Name()
	return `{"path": ` + jsonString(parentDir) + `, "type": "file", "name": ` + jsonString(name) + `}`
}

// jsonString safely encodes a string value for embedding in a JSON literal.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// SaveConfig stores the AI and UI configuration in memory and JSON disk.
// gitHubPAT is stored as-is; pass an empty string to leave the existing PAT unchanged.
func (a *App) SaveConfig(workspaces []string, engine, modelName, key, baseURL string, cloudSyncDirs []string, gitHubPAT string) string {
	a.watchDirs = workspaces
	a.aiEngine = engine
	a.modelName = modelName
	a.apiKey = key
	a.baseURL = baseURL
	a.cloudSyncDirs = cloudSyncDirs

	// Preserve fields not managed by this call
	var existingCfg Config
	if existingBytes, err := os.ReadFile("verihash_config.json"); err == nil {
		json.Unmarshal(existingBytes, &existingCfg)
	}

	// Keep existing PAT if caller passes empty string (avoids UI accidentally clearing it)
	pat := gitHubPAT
	if pat == "" {
		pat = existingCfg.GitHubPAT
	}

	cfg := Config{
		Workspaces:      workspaces,
		AIEngine:        engine,
		ModelName:       modelName,
		APIKey:          key,
		BaseURL:         baseURL,
		CloudSyncDirs:   cloudSyncDirs,
		IgnoredPatterns: existingCfg.IgnoredPatterns, // preserve
		AutoStart:       existingCfg.AutoStart,       // preserve
		SessionIgnores:  existingCfg.SessionIgnores,  // preserve local filters
		GitHubPAT:       pat,
	}
	bytes, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("verihash_config.json", bytes, 0644)

	// Re-register broadcaster with new PAT immediately
	if a.broadcastManager != nil && pat != "" {
		a.broadcastManager.RegisterBroadcaster(NewGitHubGistBroadcaster(pat))
	}

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
		var sessionIgnores []string
		cfgIgnores := a.LoadSessionIgnores()
		if cfgIgnores != nil && cfgIgnores[dir] != nil {
			sessionIgnores = cfgIgnores[dir]
		}
		go startWatchdog(a.ctx, dir, a.db, a.privKey, a.ignoredPatterns, sessionIgnores)
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[WATCHDOG] Active Target Hooked: " + filepath.Base(dir), "type": "sys"})
	}
	return "Started"
}

// UpdateIgnoredPatterns updates the manual exclusion list and saves to config
func (a *App) UpdateIgnoredPatterns(patterns []string) string {
	a.ignoredPatterns = patterns
	
	var cfg Config
	bytes, err := os.ReadFile("verihash_config.json")
	if err == nil {
		json.Unmarshal(bytes, &cfg)
	}
	
	cfg.IgnoredPatterns = patterns
	out, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("verihash_config.json", out, 0644)

	// Since watchdog doesn't easily support dynamic reload yet, we notify user
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[SYSTEM] Ignored patterns updated. Changes will affect new scans.", "type": "sys"})
	return "OK"
}

// LoadSessionIgnores retrieves the localized session exclusions from config
func (a *App) LoadSessionIgnores() map[string][]string {
	var cfg Config
	if bytes, err := os.ReadFile("verihash_config.json"); err == nil {
		json.Unmarshal(bytes, &cfg)
		if cfg.SessionIgnores != nil {
			return cfg.SessionIgnores
		}
	}
	return make(map[string][]string)
}

// SaveSessionIgnores persists the UI dropdown exclusions map for a specific workspace
func (a *App) SaveSessionIgnores(ws string, rules []string) string {
	var cfg Config
	if bytes, err := os.ReadFile("verihash_config.json"); err == nil {
		json.Unmarshal(bytes, &cfg)
	}
	if cfg.SessionIgnores == nil {
		cfg.SessionIgnores = make(map[string][]string)
	}
	cfg.SessionIgnores[ws] = rules

	out, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("verihash_config.json", out, 0644)
	return "OK"
}

// TriggerMint runs the Oracle evaluation for specifically checked files.
// workspacePath may be a single path or multiple paths joined by "|" for cross-project minting.
// When multiple paths are provided, ProjectContext is set to the combined basename label.
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

	// Build a human-readable ProjectContext from all workspace basenames
	// e.g. "ProjectA | ProjectB" when multiple workspaces are selected
	mintContext := workspacePath
	wsPaths := strings.Split(workspacePath, "|")
	if len(wsPaths) > 1 {
		var names []string
		for _, p := range wsPaths {
			p = strings.TrimSpace(p)
			if p != "" {
				names = append(names, filepath.Base(p))
			}
		}
		mintContext = strings.Join(names, " + ")
	} else {
		mintContext = filepath.Base(strings.TrimSpace(workspacePath))
	}

	result := MintCredential(a.ctx, a.db, a.pubKey, a.privKey, engineParam, a.apiKey, a.baseURL, selectedFiles, mintContext)

	// If successful, trigger cloud sync and broadcast
	if !strings.Contains(result, `"error":`) {
		var parseResult map[string]interface{}
		if err := json.Unmarshal([]byte(result), &parseResult); err == nil {
			// VC JSON uses "id" not "vc_id"
			if vcID, ok := parseResult["id"].(string); ok {
				if len(a.cloudSyncDirs) > 0 {
					go a.replicateToCloud(vcID)
				}
				// Fire-and-forget broadcast across all registered channels
				if a.broadcastManager != nil {
					go a.broadcastManager.BroadcastVC(vcID)
					runtime.EventsEmit(a.ctx, "log", map[string]string{
						"msg":  "[BROADCAST] Broadcasting VC to registered channels...",
						"type": "sys",
					})
				}
			}
		}
	}

	return result
}

// GetWorkspaceFiles returns uniquely modified files for a requested workspace.
// If workspace points to a single file (e.g. dragged in before fix), it returns
// that file directly instead of attempting a directory scan which would silently fail.
func (a *App) GetWorkspaceFiles(workspace string) []string {
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[DEBUG-TRACE] Resolving workspace: %s", workspace), "type": "sys"})

	var finalFiles []string

	// Check if the path is a regular file rather than a directory
	info, err := os.Stat(workspace)
	if err != nil {
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[DEBUG-TRACE] Workspace path not found: %s", workspace), "type": "err"})
		return finalFiles
	}

	if !info.IsDir() {
		// Workspace is a single file — return it directly (legacy drag-drop support)
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[DEBUG-TRACE] Workspace is a single file, returning directly: %s", workspace), "type": "sys"})
		finalFiles = append(finalFiles, filepath.ToSlash(workspace))
		return finalFiles
	}

	// Physically scan the actual disk so the UI shows ALL files, not just modified ones.
	var scanDir func(string)
	scanDir = func(currentDir string) {
		entries, err := os.ReadDir(currentDir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			fullPath := filepath.Join(currentDir, entry.Name())

			// Use the new helper to skip hidden/system/manual patterns recursively
			if isPathIgnored(fullPath, a.ignoredPatterns) {
				continue
			}

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
		if err := rows.Scan(&e.VcID, &e.Timestamp, &e.ProjectContext, &e.AiInsight, &e.FilePaths, &e.Status, &e.VcHash, &e.FullVcJson); err != nil {
			continue
		}

		// Parse AI engine from full VC JSON
		var vc VCSchema
		if err := json.Unmarshal([]byte(e.FullVcJson), &vc); err == nil {
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

	type RestoredBlock struct {
		VC         VCSchema
		RawData    string
		VCHash     string
		PrevVCHash string
	}

	revokedMap := make(map[string]bool)
	blocks := make(map[string]*RestoredBlock)

	totalFound := 0

	// Phase 1: Deep Parse existing files into memory blocks & tombstone markers
	for _, syncDir := range a.cloudSyncDirs {
		archiveDir := filepath.Join(syncDir, "VeriHash_Archive")
		if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
			continue
		}

		files, _ := os.ReadDir(archiveDir)
		for _, f := range files {
			if f.IsDir() {
				continue
			}

			filePath := filepath.Join(archiveDir, f.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			// Tombstone Extraction
			if strings.HasSuffix(f.Name(), ".revoke.json") {
				var revokeData struct {
					VcID         string  `json:"vc_id"`
					VcHash       string  `json:"vc_hash"`
					RevokedAt    float64 `json:"revoked_at"`
					RevokedByDID string  `json:"revoked_by_did"`
					Signature    string  `json:"signature"`
				}
				if json.Unmarshal(data, &revokeData) == nil && revokeData.VcID != "" {
				    payload := fmt.Sprintf("VERIHASH_REVOKE|%s|%s|%f|%s", revokeData.VcID, revokeData.VcHash, revokeData.RevokedAt, revokeData.RevokedByDID)
				    
				    pubKey, err := extractPubKeyFromDID(revokeData.RevokedByDID)
				    if err == nil && len(pubKey) == ed25519.PublicKeySize {
				        sigBytes, sigErr := hex.DecodeString(revokeData.Signature)
				        if sigErr == nil && ed25519.Verify(pubKey, []byte(payload), sigBytes) {
					        revokedMap[revokeData.VcID] = true
				        } else {
				            runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": fmt.Sprintf("[RESTORE WARNING] Forged tombstone discarded: %s", revokeData.VcID), "type": "err"})
				        }
				    }
				}
				continue
			}

			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			
			totalFound++

			// 1. Cryptographic Verification
			valid, _ := verifyCredentialDoc(string(data))
			if !valid {
				continue
			}

			// 2. Identity Match Check
			var vc VCSchema
			json.Unmarshal(data, &vc)
			if vc.Issuer != currentDID {
				continue
			}

			// 3. Check for existence in local DB
			var exists int
			a.db.conn.QueryRow(`SELECT COUNT(*) FROM session_credentials WHERE vc_id = ?`, vc.ID).Scan(&exists)
			if exists > 0 {
				continue
			}

			vcHash := computeSHA256(vc.ID + "|" + vc.Proof.PreviousVCHash + "|" + string(data))
			blocks[vcHash] = &RestoredBlock{
				VC:         vc,
				RawData:    string(data),
				VCHash:     vcHash,
				PrevVCHash: vc.Proof.PreviousVCHash,
			}
		}
	}

	totalRestored := 0
	if len(blocks) == 0 {
		return fmt.Sprintf(`{"found": %d, "restored": %d}`, totalFound, totalRestored)
	}

	// Phase 2: Topological Graph sorting
	var orderedBlocks []*RestoredBlock
	
	nextBlockMap := make(map[string]*RestoredBlock)
	for _, block := range blocks {
		nextBlockMap[block.PrevVCHash] = block
	}

	var root *RestoredBlock
	for _, block := range blocks {
		if _, prevExistsInPool := blocks[block.PrevVCHash]; !prevExistsInPool {
			root = block
			break
		}
	}

	if root == nil {
	    for _, block := range blocks {
	        root = block
	        break
	    }
	}

	degraded := false
	current := root
	for current != nil {
		orderedBlocks = append(orderedBlocks, current)
		nextHash := current.VCHash
		delete(blocks, current.VCHash) 
		nextBlock, exists := nextBlockMap[nextHash]
		if exists && blocks[nextBlock.VCHash] != nil {
			current = nextBlock
		} else {
		    var nextOrphan *RestoredBlock
        	for _, block := range blocks {
        		if _, prevExistsInPool := blocks[block.PrevVCHash]; !prevExistsInPool {
        			nextOrphan = block
        			break
        		}
        	}
        	if nextOrphan == nil {
        	    for _, block := range blocks {
            		nextOrphan = block
            		break
            	}
        	}
        	if nextOrphan != nil {
        	    degraded = true
        	    runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[WARNING] Strict Mode: Degraded chain continuity recovered via splicing.", "type": "err"})
        	}
        	current = nextOrphan
		}
	}

	// Phase 3: Ordered Relational Insert
	for _, block := range orderedBlocks {
		pathStr := ""
		if block.VC.LocalMetadata != nil && len(block.VC.LocalMetadata.FullPaths) > 0 {
			pathStr = strings.Join(block.VC.LocalMetadata.FullPaths, ",")
		} else {
			var names []string
			for _, f := range block.VC.CredentialSubject.ProofOfWork.Files {
				names = append(names, f.Name)
			}
			pathStr = strings.Join(names, ",")
		}

		var restoredUnixTime float64
		if block.VC.CredentialSubject.ProofOfWork.UnixNanoMinting != "" {
		    if parsedInt, pErr := strconv.ParseFloat(block.VC.CredentialSubject.ProofOfWork.UnixNanoMinting, 64); pErr == nil {
		        restoredUnixTime = parsedInt / 1e9
		    }
		} else {
            t, err := time.Parse(time.RFC3339, block.VC.IssuanceDate)
            if err == nil {
                restoredUnixTime = float64(t.UnixNano()) / 1e9
            } else {
                restoredUnixTime = float64(time.Now().UnixNano()) / 1e9
            }
		}

		status := 1
		var revokedAt float64 = 0
		var revokeSig string = ""
		
		if revokedMap[block.VC.ID] {
			status = 0
		}

		cProj := block.VC.CredentialSubject.ProofOfWork.ProjectContext
		cTags := block.VC.CredentialSubject.ProofOfWork.SkillTags

		_, dbErr := a.db.conn.Exec(`
			INSERT INTO session_credentials
			(vc_id, timestamp, project_context, ai_insight, skill_tags, file_paths, full_vc_json, status, vc_hash, prev_vc_hash, revoked_at, revoke_signature)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			block.VC.ID,
			restoredUnixTime,
			cProj,
			block.VC.CredentialSubject.ProofOfWork.AIEvaluation,
			cTags,
			pathStr,
			block.RawData,
			status,
			block.VCHash,
			block.PrevVCHash,
			revokedAt,
			revokeSig,
		)

		if dbErr == nil {
			totalRestored++
		}
	}

	result := fmt.Sprintf(`{"found": %d, "restored": %d, "degraded": %t}`, totalFound, totalRestored, degraded)
	msgStr := fmt.Sprintf("[RESTORE] Topology restored. %d records found, %d sequentially reconstructed.", totalFound, totalRestored)
	if degraded {
	    msgStr = fmt.Sprintf("[RESTORE] Recovered %d files with DEGRADED chain logic.", totalFound)
	}
	runtime.EventsEmit(a.ctx, "log", map[string]string{
		"msg":  msgStr,
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

func (a *App) RevokeCredential(vcID string) string {
	var vcHash string
	errHash := a.db.conn.QueryRow(`SELECT vc_hash FROM session_credentials WHERE vc_id = ?`, vcID).Scan(&vcHash)
	if errHash != nil {
		return `{"error": "Credential not found in local DB."}`
	}

	revokedAt := float64(time.Now().UnixNano()) / 1e9
	did := a.GetDID()
	
	// Canonical Payload: VERIHASH_REVOKE|<vc_id>|<vc_hash>|<revoked_at>|<did>
	payload := fmt.Sprintf("VERIHASH_REVOKE|%s|%s|%f|%s", vcID, vcHash, revokedAt, did)
	signatureBytes := ed25519.Sign(a.privKey, []byte(payload))
	signatureHex := hex.EncodeToString(signatureBytes)

	_, err := a.db.conn.Exec(
		`UPDATE session_credentials SET status = 0, revoked_at = ?, revoke_signature = ? WHERE vc_id = ?`, 
		revokedAt, signatureHex, vcID,
	)
	if err != nil {
		return `{"error": "` + err.Error() + `"}`
	}

	// Dump the cryptographic bundle
	cleanVcID := strings.ReplaceAll(vcID, ":", "_")
	revokeJSON := fmt.Sprintf(`{"vc_id": "%s", "vc_hash": "%s", "revoked_at": %f, "revoked_by_did": "%s", "signature": "%s"}`, 
		vcID, vcHash, revokedAt, did, signatureHex)
	
	for _, syncDir := range a.cloudSyncDirs {
		jsonPath := filepath.Join(syncDir, "VeriHash_Archive", fmt.Sprintf("VeriHash_%s.revoke.json", cleanVcID))
		_ = os.WriteFile(jsonPath, []byte(revokeJSON), 0644)
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
func (a *App) replicateToCloud(vcID string) {
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
	rows, err := a.db.conn.Query(`SELECT vc_id, full_vc_json, status, vc_hash, revoked_at, revoke_signature FROM session_credentials`)
	if err != nil {
		return `{"error": "Failed to query historic ledger: ` + err.Error() + `"}`
	}
	defer rows.Close()

	archiveDir := filepath.Join(targetDir, "VeriHash_Archive")
	_ = os.MkdirAll(archiveDir, 0755)

	count := 0
	for rows.Next() {
		var vcID, fullJsonStr, vcHash, revokeSig string
		var status int
		var revokedAt float64
		if err := rows.Scan(&vcID, &fullJsonStr, &status, &vcHash, &revokedAt, &revokeSig); err == nil && fullJsonStr != "" {
			cleanVcID := strings.ReplaceAll(vcID, ":", "_")
			jsonPath := filepath.Join(archiveDir, fmt.Sprintf("VeriHash_%s.json", cleanVcID))

			// Write the VC object if missing
			if _, statErr := os.Stat(jsonPath); os.IsNotExist(statErr) {
				_ = os.WriteFile(jsonPath, []byte(fullJsonStr), 0644)
				count++
			}
			
			// Determine if a tombstone needs to be paired
			if status == 0 && revokeSig != "" {
			    revokePath := filepath.Join(archiveDir, fmt.Sprintf("VeriHash_%s.revoke.json", cleanVcID))
			    if _, statErr := os.Stat(revokePath); os.IsNotExist(statErr) {
			        revokeJSON := fmt.Sprintf(`{"vc_id": "%s", "vc_hash": "%s", "revoked_at": %f, "revoked_by_did": "%s", "signature": "%s"}`, 
		                vcID, vcHash, revokedAt, a.GetDID(), revokeSig)
			        _ = os.WriteFile(revokePath, []byte(revokeJSON), 0644)
			    }
			}
		}
	}

	msg := fmt.Sprintf("[CLOUD-SYNC] Historic chain repair complete: %d credential(s) pushed to %s", count, filepath.Base(targetDir))
	runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": msg, "type": "sys"})
	return fmt.Sprintf(`{"status": "OK", "synced": %d}`, count)
}

// ── Broadcast Wails Bindings ──────────────────────────────────────────────────

// BroadcastVC manually triggers broadcasting of an existing credential to all
// registered channels. Useful for retrying failed broadcasts or broadcasting
// credentials that were minted before broadcast was configured.
func (a *App) BroadcastVC(vcID string) string {
	if a.broadcastManager == nil || len(a.broadcastManager.broadcasters) == 0 {
		return `{"error": "No broadcast channels configured. Please add a GitHub PAT in Settings."}`
	}
	go a.broadcastManager.BroadcastVC(vcID)
	runtime.EventsEmit(a.ctx, "log", map[string]string{
		"msg":  "[BROADCAST] Manual broadcast triggered for " + vcID[:min(20, len(vcID))] + "...",
		"type": "sys",
	})
	return `{"status": "queued"}`
}

// GetBroadcastStatus returns the broadcast status for all channels for a given vc_id.
// The frontend uses this to render per-channel status badges on each Ledger card.
func (a *App) GetBroadcastStatus(vcID string) []BroadcastPublication {
	pubs, err := a.db.GetBroadcastsByVC(vcID)
	if err != nil {
		return []BroadcastPublication{}
	}
	if pubs == nil {
		return []BroadcastPublication{}
	}
	return pubs
}

// GetProfileIndex generates and returns the public root index JSON as a string.
// The index aggregates all publicly broadcast credentials for this identity and
// is intended to be published as a pinned Gist (verihash_profile_index.json).
func (a *App) GetProfileIndex() string {
	did := a.GetDID()
	index, err := a.db.GenerateProfileIndex(did)
	if err != nil {
		return `{"error": "Failed to generate profile index: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	out, _ := json.MarshalIndent(index, "", "  ")
	return string(out)
}

// ── .vhb Cold Backup Wails Bindings ──────────────────────────────────────────

// ExportVHBBackup creates an encrypted .vhb cold backup of the ledger database
// and public identity. The backup password is independent of the vault password.
// Returns JSON: { "status": "OK", "path": "<abs-path>" } or { "error": "..." }
func (a *App) ExportVHBBackup(backupPassword, confirmPassword string) string {
	did := a.GetDID()
	absPath, err := ExportVHB(a.db, did, backupPassword, confirmPassword)
	if err != nil {
		errMsg := strings.ReplaceAll(err.Error(), `"`, `'`)
		return `{"error": "` + errMsg + `"}`
	}
	runtime.EventsEmit(a.ctx, "log", map[string]string{
		"msg":  "[BACKUP] .vhb cold backup created: " + absPath,
		"type": "sys",
	})
	out, _ := json.Marshal(map[string]string{"status": "OK", "path": absPath})
	return string(out)
}

// ImportVHBBackup opens a file dialog for the user to select a .vhb file,
// then decrypts and restores the ledger and identity.
// NOTE: The private key is NOT restored — the user must re-enter their mnemonic
// after import to rebuild their keypair (shown via the wallet flow on next launch).
// Returns JSON: { "status": "OK", "did": "...", "credentials": N } or { "error": "..." }
func (a *App) ImportVHBBackup(backupPassword string) string {
	// Open file dialog
	vhbPath, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select VeriHash Backup (.vhb)",
		Filters: []runtime.FileFilter{
			{DisplayName: "VeriHash Backup (*.vhb)", Pattern: "*.vhb"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || vhbPath == "" {
		return `{"error": "No file selected"}`
	}

	manifest, err := ImportVHB(vhbPath, backupPassword)
	if err != nil {
		errMsg := strings.ReplaceAll(err.Error(), `"`, `'`)
		return `{"error": "` + errMsg + `"}`
	}

	runtime.EventsEmit(a.ctx, "log", map[string]string{
		"msg":  fmt.Sprintf("[BACKUP] Ledger restored from .vhb: %d credential(s), DID: %s", manifest.CredentialCount, manifest.DID),
		"type": "sys",
	})

	out, _ := json.Marshal(map[string]interface{}{
		"status":      "OK",
		"did":         manifest.DID,
		"credentials": manifest.CredentialCount,
		"exported_at": manifest.ExportedAt,
	})
	return string(out)
}

