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
	_ "embed"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/zalando/go-keyring"
	"github.com/creativeprojects/go-selfupdate"
)

//go:embed wails.json
var wailsJSON []byte

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
	GitHubPAT       string              `json:"github_pat"`        // GitHub Personal Access Token (gist scope)
	IndexGistID     string              `json:"index_gist_id"`     // Phase 4.5: pinned root index Gist ID (stable anchor)
	IndexGistURL    string              `json:"index_gist_url"`    // Phase 4.5: public URL of the root index Gist
	DisplayName     string              `json:"display_name"`      // Human-readable name shown in the public index
	// Public Profile — all opt-in, published to Index Gist if set
	ProfileName    string            `json:"profile_name"`
	ProfileWebsite string            `json:"profile_website"`
	ProfileCustom  map[string]string `json:"profile_custom"`
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
	indexUpdater     *IndexUpdater // Phase 4.5: auto-syncs the public root index Gist
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
		gistBroadcaster := NewGitHubGistBroadcaster(cfg.GitHubPAT)
		a.broadcastManager.RegisterBroadcaster(gistBroadcaster)
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[BROADCAST] GitHub Gist channel registered.", "type": "sys"})

		// Phase 4.5: Start the IndexUpdater background worker.
		// It listens for signals from Mint and Revoke and serially syncs the
		// public root index Gist, debouncing burst updates automatically.
		iu := NewIndexUpdater(a.db, gistBroadcaster, "verihash_config.json")
		a.indexUpdater = iu
		a.broadcastManager.indexUpdater = iu
		iu.Start()
		runtime.EventsEmit(a.ctx, "log", map[string]string{"msg": "[INDEX] Public root index auto-updater started.", "type": "sys"})
	}

	// 5. Sync DB snapshot to all bound cloud directories on startup
	if len(a.cloudSyncDirs) > 0 {
		go a.syncDBToCloud()
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
		// Phase 4.5: MUST preserve — losing these would cause IndexUpdater to
		// re-bootstrap and create a duplicate Index Gist, breaking the stable URL.
		IndexGistID:  existingCfg.IndexGistID,
		IndexGistURL: existingCfg.IndexGistURL,
		DisplayName:  existingCfg.DisplayName,
		// Public Profile — preserve user-set fields
		ProfileName:    existingCfg.ProfileName,
		ProfileWebsite: existingCfg.ProfileWebsite,
		ProfileCustom:  existingCfg.ProfileCustom,
	}
	bytes, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("verihash_config.json", bytes, 0644)

	// Re-register broadcaster and IndexUpdater with new PAT immediately
	if a.broadcastManager != nil && pat != "" {
		gistBroadcaster := NewGitHubGistBroadcaster(pat)
		a.broadcastManager.RegisterBroadcaster(gistBroadcaster)
		// Restart IndexUpdater with new broadcaster if it wasn't running before
		if a.indexUpdater == nil {
			iu := NewIndexUpdater(a.db, gistBroadcaster, "verihash_config.json")
			a.indexUpdater = iu
			a.broadcastManager.indexUpdater = iu
			iu.Start()
		} else {
			a.indexUpdater.UpdateBroadcaster(gistBroadcaster)
		}
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
func (a *App) TriggerMint(selectedFiles []string, workspacePath string, projectName string) string {
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

	// If the user supplied a project name, use it directly as the mint context.
	// Otherwise fall back to deriving the context from workspace basenames.
	var mintContext string
	var publicTitle string
	if strings.TrimSpace(projectName) != "" {
		publicTitle = strings.TrimSpace(projectName)
		mintContext = publicTitle
	} else {
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
	}

	result := MintCredential(a.ctx, a.db, a.pubKey, a.privKey, engineParam, a.apiKey, a.baseURL, selectedFiles, mintContext, publicTitle)


	// If successful, trigger cloud sync and broadcast
	if !strings.Contains(result, `"error":`) {
		var parseResult map[string]interface{}
		if err := json.Unmarshal([]byte(result), &parseResult); err == nil {
			// VC JSON uses "id" not "vc_id"
			if vcID, ok := parseResult["id"].(string); ok {
				if len(a.cloudSyncDirs) > 0 {
					go a.syncDBToCloud()
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

// RestoreDataFromSync finds the newest verihash_ledger.db across all configured
// cloud sync directories and atomically restores it as the local ledger.
// The active DB is backed up to proof_of_work.db.bak before overwrite.
// Returns JSON: { "credentials": N } on success or { "error": "..." }
func (a *App) RestoreDataFromSync() string {
	if len(a.cloudSyncDirs) == 0 {
		return `{"error": "No cloud sync directories configured."}`
	}

	// Find the newest verihash_ledger.db across all sync dirs
	var bestPath string
	var bestMod time.Time
	for _, syncDir := range a.cloudSyncDirs {
		candidate := filepath.Join(syncDir, "verihash_ledger.db")
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if bestPath == "" || info.ModTime().After(bestMod) {
			bestPath = candidate
			bestMod = info.ModTime()
		}
	}
	if bestPath == "" {
		return `{"error": "No verihash_ledger.db found in any configured cloud sync directory."}`
	}

	// Read the source DB
	dbData, err := os.ReadFile(bestPath)
	if err != nil {
		return `{"error": "Cannot read ledger file: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}

	// Backup current DB (best-effort)
	if existing, readErr := os.ReadFile(dbFile); readErr == nil {
		_ = os.WriteFile(dbFile+".bak", existing, 0644)
	}

	// Write to staging then rename (atomic)
	// On Windows, os.Rename fails with "Access is denied" if the target file has
	// open handles. We must close the SQLite connection BEFORE the rename, then
	// reopen it. Linux does not have this restriction.
	stagingPath := dbFile + ".restore_staging"
	if err := os.WriteFile(stagingPath, dbData, 0644); err != nil {
		return `{"error": "Staging write failed: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}

	// ── Step 1: Pause all DB-dependent subsystems and close the connection ──
	if a.indexUpdater != nil {
		a.indexUpdater.Stop()
	}
	if a.db != nil {
		a.db.conn.Close()
		a.db = nil
	}

	// ── Step 2: Atomic rename (now safe — no open handle on dbFile) ──
	if err := os.Rename(stagingPath, dbFile); err != nil {
		os.Remove(stagingPath)
		// Try to reopen original DB so the app remains functional
		if db, reopenErr := connectDB(); reopenErr == nil {
			a.db = db
		}
		return `{"error": "Cannot activate restored ledger: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}

	// ── Step 3: Reopen fresh DB connection on the restored file ──
	newDB, err := connectDB()
	if err != nil {
		return `{"error": "Ledger restored but failed to reopen: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	a.db = newDB


	// ── Step 4: Restart IndexUpdater with the new DB handle ──
	cfg := a.LoadConfig()
	if cfg.GitHubPAT != "" {
		broadcaster := NewGitHubGistBroadcaster(cfg.GitHubPAT)
		iu := NewIndexUpdater(a.db, broadcaster, "verihash_config.json")
		a.indexUpdater = iu
		a.broadcastManager.indexUpdater = iu
		iu.Start()
	}

	// Count credentials in the restored DB for user feedback
	var credCount int
	if a.db != nil {
		_ = a.db.conn.QueryRow(`SELECT COUNT(*) FROM session_credentials`).Scan(&credCount)
	}

	runtime.EventsEmit(a.ctx, "log", map[string]string{
		"msg":  fmt.Sprintf("[RESTORE] Ledger restored from %s (%d credentials). Reload complete.", filepath.Base(bestPath), credCount),
		"type": "sys",
	})
	return fmt.Sprintf(`{"credentials": %d, "source": "%s"}`, credCount, strings.ReplaceAll(filepath.Base(bestPath), `"`, `'`))
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

	// Sync the updated DB (with revocation) to all cloud sync dirs
	if len(a.cloudSyncDirs) > 0 {
		go a.syncDBToCloud()
	}

	// Best-effort: stamp the remote Gist with an in-place tombstone for every
	// broadcast channel. PATCH replaces the VC payload — the Gist URL stays alive
	// and now resolves to the signed revocation notice. Fire-and-forget so the
	// UI response is instant regardless of network latency.
	if a.broadcastManager != nil {
		capturedVcID := vcID
		capturedTomb := TombstonePayload{
			VCID:            vcID,
			IssuerDID:       did,
			RevokedAt:       time.Unix(int64(revokedAt), 0).UTC().Format(time.RFC3339),
			RevokeSignature: signatureHex,
			OriginalVCHash:  vcHash,
		}
		go func() {
			for channel := range a.broadcastManager.broadcasters {
				if err := a.broadcastManager.RevokeBroadcast(capturedVcID, channel, capturedTomb); err != nil {
					log.Printf("[REVOKE] Could not stamp tombstone (%s, %s): %v", capturedVcID[:min(20, len(capturedVcID))]+"...", channel, err)
				} else {
					log.Printf("[REVOKE] ✓ Gist tombstoned in-place (%s, %s)", capturedVcID[:min(20, len(capturedVcID))]+"...", channel)
				}
			}
		}()
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

	a.privKey = privKey
	a.pubKey = pubKey
	a.walletStatus = WalletStatusEncrypted

	// We'll return OK and let the frontend reboot.
	return `{"status": "OK", "did": "` + pubKeyToDIDKey(pubKey) + `"}`
}

// syncDBToCloud copies the full proof_of_work.db to every configured cloud sync
// directory as verihash_ledger.db. Called after Mint and Revoke so the cloud
// always holds a current snapshot of the complete credential ledger.
// It is intentionally fire-and-forget (called via goroutine).
func (a *App) syncDBToCloud() {
	// WAL checkpoint so the DB file on disk is fully up to date
	_, _ = a.db.conn.Exec(`PRAGMA wal_checkpoint(FULL);`)

	// Read the DB file
	dbBytes, err := os.ReadFile(dbFile)
	if err != nil {
		runtime.EventsEmit(a.ctx, "log", map[string]string{
			"msg":  "[CLOUD-SYNC] Cannot read DB for sync: " + err.Error(),
			"type": "err",
		})
		return
	}

	for _, syncDir := range a.cloudSyncDirs {
		destPath := filepath.Join(syncDir, "verihash_ledger.db")
		if writeErr := os.WriteFile(destPath, dbBytes, 0644); writeErr != nil {
			runtime.EventsEmit(a.ctx, "log", map[string]string{
				"msg":  fmt.Sprintf("[CLOUD-SYNC] Failed to sync DB to %s: %v", filepath.Base(syncDir), writeErr),
				"type": "err",
			})
			continue
		}
		runtime.EventsEmit(a.ctx, "log", map[string]string{
			"msg":  fmt.Sprintf("[CLOUD-SYNC] ✓ verihash_ledger.db → %s", filepath.Base(syncDir)),
			"type": "sys",
		})
	}
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

// ResetBroadcastVC clears the broadcast record for a given VC and channel back
// to 'pending', allowing the user to re-broadcast after deleting the remote Gist.
// This is intentionally separate from BroadcastVC so it requires an explicit user action.
func (a *App) ResetBroadcastVC(vcID, channel string) string {
	if err := a.db.ResetBroadcastForVC(vcID, channel); err != nil {
		return `{"error": "` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	log.Printf("[BROADCAST] Reset broadcast record for (%s, %s)", vcID[:min(20, len(vcID))]+"...", channel)
	return `{"status": "reset"}`
}

// DeleteBroadcastVC deletes the remote artifact (e.g. the GitHub Gist) for the
// given VC and channel, then fully wipes the broadcast DB record so the user can
// re-broadcast from scratch. Unlike RevokeCredential, the local credential itself
// is NOT affected — it stays valid in the Ledger.
func (a *App) DeleteBroadcastVC(vcID, channel string) string {
	if a.broadcastManager == nil {
		return `{"error": "Broadcast manager not initialized"}`
	}
	b, ok := a.broadcastManager.broadcasters[channel]
	if !ok {
		return `{"error": "No broadcaster registered for channel: ` + channel + `"}`
	}

	// Look up the remote_id to delete
	pubs, err := a.db.GetBroadcastsByVC(vcID)
	if err != nil {
		return `{"error": "DB lookup failed: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	var remoteID string
	for _, p := range pubs {
		if p.Channel == channel {
			remoteID = p.RemoteID
			break
		}
	}
	if remoteID == "" {
		return `{"error": "No published artifact found for this credential"}`
	}

	// Delete the remote artifact (404 = already gone, treat as success)
	if err := b.Delete(remoteID); err != nil {
		return `{"error": "` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}

	// Fully wipe the broadcast record (including remote_id) so next broadcast creates fresh
	if err := a.db.ClearBroadcastRecord(vcID, channel); err != nil {
		log.Printf("[BROADCAST] Warning: Gist deleted but DB clear failed: %v", err)
	}

	log.Printf("[BROADCAST] Gist deleted and record cleared for (%s, %s)", vcID[:min(20, len(vcID))]+"...", channel)
	return `{"status": "deleted"}`
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
	// Inject profile from config
	cfg := a.LoadConfig()
	index.Profile = ProfileInfo{
		Name:    cfg.ProfileName,
		Website: cfg.ProfileWebsite,
		Custom:  cfg.ProfileCustom,
	}
	if cfg.ProfileName != "" {
		index.DisplayName = cfg.ProfileName
	} else {
		index.DisplayName = cfg.DisplayName
	}
	out, _ := json.MarshalIndent(index, "", "  ")
	return string(out)
}

// GetProfileInfo returns the current public profile fields stored in config.
func (a *App) GetProfileInfo() string {
	var existingCfg Config
	if b, err := os.ReadFile("verihash_config.json"); err == nil {
		json.Unmarshal(b, &existingCfg)
	}
	out, _ := json.Marshal(map[string]interface{}{
		"name":    existingCfg.ProfileName,
		"website": existingCfg.ProfileWebsite,
		"custom":  existingCfg.ProfileCustom,
		"index_gist_url": existingCfg.IndexGistURL,
	})
	return string(out)
}

// SaveProfileInfo persists the public profile fields (name, website, custom key-values)
// to verihash_config.json and signals the IndexUpdater to push an updated index Gist.
// All fields are optional \u2014 empty values are stored as empty strings / nil maps.
func (a *App) SaveProfileInfo(name, website string, customJSON string) string {
	var existingCfg Config
	if b, err := os.ReadFile("verihash_config.json"); err == nil {
		json.Unmarshal(b, &existingCfg)
	}

	// Parse the custom key-value pairs from JSON string sent by frontend
	var custom map[string]string
	if customJSON != "" && customJSON != "{}" && customJSON != "null" {
		if err := json.Unmarshal([]byte(customJSON), &custom); err != nil {
			return `{"error": "Invalid custom fields JSON: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
		}
	}

	existingCfg.ProfileName = strings.TrimSpace(name)
	existingCfg.ProfileWebsite = strings.TrimSpace(website)
	existingCfg.ProfileCustom = custom
	// Keep display_name in sync for backwards compat
	existingCfg.DisplayName = existingCfg.ProfileName

	out, err := json.MarshalIndent(existingCfg, "", "  ")
	if err != nil {
		return `{"error": "Failed to serialize config"}`
	}
	if err := os.WriteFile("verihash_config.json", out, 0644); err != nil {
		return `{"error": "Failed to write config: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}

	// Trigger index update so the change appears in the public Gist promptly
	if a.indexUpdater != nil {
		a.indexUpdater.Signal()
	}

	log.Printf("[PROFILE] Public profile updated: name=%q website=%q custom_fields=%d",
		existingCfg.ProfileName, existingCfg.ProfileWebsite, len(custom))
	return `{"status": "saved"}`
}

// GetAppVersion returns the current application version dynamically from wails.json.
func (a *App) GetAppVersion() string {
	var config struct {
		Info struct {
			ProductVersion string `json:"productVersion"`
		} `json:"info"`
	}
	if err := json.Unmarshal(wailsJSON, &config); err == nil {
		if config.Info.ProductVersion != "" {
			return config.Info.ProductVersion
		}
	}
	return "0.0.0"
}

// CheckForUpdate queries GitHub for the latest release version.
func (a *App) CheckForUpdate(currentVersion string) string {
	latest, found, err := selfupdate.DetectLatest(context.Background(), selfupdate.ParseSlug("briansuin/verihash"))
	if err != nil {
		return `{"error": "Failed to check for updates: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	if !found {
		return `{"update_available": false}`
	}
	// Compare versions
	if latest.Version() == currentVersion || "v"+latest.Version() == currentVersion || latest.Version() == "v"+currentVersion {
		return `{"update_available": false}`
	}
	return `{"update_available": true, "version": "` + latest.Version() + `", "release_notes": ""}`
}

// ApplyUpdate downloads the latest release from GitHub.
func (a *App) ApplyUpdate() string {
	latest, err := selfupdate.UpdateSelf(context.Background(), "0.0.0", selfupdate.ParseSlug("briansuin/verihash"))
	if err != nil {
		return `{"error": "Update failed: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	runtime.EventsEmit(a.ctx, "log", map[string]string{
		"msg":  "[SYSTEM] Update successfully applied: " + latest.Version(),
		"type": "sys",
	})
	return `{"status": "success", "new_version": "` + latest.Version() + `"}`
}


