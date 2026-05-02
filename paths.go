package main

import (
	"os"
	"path/filepath"
	"sync"
)

var (
	dataDirOnce sync.Once
	dataDirPath string
)

// AppDataDir returns the directory where VeriHash stores all persistent user data.
// This is intentionally separate from the install directory so that:
//   - App upgrades never destroy user data
//   - A full uninstall+reinstall preserves all credentials and config
//
// Platform defaults:
//
//	Windows : %APPDATA%\VeriHash   (C:\Users\<user>\AppData\Roaming\VeriHash)
//	Linux   : $XDG_CONFIG_HOME/VeriHash  (~/.config/VeriHash)
//	macOS   : ~/Library/Application Support/VeriHash
//
// Falls back to the executable's own directory if the above cannot be determined.
func AppDataDir() string {
	dataDirOnce.Do(func() {
		base, err := os.UserConfigDir()
		if err != nil {
			// Fallback: put data next to the exe
			if exePath, e2 := os.Executable(); e2 == nil {
				dataDirPath = filepath.Dir(exePath)
			} else {
				dataDirPath = "."
			}
			return
		}
		dataDirPath = filepath.Join(base, "VeriHash")
		_ = os.MkdirAll(dataDirPath, 0700)

		// One-time migration: move legacy data files from the old location
		// (the exe's directory) to the new AppData directory so existing
		// users don't lose their credentials, keys, or config on upgrade.
		migrateDataFiles(dataDirPath)
	})
	return dataDirPath
}

// DataPath returns the absolute path for a named data file inside AppDataDir.
func DataPath(filename string) string {
	return filepath.Join(AppDataDir(), filename)
}

// legacyDataDir returns the old data directory (the exe's own folder).
// Used only during the one-time migration.
func legacyDataDir() string {
	if exePath, err := os.Executable(); err == nil {
		return filepath.Dir(exePath)
	}
	return ""
}

// migrateDataFiles moves existing data files from the old exe directory into
// the new AppData directory. Safe to call repeatedly — files are only moved
// when the destination does not yet exist.
func migrateDataFiles(newDir string) {
	oldDir := legacyDataDir()
	if oldDir == "" || oldDir == newDir {
		return
	}
	candidates := []string{
		"proof_of_work.db",
		"proof_of_work.db-shm",
		"proof_of_work.db-wal",
		"verihash_ledger.db",
		"verihash_config.json",
		"node_identity.json",
		".node_secret.key",
	}
	for _, name := range candidates {
		src := filepath.Join(oldDir, name)
		dst := filepath.Join(newDir, name)
		// Only migrate if source exists AND destination doesn't (never overwrite)
		if _, errSrc := os.Stat(src); errSrc != nil {
			continue
		}
		if _, errDst := os.Stat(dst); errDst == nil {
			continue // destination already exists — don't overwrite
		}
		_ = os.Rename(src, dst)
	}
}
