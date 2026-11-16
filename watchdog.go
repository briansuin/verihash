package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const debounceDuration = 3 * time.Second

// fileState keeps track of the file's last modified time for debouncing
type fileState struct {
	lastModified time.Time
	timer        *time.Timer
}

var (
	stateMap   = make(map[string]*fileState)
	stateMutex sync.Mutex
	dmp        = diffmatchpatch.New()
)

var previousContentCache = make(map[string]string)

func startWatchdog(ctx context.Context, targetDir string, db *VeriHashDB, privKey []byte, ignoredPatterns []string, sessionIgnores []string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Fatal Error: Watchdog failed to initialize: %v", err)
		return
	}
	defer watcher.Close()

	// Core recursively walk directories (symlink and reparse point tolerant for cloud drives)
	var walkDir func(string)
	walkDir = func(currentDir string) {
		info, err := os.Stat(currentDir)
		if err != nil {
			runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[WATCHDOG WARN] Skipping unstatable path: %s", currentDir), "type": "err"})
			return
		}

		if info.IsDir() {
			if isPathIgnored(currentDir, ignoredPatterns) {
				return
			}
			if isPathSessionIgnored(currentDir, targetDir, sessionIgnores) && !hasSessionExceptionInside(currentDir, targetDir, sessionIgnores) {
				return // bypass excluded directories to save filesystem watchers entirely
			}
			
			err = watcher.Add(currentDir)
			if err != nil {
				runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[WATCHDOG ERROR] Registration failed on %s", currentDir), "type": "err"})
			}
			
			// Natively read and iterate rather than relying on filepath.Walk which chokes on virtual drive links
			entries, readErr := os.ReadDir(currentDir)
			if readErr == nil {
				for _, entry := range entries {
					fullPath := filepath.Join(currentDir, entry.Name())
					if isPathIgnored(fullPath, ignoredPatterns) {
						continue
					}
					if !entry.IsDir() && isPathSessionIgnored(fullPath, targetDir, sessionIgnores) {
						continue
					}
					if entry.IsDir() {
						walkDir(fullPath)
					}
				}
			}
		}
	}
	
	walkDir(targetDir)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			
			// OS events bubble up. Safely ignore those explicitly rejected by UI or Global settings.
			if isPathIgnored(event.Name, ignoredPatterns) || isPathSessionIgnored(event.Name, targetDir, sessionIgnores) {
				continue
			}

			if event.Op&fsnotify.Write == fsnotify.Write {
				handleFileWrite(ctx, event.Name, db, privKey)
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				info, err := os.Stat(event.Name)
				if err == nil && info.IsDir() {
					// Recursively watch freshly pasted nested folders using the native symlink friendly walker
					walkDir(event.Name)
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[WATCHDOG ERROR] %v", err), "type": "err"})
		}
	}
}

func handleFileWrite(ctx context.Context, filePath string, db *VeriHashDB, privKey []byte) {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	state, exists := stateMap[filePath]
	if !exists {
		state = &fileState{}
		stateMap[filePath] = state
	}

	state.lastModified = time.Now()

	if state.timer != nullTimer() && state.timer != nil {
		state.timer.Stop()
	}

	state.timer = time.AfterFunc(debounceDuration, func() {
		processFileChange(ctx, filePath, db, privKey)
	})
}

func nullTimer() *time.Timer {
	return nil
}

func processFileChange(ctx context.Context, filePath string, db *VeriHashDB, privKey []byte) {
	// Guard against ledger bloat: only small, text-like files are diffed and
	// stored. Large files / PDFs / office docs / archives / media are skipped
	// BEFORE being read into memory (previously a single PDF could add 400MB+).
	if shouldSkipForSnapshot(filePath) {
		return
	}
	if info, statErr := os.Stat(filePath); statErr != nil || info.Size() > maxSnapshotFileBytes {
		return
	}

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	contentStr := string(contentBytes)

	if isBinary(contentBytes) {
		return
	}

	stateMutex.Lock()
	prevContent := previousContentCache[filePath]
	previousContentCache[filePath] = contentStr
	stateMutex.Unlock()

	if prevContent == contentStr {
		return
	}

	diffs := dmp.DiffMain(prevContent, contentStr, false)
	diffText := dmp.DiffToDelta(diffs)
	
	hashResult, err := db.CommitSnapshot(filePath, diffText, privKey)
	if err != nil {
		runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[ERROR] Failed to commit to ledger: %v", err), "type": "err"})
		return
	}

	msg := fmt.Sprintf("[POW] Block Mined -> %s | Hash: %s...", filepath.Base(filePath), hashResult[:16])
	runtime.EventsEmit(ctx, "log", map[string]string{"msg": msg, "type": "hash"})
}

// maxSnapshotFileBytes caps the size of a file that will be diffed and stored
// in the local file_snapshots table. The AI oracle only uses ~3000 chars/file,
// so storing megabytes per snapshot is pure waste.
const maxSnapshotFileBytes = 2 * 1024 * 1024 // 2 MB

// binaryExts lists extensions that are never useful as text diffs.
var binaryExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".zip": true, ".rar": true, ".7z": true, ".gz": true, ".tar": true, ".bz2": true, ".iso": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".webp": true, ".tif": true, ".tiff": true,
	".psd": true, ".heic": true, ".ico": true,
	".mp3": true, ".wav": true, ".flac": true, ".aac": true, ".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".wmv": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true, ".db": true, ".sqlite": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true,
}

// shouldSkipForSnapshot reports whether a file is known to be binary by extension.
func shouldSkipForSnapshot(path string) bool {
	return binaryExts[strings.ToLower(filepath.Ext(path))]
}

func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Magic numbers for common containers that start with printable bytes
	// (e.g. "%PDF-" slips past a NUL-byte check).
	if bytes.HasPrefix(data, []byte("%PDF-")) || bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return true
	}
	limit := len(data)
	if limit > 8000 {
		limit = 8000
	}
	for _, b := range data[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}

func computeSHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// isPathSessionIgnored emulates the frontend JS cascade check loop safely in backend
func isPathSessionIgnored(fullPath string, targetDir string, sessionIgnores []string) bool {
	if len(sessionIgnores) == 0 {
		return false
	}
	
	if !strings.HasPrefix(strings.ToLower(fullPath), strings.ToLower(targetDir)) {
		return false
	}
	
	relPath := fullPath[len(targetDir):]
	if len(relPath) > 0 && (relPath[0] == '/' || relPath[0] == '\\') {
		relPath = relPath[1:]
	}
	if relPath == "" {
		return false
	}
	
	relPath = filepath.ToSlash(relPath)
	parts := strings.Split(relPath, "/")
	
	currentDir := ""
	shouldIgnore := false
	
	// Evaluate inherited directory rules exactly like UI algorithm deepest rule wins
	for i := 0; i < len(parts)-1; i++ {
		if currentDir != "" {
			currentDir += "/"
		}
		currentDir += parts[i]
		
		for _, ignore := range sessionIgnores {
			switch ignore {
			case "DIR:" + currentDir:
				shouldIgnore = true
			case "EXCEPT:" + currentDir:
				shouldIgnore = false
			}
		}
	}
	
	// Explicit file/leaf checks
	fileExcept := "EXCEPT:" + relPath
	for _, ignore := range sessionIgnores {
		if ignore == fileExcept {
			shouldIgnore = false
		} else if ignore == fullPath || ignore == filepath.ToSlash(fullPath) {
			shouldIgnore = true
		} else if strings.HasPrefix(ignore, "FILE:") {
		    // FILE:relPath|fullPath format from frontend JS
		    parts := strings.SplitN(ignore, "|", 2)
		    if len(parts) == 2 && parts[1] == fullPath {
		        shouldIgnore = true
		    }
		}
	}
	
	return shouldIgnore
}

func hasSessionExceptionInside(fullPath string, targetDir string, sessionIgnores []string) bool {
	if len(sessionIgnores) == 0 {
		return false
	}
	relPath := fullPath[len(targetDir):]
	if len(relPath) > 0 && (relPath[0] == '/' || relPath[0] == '\\') {
		relPath = relPath[1:]
	}
	relPath = filepath.ToSlash(relPath)
	
	for _, rule := range sessionIgnores {
		if strings.HasPrefix(rule, "EXCEPT:") && strings.HasPrefix(rule[7:], relPath+"/") {
			return true
		}
	}
	return false
}
