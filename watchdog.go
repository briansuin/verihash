package main

import (
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

func startWatchdog(ctx context.Context, targetDir string, db *VeriHashDB, privKey []byte) {
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
			baseName := info.Name()
			if strings.HasPrefix(baseName, ".") && baseName != "." {
				return // silently skip hidden directories like .git
			}
			
			err = watcher.Add(currentDir)
			if err != nil {
				runtime.EventsEmit(ctx, "log", map[string]string{"msg": fmt.Sprintf("[WATCHDOG ERROR] Registration failed on %s", currentDir), "type": "err"})
			}
			
			// Natively read and iterate rather than relying on filepath.Walk which chokes on virtual drive links
			entries, readErr := os.ReadDir(currentDir)
			if readErr == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						walkDir(filepath.Join(currentDir, entry.Name()))
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
			if event.Op&fsnotify.Write == fsnotify.Write {
				handleFileWrite(ctx, event.Name, db, privKey)
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				info, err := os.Stat(event.Name)
				if err == nil && info.IsDir() && !strings.HasPrefix(info.Name(), ".") {
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

func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	limit := len(data)
	if limit > 512 {
		limit = 512
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
