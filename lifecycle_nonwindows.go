//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
)

// setupSystemTray is a stub for non-Windows platforms to prevent main-thread panic.
// macOS system tray requires main thread execution, which conflicts with Wails.
func setupSystemTray(ctx context.Context) {
	fmt.Println("[SYSTEM] Background tray disabled on non-Windows platform to prevent thread collision.")
}

// ToggleAutoStart is a stub since Windows Registry does not exist on Mac/Linux.
func (a *App) ToggleAutoStart(enable bool) error {
	if enable {
		return errors.New("auto-start is currently only supported on Windows")
	}
	return nil
}

// IsAutoStartEnabled defaults to false on non-Windows platforms.
func (a *App) IsAutoStartEnabled() bool {
	return false
}

// EnsureSingleInstance is a no-op on non-Windows platforms.
// Single-instance enforcement is only implemented via Named Mutex on Windows.
func EnsureSingleInstance() {}
