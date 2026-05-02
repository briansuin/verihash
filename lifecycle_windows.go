//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows/registry"
)

// isAutoStartLaunch returns true when the app was launched by Windows at boot
// (i.e. the --autostart flag was injected by ToggleAutoStart into the registry value).
func isAutoStartLaunch() bool {
	for _, arg := range os.Args[1:] {
		if arg == "--autostart" {
			return true
		}
	}
	return false
}

// setupSystemTray initializes the system tray icon, tooltips, and menus
func setupSystemTray(ctx context.Context) {
	// systray.Run in energye fork is more stable in goroutines for Windows/Wails
	go systray.Run(func() {
		systray.SetIcon(iconData)
		systray.SetTitle("VeriHash")
		systray.SetTooltip("VeriHash Node Running")

		// BIND LEFT CLICK: Show window directly
		systray.SetOnClick(func(menu systray.IMenu) {
			runtime.WindowShow(ctx)
		})

		// BIND RIGHT CLICK: Show context menu
		systray.SetOnRClick(func(menu systray.IMenu) {
			menu.ShowMenu()
		})

		mShow := systray.AddMenuItem("Show VeriHash", "Bring VeriHash window to front")
		mShow.Click(func() {
			runtime.WindowShow(ctx)
		})

		systray.AddSeparator()
		
		mQuit := systray.AddMenuItem("Quit", "Terminate the VeriHash background node")
		mQuit.Click(func() {
			// Signal Wails to quit; cleanup handled in OnExit
			runtime.Quit(ctx)
		})
	}, func() {
		// onExit: Clean up tray icon
		systray.Quit()
	})
}

// ToggleAutoStart adds or removes VeriHash from the Windows boot sequence
func (a *App) ToggleAutoStart(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("could not open registry: %v", err)
	}
	defer k.Close()

	if enable {
		exePath, err := os.Executable()
		if err != nil {
			return err
		}
		// --autostart flag lets the app detect a boot-time launch and hide its window silently
		err = k.SetStringValue("VeriHash", "\""+exePath+"\"" + " --autostart")
		if err != nil {
			return fmt.Errorf("failed to set registry value: %v", err)
		}
	} else {
		err = k.DeleteValue("VeriHash")
		if err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("failed to delete registry value: %v", err)
		}
	}
	
	// Update config as well
	config := a.LoadConfig()
	config.AutoStart = enable
	
	bytes, err := json.MarshalIndent(config, "", "  ")
	if err == nil {
		os.WriteFile(configPath, bytes, 0644)
	}
	
	return nil
}

// IsAutoStartEnabled checks if VeriHash is currently set to boot with Windows
func (a *App) IsAutoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue("VeriHash")
	if err != nil {
		return false
	}
	
	exePath, _ := os.Executable()
	// Accept both the plain path and the path with the --autostart flag
	return val == "\""+exePath+"\"" || val == "\""+exePath+"\"" + " --autostart"
}
