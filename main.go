package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/windows/icon.ico
var iconData []byte

func main() {
	// Prevent multiple instances: if VeriHash is already running, wake its
	// window (via WM_USER+1 broadcast) and exit this process immediately.
	EnsureSingleInstance()

	// Create an instance of the app structure
	app := NewApp()

	// Set up the tray immediately on the main thread BEFORE wails.Run
	// so the Win32 message loop is bound to the main OS thread.
	setupSystemTray(app)

	// Create application with options
	err := wails.Run(&options.App{
		Title:  "VeriHash",
		Width:  1160,
		Height: 768,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop: true,
		},
		HideWindowOnClose: true,
		BackgroundColour:  &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdownTray,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
