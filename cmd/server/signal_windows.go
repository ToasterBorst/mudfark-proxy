//go:build windows

package main

import (
	"os"
	"os/signal"
	"path/filepath"
)

// registerSignals sets up signal handling for Windows.
// Only SIGINT (Ctrl+C) is reliably supported; graceful restart via signal
// is not available on Windows.
func registerSignals(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt)
}

// isGracefulRestart always returns false on Windows since SIGUSR1 does not exist.
func isGracefulRestart(_ os.Signal) bool {
	return false
}

// restartDelayPath returns the path to the restart delay temp file.
func restartDelayPath() string {
	return filepath.Join(os.TempDir(), "mudlark-restart-delay")
}
