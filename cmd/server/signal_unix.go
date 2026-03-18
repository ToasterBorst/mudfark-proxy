//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// registerSignals sets up signal handling for Unix systems.
// SIGINT/SIGTERM = shutdown, SIGUSR1 = graceful restart.
func registerSignals(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
}

// isGracefulRestart returns true for SIGUSR1.
func isGracefulRestart(sig os.Signal) bool {
	return sig == syscall.SIGUSR1
}

// restartDelayPath returns the path to the restart delay temp file.
func restartDelayPath() string {
	return "/run/mudlark-restart-delay"
}
