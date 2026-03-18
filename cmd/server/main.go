package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mudlark-app/mudlark-proxy/internal/config"
	"github.com/mudlark-app/mudlark-proxy/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("MUDlark proxy server started on %s", cfg.Server.Address)

	// Wait for interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	registerSignals(sigChan) // platform-specific (signal_unix.go / signal_windows.go)

	restartDone := make(chan struct{})

	for {
		select {
		case sig := <-sigChan:
			if isGracefulRestart(sig) {
				// Graceful restart: warn clients, then shut down after delay.
				delay := 15 * time.Minute
				if d, ok := readRestartDelay(); ok {
					delay = d
				} else if envDelay := os.Getenv("RESTART_DELAY"); envDelay != "" {
					if d, err := time.ParseDuration(envDelay); err == nil {
						delay = d
					}
				}
				log.Printf("Received graceful restart signal: scheduling restart in %v", delay)
				srv.ScheduleRestart(delay, restartDone)
			} else {
				// SIGTERM/SIGINT: immediate graceful shutdown
				log.Println("Shutting down server...")
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if err := srv.Shutdown(ctx); err != nil {
					log.Printf("Error during shutdown: %v", err)
				}
				log.Println("Server stopped")
				return
			}
		case <-restartDone:
			// Scheduled restart timer elapsed
			log.Println("Scheduled restart: shutting down server...")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := srv.Shutdown(ctx); err != nil {
				log.Printf("Error during shutdown: %v", err)
			}
			log.Println("Server stopped (restart)")
			return
		}
	}
}

// readRestartDelay reads a restart delay from the temp file written by
// the graceful-restart script. Returns the delay and true if found.
func readRestartDelay() (time.Duration, bool) {
	path := restartDelayPath() // platform-specific
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	os.Remove(path)
	d, err := time.ParseDuration(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return d, true
}
