package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mudlark-app/mudlark-proxy/internal/auth"
	"github.com/mudlark-app/mudlark-proxy/internal/config"
	"github.com/mudlark-app/mudlark-proxy/internal/session"
	"github.com/mudlark-app/mudlark-proxy/internal/userstore"
)

// quietErrorLog is a custom logger that filters out expected network errors
type quietErrorLog struct{}

func (q *quietErrorLog) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Filter out expected TLS/network errors that aren't actionable
	expectedErrors := []string{
		"connection reset by peer",
		"broken pipe",
		"connection abort",
		"use of closed network connection",
		"i/o timeout",
		"TLS handshake error",
		"EOF",
	}
	for _, expected := range expectedErrors {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(expected)) {
			// Still log but at a quieter level
			log.Printf("[HTTP] Expected error (non-fatal): %s", strings.TrimSpace(msg))
			return len(p), nil
		}
	}
	// Log unexpected errors normally
	log.Printf("[HTTP] %s", strings.TrimSpace(msg))
	return len(p), nil
}

// Server represents the proxy server
type Server struct {
	config         *config.Config
	httpServer     *http.Server
	sessionManager *session.Manager
	jwtValidator   *auth.Validator
	userStore      *userstore.Store
	challenges     *challengeStore
	cleanupTicker  *time.Ticker
	cleanupDone    chan struct{}
}

// New creates a new server instance
func New(cfg *config.Config) (*Server, error) {
	// Create JWT validator
	jwtValidator, err := auth.NewValidator(&cfg.Auth)
	if err != nil {
		return nil, err
	}

	// Create session manager
	sessionManager := session.NewManager(cfg)

	// Create user store for public key registration
	userStore, err := userstore.New(cfg.Auth.UserStorePath)
	if err != nil {
		return nil, err
	}
	log.Printf("User store loaded: %d registered users", userStore.Count())

	s := &Server{
		config:         cfg,
		sessionManager: sessionManager,
		jwtValidator:   jwtValidator,
		userStore:      userStore,
		challenges:     newChallengeStore(),
	}

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/challenge", s.handleChallenge)
	mux.HandleFunc("/challenge/verify", s.handleChallengeVerify)

	s.httpServer = &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		ErrorLog:     log.New(&quietErrorLog{}, "", 0), // Filter out expected network errors
	}

	return s, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Start cleanup goroutine for idle sessions
	s.cleanupTicker = time.NewTicker(1 * time.Minute)
	s.cleanupDone = make(chan struct{})

	go func() {
		for {
			select {
			case <-s.cleanupTicker.C:
				s.sessionManager.CleanupIdleSessions()
			case <-s.cleanupDone:
				return
			}
		}
	}()

	// Check if TLS is configured
	if s.config.Server.TLSCertFile != "" && s.config.Server.TLSKeyFile != "" {
		log.Printf("Starting HTTPS server on %s", s.config.Server.Address)

		// Configure TLS
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		s.httpServer.TLSConfig = tlsConfig

		go func() {
			if err := s.httpServer.ListenAndServeTLS(
				s.config.Server.TLSCertFile,
				s.config.Server.TLSKeyFile,
			); err != nil && err != http.ErrServerClosed {
				// Log but don't crash - could be transient network error
				log.Printf("HTTPS server error (fatal): %v", err)
			}
		}()
	} else {
		log.Printf("Starting HTTP server on %s (WARNING: TLS not configured)", s.config.Server.Address)
		go func() {
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				// Log but don't crash - could be transient network error
				log.Printf("HTTP server error (fatal): %v", err)
			}
		}()
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down HTTP server...")

	// Stop cleanup goroutine
	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
		close(s.cleanupDone)
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(shutdownCtx)
}

// ScheduleRestart broadcasts countdown warnings to all clients, then signals
// the provided done channel to trigger a graceful shutdown.
func (s *Server) ScheduleRestart(delay time.Duration, done chan<- struct{}) {
	go func() {
		log.Printf("Graceful restart scheduled in %v", delay)

		// Define warning intervals (only use intervals smaller than the total delay)
		warnings := []time.Duration{
			15 * time.Minute,
			10 * time.Minute,
			5 * time.Minute,
			1 * time.Minute,
			30 * time.Second,
		}

		deadline := time.Now().Add(delay)

		for _, w := range warnings {
			if delay < w {
				continue
			}
			waitUntil := deadline.Add(-w)
			sleepDur := time.Until(waitUntil)
			if sleepDur > 0 {
				time.Sleep(sleepDur)
			}
			msg := formatRestartWarning(w)
			log.Printf("Broadcasting restart warning: %v remaining", w)
			s.sessionManager.BroadcastSystemMessage(msg)
		}

		// Wait for the remaining time
		remaining := time.Until(deadline)
		if remaining > 0 {
			time.Sleep(remaining)
		}

		// Final warning
		s.sessionManager.BroadcastSystemMessage("\r\n*******\r\nSERVER RESTARTING NOW\r\n*******\r\n")
		time.Sleep(2 * time.Second) // Give clients a moment to receive it

		log.Println("Restart timer elapsed, initiating shutdown")
		close(done)
	}()
}

func formatRestartWarning(remaining time.Duration) string {
	var label string
	if remaining >= time.Minute {
		mins := int(remaining.Minutes())
		if mins == 1 {
			label = "1 MINUTE"
		} else {
			label = fmt.Sprintf("%d MINUTES", mins)
		}
	} else {
		label = fmt.Sprintf("%d SECONDS", int(remaining.Seconds()))
	}
	return fmt.Sprintf("\r\n*******\r\nWARNING: MUDFARK PROXY SERVER RESTART IN %s\r\n*******\r\n", label)
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":   "ok",
		"sessions": s.sessionManager.Count(),
	}

	json.NewEncoder(w).Encode(response)
}
