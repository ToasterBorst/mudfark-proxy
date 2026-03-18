package session

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/mudlark-app/mudlark-proxy/internal/config"
)

// Manager manages all active sessions
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	config   *config.Config
}

// NewManager creates a new session manager
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		config:   cfg,
	}
}

// GetOrCreate gets an existing session or creates a new one
func (m *Manager) GetOrCreate(sessionID, userID, mudHost string, mudPort, connectionTime, mudIdleTimeoutMinutes, bufferTimeoutMinutes int, mudTLS bool) (*Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session exists
	if existing, ok := m.sessions[sessionID]; ok {
		// Verify ownership
		if err := existing.VerifyOwnership(userID); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}

	// Create new session
	session, err := NewSession(sessionID, userID, mudHost, mudPort, connectionTime, mudIdleTimeoutMinutes, bufferTimeoutMinutes, mudTLS, m.config)
	if err != nil {
		return nil, false, err
	}

	m.sessions[sessionID] = session
	return session, true, nil
}

// Get retrieves a session by ID
func (m *Manager) Get(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// Remove removes a session
func (m *Manager) Remove(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.sessions[sessionID]; ok {
		session.Close()
		delete(m.sessions, sessionID)
	}
}

// Count returns the number of active sessions
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// CleanupIdleSessions handles cleanup of idle MUD connections and expired sessions
func (m *Manager) CleanupIdleSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, session := range m.sessions {
		// First check if MUD connection should be disconnected (no clients for MUD idle timeout)
		if session.ShouldDisconnectMUD() {
			log.Printf("[Manager] Disconnecting idle MUD connection for session %s", id)
			session.DisconnectFromMUD()
		}

		// Then check if entire session should be removed (exceeded buffer timeout)
		if session.IsIdle() {
			log.Printf("[Manager] Removing expired session %s (buffer timeout)", id)
			session.Close()
			delete(m.sessions, id)
		}
	}
}

// BroadcastSystemMessage sends a system message to all clients across all sessions
func (m *Manager) BroadcastSystemMessage(text string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, session := range m.sessions {
		session.BroadcastSystemMessage(text)
	}
}

// mustMarshalJSON marshals data to JSON or returns empty JSON on error
func mustMarshalJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("JSON marshal error (non-fatal): %v", err)
		return []byte("{}")
	}
	return data
}
