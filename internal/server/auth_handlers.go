package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	challengeTTL       = 30 * time.Second
	challengeNonceSize = 32
)

// challengeRecord stores a pending challenge nonce
type challengeRecord struct {
	nonce     []byte
	expiresAt time.Time
}

// challengeStore manages pending authentication challenges (in-memory, TTL-based)
type challengeStore struct {
	mu         sync.Mutex
	challenges map[string]*challengeRecord // keyed by userId
}

func newChallengeStore() *challengeStore {
	return &challengeStore{
		challenges: make(map[string]*challengeRecord),
	}
}

// create generates a new challenge nonce for a userId (replaces any existing)
func (cs *challengeStore) create(userID string) ([]byte, error) {
	nonce := make([]byte, challengeNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Clean up expired challenges opportunistically
	now := time.Now()
	for k, v := range cs.challenges {
		if now.After(v.expiresAt) {
			delete(cs.challenges, k)
		}
	}

	cs.challenges[userID] = &challengeRecord{
		nonce:     nonce,
		expiresAt: now.Add(challengeTTL),
	}

	return nonce, nil
}

// verify checks a signature against the stored nonce, consuming it (one-time use)
func (cs *challengeStore) verify(userID string, pubKey ed25519.PublicKey, signatureB64 string) (bool, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	record, exists := cs.challenges[userID]
	if !exists {
		return false, nil
	}

	// Always delete the challenge (one-time use)
	delete(cs.challenges, userID)

	// Check expiry
	if time.Now().After(record.expiresAt) {
		return false, nil
	}

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, err
	}

	// Verify Ed25519 signature over the nonce
	return ed25519.Verify(pubKey, record.nonce, sigBytes), nil
}

// handleRegister handles POST /register
// Body: {"userId": "...", "publicKey": "base64..."}
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}

	var req struct {
		UserID    string `json:"userId"`
		PublicKey string `json:"publicKey"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	if req.UserID == "" || req.PublicKey == "" {
		s.jsonError(w, http.StatusBadRequest, "MISSING_FIELDS", "userId and publicKey are required")
		return
	}

	if err := s.userStore.Register(req.UserID, req.PublicKey); err != nil {
		if err.Error() == "userId already registered" {
			s.jsonError(w, http.StatusConflict, "ALREADY_REGISTERED", "This userId is already registered")
		} else {
			log.Printf("Registration error: %v", err)
			s.jsonError(w, http.StatusBadRequest, "INVALID_KEY", err.Error())
		}
		return
	}

	log.Printf("New user registered: %s", req.UserID)
	s.jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"status": "registered",
		"userId": req.UserID,
	})
}

// handleChallenge handles POST /challenge
// Body: {"userId": "..."}
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}

	var req struct {
		UserID string `json:"userId"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	if req.UserID == "" {
		s.jsonError(w, http.StatusBadRequest, "MISSING_FIELDS", "userId is required")
		return
	}

	if !s.userStore.Exists(req.UserID) {
		s.jsonError(w, http.StatusUnauthorized, "UNKNOWN_USER", "userId not registered")
		return
	}

	nonce, err := s.challenges.create(req.UserID)
	if err != nil {
		log.Printf("Challenge creation error: %v", err)
		s.jsonError(w, http.StatusInternalServerError, "SERVER_ERROR", "Failed to create challenge")
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"nonce": base64.StdEncoding.EncodeToString(nonce),
	})
}

// handleChallengeVerify handles POST /challenge/verify
// Body: {"userId": "...", "signature": "base64..."}
func (s *Server) handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}

	var req struct {
		UserID    string `json:"userId"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	if req.UserID == "" || req.Signature == "" {
		s.jsonError(w, http.StatusBadRequest, "MISSING_FIELDS", "userId and signature are required")
		return
	}

	// Get stored public key
	pubKey, err := s.userStore.GetPublicKey(req.UserID)
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, "UNKNOWN_USER", "userId not registered")
		return
	}

	// Verify signature against the stored challenge nonce
	valid, err := s.challenges.verify(req.UserID, pubKey, req.Signature)
	if err != nil {
		log.Printf("Challenge verification error for %s: %v", req.UserID, err)
		s.jsonError(w, http.StatusBadRequest, "INVALID_SIGNATURE", "Invalid signature format")
		return
	}

	if !valid {
		log.Printf("Challenge verification failed for user: %s", req.UserID)
		s.jsonError(w, http.StatusUnauthorized, "VERIFICATION_FAILED", "Signature verification failed or challenge expired")
		return
	}

	// Mint a short-lived JWT
	tokenString, expiry, err := s.jwtValidator.MintToken(req.UserID)
	if err != nil {
		log.Printf("Token minting error: %v", err)
		s.jsonError(w, http.StatusInternalServerError, "SERVER_ERROR", "Failed to create token")
		return
	}

	log.Printf("Token issued for user: %s (expires: %s)", req.UserID, expiry.Format(time.RFC3339))

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"access_token": tokenString,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(expiry).Seconds()),
	})
}

// JSON response helpers
func (s *Server) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, code, message string) {
	s.jsonResponse(w, status, map[string]interface{}{
		"error":   code,
		"message": message,
	})
}
