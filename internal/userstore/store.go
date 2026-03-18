package userstore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// UserRecord represents a registered user with their Ed25519 public key
type UserRecord struct {
	UserID    string    `json:"userId"`
	PublicKey string    `json:"publicKey"` // base64-encoded Ed25519 public key (32 bytes)
	CreatedAt time.Time `json:"createdAt"`
}

// Store manages user registrations with file-based persistence
type Store struct {
	mu       sync.RWMutex
	users    map[string]*UserRecord // keyed by userId
	filePath string
}

// Sentinel errors
var (
	ErrAlreadyRegistered = fmt.Errorf("userId already registered")
	ErrUserNotFound      = fmt.Errorf("userId not registered")
)

// New creates a new user store, loading existing data from disk
func New(filePath string) (*Store, error) {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("creating user store directory: %w", err)
	}

	s := &Store{
		users:    make(map[string]*UserRecord),
		filePath: filePath,
	}

	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading user store: %w", err)
	}

	return s, nil
}

// Register stores a new user's public key. Returns error if userId is already registered.
func (s *Store) Register(userID, publicKeyB64 string) error {
	// Validate the public key is valid Ed25519 (32 bytes)
	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return fmt.Errorf("invalid base64 public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[userID]; exists {
		return ErrAlreadyRegistered
	}

	s.users[userID] = &UserRecord{
		UserID:    userID,
		PublicKey: publicKeyB64,
		CreatedAt: time.Now(),
	}

	return s.save()
}

// GetPublicKey returns the Ed25519 public key bytes for a userId
func (s *Store) GetPublicKey(userID string) (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(record.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("corrupt public key data: %w", err)
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// Exists checks if a userId is registered
func (s *Store) Exists(userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.users[userID]
	return exists
}

// Count returns the number of registered users
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var records []*UserRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("parsing user store: %w", err)
	}

	for _, r := range records {
		s.users[r.UserID] = r
	}

	return nil
}

func (s *Store) save() error {
	records := make([]*UserRecord, 0, len(s.users))
	for _, r := range s.users {
		records = append(records, r)
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling user store: %w", err)
	}

	return os.WriteFile(s.filePath, data, 0640)
}
