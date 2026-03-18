package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const envJWTSecret = "JWT_SECRET"

// Config holds all configuration for the proxy server
type Config struct {
	Server ServerConfig `yaml:"server"`
	Auth   AuthConfig   `yaml:"auth"`
	Buffer BufferConfig `yaml:"buffer"`
	MUD    MUDConfig    `yaml:"mud"`
}

// ServerConfig holds HTTP/WebSocket server configuration
type ServerConfig struct {
	Address      string        `yaml:"address"`       // e.g., ":8443"
	TLSCertFile  string        `yaml:"tls_cert_file"` // Path to TLS certificate
	TLSKeyFile   string        `yaml:"tls_key_file"`  // Path to TLS private key
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

// AuthConfig holds JWT authentication configuration
type AuthConfig struct {
	JWTSecret      string        `yaml:"jwt_secret"`      // HMAC secret for HS256
	JWTAlgorithm   string        `yaml:"jwt_algorithm"`   // "HS256" or "RS256"
	JWTPublicKey   string        `yaml:"jwt_public_key"`  // Path to public key for RS256
	Audience       string        `yaml:"audience"`        // Expected "aud" claim
	Issuer         string        `yaml:"issuer"`          // Expected "iss" claim
	MaxTokenAge    time.Duration `yaml:"max_token_age"`   // Maximum age for tokens
	TokenExpiry    time.Duration `yaml:"token_expiry"`    // Expiry for server-issued tokens
	AllowedOrigins []string      `yaml:"allowed_origins"` // Allowed WebSocket origins
	UserStorePath  string        `yaml:"user_store_path"` // Path to user registration store
}

// BufferConfig holds ring buffer configuration
type BufferConfig struct {
	Capacity     int           `yaml:"capacity"`      // Number of lines to store
	MaxReplay    int           `yaml:"max_replay"`    // Maximum lines to replay
	SensitiveRE  string        `yaml:"sensitive_re"`  // Regex for password detection
	SensitiveTTL time.Duration `yaml:"sensitive_ttl"` // How long to stay in sensitive mode
}

// MUDConfig holds MUD connection configuration
type MUDConfig struct {
	ConnectTimeout time.Duration `yaml:"connect_timeout"` // Timeout for connecting to MUD
	ReadTimeout    time.Duration `yaml:"read_timeout"`    // Read timeout for MUD socket
	WriteTimeout   time.Duration `yaml:"write_timeout"`   // Write timeout for MUD socket
	IdleTimeout    time.Duration `yaml:"idle_timeout"`    // How long to keep session alive without client
	LineEnding     string        `yaml:"line_ending"`     // "\n" or "\r\n"
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Set defaults
	if cfg.Server.Address == "" {
		cfg.Server.Address = ":443"
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 60 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 60 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 120 * time.Second
	}

	// Override jwt_secret from environment variable if set
	if envSecret := os.Getenv(envJWTSecret); envSecret != "" {
		cfg.Auth.JWTSecret = envSecret
	}

	if cfg.Auth.Audience == "" {
		cfg.Auth.Audience = "mudlark-client"
	}
	if cfg.Auth.Issuer == "" {
		cfg.Auth.Issuer = "mudlark-proxy"
	}
	if cfg.Auth.JWTAlgorithm == "" {
		cfg.Auth.JWTAlgorithm = "HS256"
	}
	if cfg.Auth.MaxTokenAge == 0 {
		cfg.Auth.MaxTokenAge = 24 * time.Hour
	}
	if cfg.Auth.TokenExpiry == 0 {
		cfg.Auth.TokenExpiry = 15 * time.Minute
	}
	if cfg.Auth.UserStorePath == "" {
		cfg.Auth.UserStorePath = "data/users.json"
	}

	if cfg.Buffer.Capacity == 0 {
		cfg.Buffer.Capacity = 2000
	}
	if cfg.Buffer.MaxReplay == 0 {
		cfg.Buffer.MaxReplay = 2000
	}
	if cfg.Buffer.SensitiveRE == "" {
		cfg.Buffer.SensitiveRE = `(?i)password[:>\s]`
	}
	if cfg.Buffer.SensitiveTTL == 0 {
		cfg.Buffer.SensitiveTTL = 10 * time.Second
	}

	if cfg.MUD.ConnectTimeout == 0 {
		cfg.MUD.ConnectTimeout = 10 * time.Second
	}
	if cfg.MUD.ReadTimeout == 0 {
		cfg.MUD.ReadTimeout = 5 * time.Minute
	}
	if cfg.MUD.WriteTimeout == 0 {
		cfg.MUD.WriteTimeout = 30 * time.Second
	}
	if cfg.MUD.IdleTimeout == 0 {
		cfg.MUD.IdleTimeout = 60 * time.Minute
	}
	if cfg.MUD.LineEnding == "" {
		cfg.MUD.LineEnding = "\n"
	}

	return cfg, nil
}
