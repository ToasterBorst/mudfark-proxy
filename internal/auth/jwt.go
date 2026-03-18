package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mudlark-app/mudlark-proxy/internal/config"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenExpired    = errors.New("token expired")
	ErrInvalidAudience = errors.New("invalid audience")
	ErrInvalidIssuer   = errors.New("invalid issuer")
	ErrMissingClaims   = errors.New("missing required claims")
)

// Claims represents the JWT claims we expect
type Claims struct {
	jwt.RegisteredClaims
	SessionID  string `json:"sid"`
	UserID     string `json:"sub"`
	EgressPool string `json:"egress_pool,omitempty"`
}

// Validator handles JWT validation and minting
type Validator struct {
	secret      []byte
	algorithm   string
	audience    string
	issuer      string
	maxAge      time.Duration
	tokenExpiry time.Duration
}

// NewValidator creates a new JWT validator
func NewValidator(cfg *config.AuthConfig) (*Validator, error) {
	if cfg.JWTSecret == "" {
		return nil, errors.New("jwt_secret is required")
	}

	tokenExpiry := cfg.TokenExpiry
	if tokenExpiry == 0 {
		tokenExpiry = 15 * time.Minute
	}

	return &Validator{
		secret:      []byte(cfg.JWTSecret),
		algorithm:   cfg.JWTAlgorithm,
		audience:    cfg.Audience,
		issuer:      cfg.Issuer,
		maxAge:      cfg.MaxTokenAge,
		tokenExpiry: tokenExpiry,
	}, nil
}

// ValidateToken validates a JWT token string and returns the claims
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify algorithm
		if token.Method.Alg() != v.algorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Validate expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	// Validate audience
	if v.audience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == v.audience {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrInvalidAudience
		}
	}

	// Validate issuer
	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, ErrInvalidIssuer
	}

	// Validate required custom claims (SessionID is optional for server-minted tokens)
	if claims.UserID == "" {
		return nil, ErrMissingClaims
	}

	return claims, nil
}

// MintToken creates a new short-lived JWT for an authenticated user
func (v *Validator) MintToken(userID string) (string, time.Time, error) {
	now := time.Now()
	expiry := now.Add(v.tokenExpiry)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Audience:  jwt.ClaimStrings{v.audience},
			Issuer:    v.issuer,
		},
		UserID: userID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(v.secret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiry, nil
}
