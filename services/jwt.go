package services

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/your-org/x509-mvc/models"
)

// Config holds JWT configuration.
type JWTConfig struct {
	AccessTokenSecret  string        `mapstructure:"access_token_secret"`
	RefreshTokenSecret string        `mapstructure:"refresh_token_secret"`
	AccessTokenTTL     time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL    time.Duration `mapstructure:"refresh_token_ttl"`
	Issuer             string        `mapstructure:"issuer"`
}

// AccessClaims are the claims embedded in an access token.
type AccessClaims struct {
	UserID   uint   `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// RefreshClaims are the claims embedded in a refresh token.
type RefreshClaims struct {
	TokenID string `json:"jti"`
	UserID  uint   `json:"uid"`
	jwt.RegisteredClaims
}

// TokenService handles JWT creation and validation.
type TokenService struct {
	cfg JWTConfig
}

// NewTokenService creates a new TokenService.
func NewTokenService(cfg JWTConfig) *TokenService {
	return &TokenService{cfg: cfg}
}

// GenerateAccessToken creates a signed JWT access token.
func (s *TokenService) GenerateAccessToken(userID uint, username, role string) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.cfg.AccessTokenTTL)

	claims := AccessClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.cfg.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.AccessTokenSecret))
	return signed, expiresAt, err
}

// GenerateRefreshToken creates a signed JWT refresh token with a random jti.
func (s *TokenService) GenerateRefreshToken(userID uint) (string, string, time.Time, error) {
	tokenID := newTokenID()
	expiresAt := time.Now().Add(s.cfg.RefreshTokenTTL)

	claims := RefreshClaims{
		TokenID: tokenID,
		UserID:  userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.cfg.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.RefreshTokenSecret))
	return signed, tokenID, expiresAt, err
}

// ValidateAccessToken verifies an access token and returns its claims.
func (s *TokenService) ValidateAccessToken(tokenString string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.cfg.AccessTokenSecret), nil
	})
	if err != nil {
		return nil, models.ErrTokenInvalid
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, models.ErrTokenInvalid
	}

	return claims, nil
}

// ValidateRefreshToken verifies a refresh token and returns its claims.
func (s *TokenService) ValidateRefreshToken(tokenString string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.cfg.RefreshTokenSecret), nil
	})
	if err != nil {
		return nil, models.ErrRefreshTokenInvalid
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok || !token.Valid {
		return nil, models.ErrRefreshTokenInvalid
	}

	return claims, nil
}

// newTokenID generates a random alphanumeric token ID.
func newTokenID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 32

	b := make([]byte, length)
	if _, err := readRandomBytes(b); err != nil {
		return "" // fallback: caller handles empty string
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
