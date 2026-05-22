package core

import (
	"errors"
	"time"
)

type Config struct {
	Issuer          string
	SigningKey      []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	PasswordMinLen  int
	Now             func() time.Time
}

type Dependencies struct {
	Users          UserRepository
	Identities     IdentityRepository
	UserIdentities UserIdentityRepository
	RefreshTokens  RefreshTokenRepository
	PasswordHasher PasswordHasher
	TokenManager   TokenManager
	SMSVerifier    SMSVerifier
	OAuthProviders []OAuthProvider
}

func (c Config) withDefaults() Config {
	if c.Issuer == "" {
		c.Issuer = "authkit"
	}
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = 15 * time.Minute
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if c.PasswordMinLen == 0 {
		c.PasswordMinLen = 8
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c Config) validate(requireSigningKey bool) error {
	if requireSigningKey && len(c.SigningKey) < 32 {
		return errors.New("authkit: signing key must be at least 32 bytes")
	}
	if c.AccessTokenTTL <= 0 {
		return errors.New("authkit: access token ttl must be positive")
	}
	if c.RefreshTokenTTL <= 0 {
		return errors.New("authkit: refresh token ttl must be positive")
	}
	if c.PasswordMinLen <= 0 {
		return errors.New("authkit: password minimum length must be positive")
	}
	return nil
}
