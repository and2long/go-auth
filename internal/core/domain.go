package core

import (
	"context"
	"errors"
	"time"
)

const (
	ProviderEmail = "email"
	ProviderPhone = "phone"
)

var (
	ErrNotFound           = errors.New("authkit: not found")
	ErrConflict           = errors.New("authkit: conflict")
	ErrEmailExists        = errors.New("authkit: email exists")
	ErrIdentityExists     = errors.New("authkit: identity exists")
	ErrInvalidCredentials = errors.New("authkit: invalid credentials")
	ErrInvalidToken       = errors.New("authkit: invalid token")
	ErrExpiredToken       = errors.New("authkit: expired token")
	ErrWeakPassword       = errors.New("authkit: weak password")
	ErrProviderNotFound   = errors.New("authkit: provider not found")
	ErrVerificationFailed = errors.New("authkit: verification failed")
)

type ErrorCode string

const (
	CodeInvalidCredentials ErrorCode = "invalid_credentials"
	CodeInvalidToken       ErrorCode = "invalid_token"
	CodeExpiredToken       ErrorCode = "expired_token"
	CodeWeakPassword       ErrorCode = "weak_password"
	CodeVerificationFailed ErrorCode = "verification_failed"
	CodeEmailExists        ErrorCode = "email_exists"
	CodePhoneExists        ErrorCode = "phone_exists"
	CodeProviderError      ErrorCode = "provider_error"
	CodeNotFound           ErrorCode = "not_found"
	CodeConflict           ErrorCode = "conflict"
	CodeInternal           ErrorCode = "internal_error"
)

type User struct {
	ID        string    `json:"id"`
	Email     *string   `json:"email"`
	Phone     *string   `json:"phone"`
	Name      *string   `json:"name"`
	AvatarURL *string   `json:"avatar_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Identity struct {
	ID             string
	UserID         string
	Provider       string
	ProviderUserID string
	Email          *string
	Phone          *string
	PasswordHash   *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Profile struct {
	Name      string
	AvatarURL string
}

type AuthResult struct {
	User         User
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type OAuthUser struct {
	ProviderUserID string
	Email          string
	Phone          string
	Name           string
	AvatarURL      string
}

type Claims struct {
	UserID string
	Email  string
	Phone  string
}

type UserRepository interface {
	Create(ctx context.Context, user User) (User, error)
	FindByID(ctx context.Context, id string) (User, error)
	FindByEmail(ctx context.Context, email string) (User, error)
	FindByPhone(ctx context.Context, phone string) (User, error)
	Update(ctx context.Context, user User) (User, error)
}

type IdentityRepository interface {
	Create(ctx context.Context, identity Identity) (Identity, error)
	FindByProvider(ctx context.Context, provider, providerUserID string) (Identity, error)
	FindForUser(ctx context.Context, userID, provider string) (Identity, error)
}

type UserIdentityRepository interface {
	CreateUserWithIdentity(ctx context.Context, user User, identity Identity) (User, Identity, error)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token RefreshToken) (RefreshToken, error)
	FindByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	Revoke(ctx context.Context, id string) error
	RevokeIfActive(ctx context.Context, id string, now time.Time) error
	RevokeAllForUser(ctx context.Context, userID string) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

type TokenManager interface {
	Issue(user User) (accessToken string, expiresIn int64, err error)
	Parse(accessToken string) (Claims, error)
}

type SMSVerifier interface {
	Verify(ctx context.Context, phone, code string) error
}

type OAuthProvider interface {
	Name() string
	Exchange(ctx context.Context, authCode string) (OAuthUser, error)
}
