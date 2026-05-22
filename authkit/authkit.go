package authkit

import (
	"context"
	"errors"
	"time"

	"github.com/and2long/go-auth/authkit/internal/core"
)

const (
	ProviderEmail = core.ProviderEmail
	ProviderPhone = core.ProviderPhone
)

const (
	CodeInvalidCredentials = core.CodeInvalidCredentials
	CodeInvalidToken       = core.CodeInvalidToken
	CodeExpiredToken       = core.CodeExpiredToken
	CodeWeakPassword       = core.CodeWeakPassword
	CodeVerificationFailed = core.CodeVerificationFailed
	CodeEmailExists        = core.CodeEmailExists
	CodePhoneExists        = core.CodePhoneExists
	CodeProviderError      = core.CodeProviderError
	CodeNotFound           = core.CodeNotFound
	CodeConflict           = core.CodeConflict
	CodeInternal           = core.CodeInternal
)

var (
	ErrNotFound           = core.ErrNotFound
	ErrConflict           = core.ErrConflict
	ErrEmailExists        = core.ErrEmailExists
	ErrIdentityExists     = core.ErrIdentityExists
	ErrInvalidCredentials = core.ErrInvalidCredentials
	ErrInvalidToken       = core.ErrInvalidToken
	ErrExpiredToken       = core.ErrExpiredToken
	ErrWeakPassword       = core.ErrWeakPassword
	ErrProviderNotFound   = core.ErrProviderNotFound
	ErrVerificationFailed = core.ErrVerificationFailed
)

type (
	Config = core.Config
	Kit    = core.Kit

	ErrorCode = core.ErrorCode

	User         = core.User
	Identity     = core.Identity
	RefreshToken = core.RefreshToken
	Profile      = core.Profile
	AuthResult   = core.AuthResult
	OAuthUser    = core.OAuthUser
	Claims       = core.Claims

	PasswordHasher = core.PasswordHasher
	TokenManager   = core.TokenManager
	SMSVerifier    = core.SMSVerifier
	OAuthProvider  = core.OAuthProvider

	BcryptHasher = core.BcryptHasher
	JWTManager   = core.JWTManager
)

var (
	NewJWTManager = core.NewJWTManager
)

type Store interface {
	Create(ctx context.Context, user User) (User, error)
	FindByID(ctx context.Context, id string) (User, error)
	FindByEmail(ctx context.Context, email string) (User, error)
	FindByPhone(ctx context.Context, phone string) (User, error)
	Update(ctx context.Context, user User) (User, error)
	CreateUserWithIdentity(ctx context.Context, user User, identity Identity) (User, Identity, error)
	CreateIdentityRecord(ctx context.Context, identity Identity) (Identity, error)
	FindByProvider(ctx context.Context, provider, providerUserID string) (Identity, error)
	FindForUser(ctx context.Context, userID, provider string) (Identity, error)
	CreateRefreshToken(ctx context.Context, token RefreshToken) (RefreshToken, error)
	FindByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	Revoke(ctx context.Context, id string) error
	RevokeIfActive(ctx context.Context, id string, now time.Time) error
	RevokeAllForUser(ctx context.Context, userID string) error
}

type Option interface {
	apply(*options)
}

func NewWithStore(cfg Config, store Store, opts ...Option) (*Kit, error) {
	if store == nil {
		return nil, errors.New("authkit: store is required")
	}
	cfgOptions := options{}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(&cfgOptions)
		}
	}
	deps := core.Dependencies{
		Users:          store,
		Identities:     identityStore{store: store},
		UserIdentities: store,
		RefreshTokens:  refreshTokenStore{store: store},
		PasswordHasher: cfgOptions.passwordHasher,
		TokenManager:   cfgOptions.tokenManager,
		SMSVerifier:    cfgOptions.smsVerifier,
		OAuthProviders: cfgOptions.oauthProviders,
	}
	return core.New(cfg, deps)
}

func WithPasswordHasher(hasher PasswordHasher) Option {
	return optionFunc(func(opts *options) {
		opts.passwordHasher = hasher
	})
}

func WithTokenManager(manager TokenManager) Option {
	return optionFunc(func(opts *options) {
		opts.tokenManager = manager
	})
}

func WithSMSVerifier(verifier SMSVerifier) Option {
	return optionFunc(func(opts *options) {
		opts.smsVerifier = verifier
	})
}

func WithOAuthProviders(providers ...OAuthProvider) Option {
	return optionFunc(func(opts *options) {
		opts.oauthProviders = providers
	})
}

type options struct {
	passwordHasher PasswordHasher
	tokenManager   TokenManager
	smsVerifier    SMSVerifier
	oauthProviders []OAuthProvider
}

type optionFunc func(*options)

func (f optionFunc) apply(opts *options) {
	f(opts)
}

type identityStore struct {
	store Store
}

func (s identityStore) Create(ctx context.Context, identity Identity) (Identity, error) {
	return s.store.CreateIdentityRecord(ctx, identity)
}

func (s identityStore) FindByProvider(ctx context.Context, provider, providerUserID string) (Identity, error) {
	return s.store.FindByProvider(ctx, provider, providerUserID)
}

func (s identityStore) FindForUser(ctx context.Context, userID, provider string) (Identity, error) {
	return s.store.FindForUser(ctx, userID, provider)
}

type refreshTokenStore struct {
	store Store
}

func (s refreshTokenStore) Create(ctx context.Context, token RefreshToken) (RefreshToken, error) {
	return s.store.CreateRefreshToken(ctx, token)
}

func (s refreshTokenStore) FindByHash(ctx context.Context, tokenHash string) (RefreshToken, error) {
	return s.store.FindByHash(ctx, tokenHash)
}

func (s refreshTokenStore) Revoke(ctx context.Context, id string) error {
	return s.store.Revoke(ctx, id)
}

func (s refreshTokenStore) RevokeIfActive(ctx context.Context, id string, now time.Time) error {
	return s.store.RevokeIfActive(ctx, id, now)
}

func (s refreshTokenStore) RevokeAllForUser(ctx context.Context, userID string) error {
	return s.store.RevokeAllForUser(ctx, userID)
}
