package authkit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/and2long/go-auth/authkit"
	gormrepo "github.com/and2long/go-auth/authkit/repository/gorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestEmailRegisterLoginRefreshAndLogout(t *testing.T) {
	kit := newTestKit(t, nil, nil)
	ctx := context.Background()

	registered, err := kit.RegisterWithEmail(ctx, "USER@example.com", "password123", authkit.Profile{Name: "User"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if registered.User.Email == nil || *registered.User.Email != "user@example.com" {
		t.Fatalf("email was not normalized: %#v", registered.User.Email)
	}
	if registered.AccessToken == "" || registered.RefreshToken == "" {
		t.Fatal("expected tokens")
	}

	if _, err := kit.RegisterWithEmail(ctx, "user@example.com", "password123", authkit.Profile{}); !errors.Is(err, authkit.ErrEmailExists) {
		t.Fatalf("expected duplicate email exists, got %v", err)
	}

	if _, err := kit.LoginWithEmail(ctx, "user@example.com", "wrong-password"); !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}

	loggedIn, err := kit.LoginWithEmail(ctx, "user@example.com", "password123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	current, err := kit.CurrentUser(ctx, loggedIn.AccessToken)
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	if current.ID != registered.User.ID {
		t.Fatalf("current user mismatch: got %s want %s", current.ID, registered.User.ID)
	}

	refreshed, err := kit.Refresh(ctx, loggedIn.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.RefreshToken == loggedIn.RefreshToken {
		t.Fatal("expected refresh token rotation")
	}
	if _, err := kit.Refresh(ctx, loggedIn.RefreshToken); !errors.Is(err, authkit.ErrInvalidToken) {
		t.Fatalf("expected replayed refresh token to fail, got %v", err)
	}
	if err := kit.Logout(ctx, refreshed.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := kit.Refresh(ctx, refreshed.RefreshToken); !errors.Is(err, authkit.ErrInvalidToken) {
		t.Fatalf("expected logged out refresh token to fail, got %v", err)
	}
}

func TestWeakPassword(t *testing.T) {
	kit := newTestKit(t, nil, nil)
	_, err := kit.RegisterWithEmail(context.Background(), "user@example.com", "short", authkit.Profile{})
	if !errors.Is(err, authkit.ErrWeakPassword) {
		t.Fatalf("expected weak password, got %v", err)
	}
}

func TestDuplicateEmailReturnsEmailExists(t *testing.T) {
	kit := newTestKit(t, nil, nil)
	ctx := context.Background()
	if _, err := kit.RegisterWithEmail(ctx, "user@example.com", "password123", authkit.Profile{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := kit.RegisterWithEmail(ctx, "user@example.com", "password123", authkit.Profile{}); !errors.Is(err, authkit.ErrEmailExists) {
		t.Fatalf("expected email exists, got %v", err)
	}
}

func TestRejectsDisplayNameEmail(t *testing.T) {
	kit := newTestKit(t, nil, nil)
	_, err := kit.RegisterWithEmail(context.Background(), "User <user@example.com>", "password123", authkit.Profile{})
	if !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials for display-name email, got %v", err)
	}
}

func TestRegisterEmailIdentityConflictReturnsEmailExists(t *testing.T) {
	store := &identityConflictStore{
		user:     authkit.User{ID: "existing-user"},
		identity: authkit.Identity{ID: "identity-1", UserID: "existing-user", Provider: authkit.ProviderEmail, ProviderUserID: "user@example.com"},
	}
	kit := newConflictTestKit(t, store)

	_, err := kit.RegisterWithEmail(context.Background(), "user@example.com", "password123", authkit.Profile{})
	if !errors.Is(err, authkit.ErrEmailExists) {
		t.Fatalf("expected email exists for identity conflict, got %v", err)
	}
}

func TestPhoneLoginCreatesAndReusesUser(t *testing.T) {
	sms := fakeSMSVerifier{}
	kit := newTestKit(t, sms, nil)
	ctx := context.Background()

	first, err := kit.LoginWithPhone(ctx, "+15555550100", "123456")
	if err != nil {
		t.Fatalf("phone login: %v", err)
	}
	second, err := kit.LoginWithPhone(ctx, "+15555550100", "123456")
	if err != nil {
		t.Fatalf("second phone login: %v", err)
	}
	if first.User.ID != second.User.ID {
		t.Fatalf("expected same user, got %s and %s", first.User.ID, second.User.ID)
	}
}

func TestPhoneLoginConflictReusesExistingIdentity(t *testing.T) {
	store := &identityConflictStore{
		user:     authkit.User{ID: "existing-user", Phone: stringPtr("+15555550100")},
		identity: authkit.Identity{ID: "identity-1", UserID: "existing-user", Provider: authkit.ProviderPhone, ProviderUserID: "+15555550100"},
	}
	kit := newConflictTestKit(t, store)
	ctx := context.Background()

	result, err := kit.LoginWithPhone(ctx, "+15555550100", "123456")
	if err != nil {
		t.Fatalf("phone login after conflict path should succeed: %v", err)
	}
	if result.User.ID != "existing-user" {
		t.Fatalf("expected existing user, got %s", result.User.ID)
	}
	if store.providerLookups != 2 {
		t.Fatalf("expected identity lookup before and after conflict, got %d", store.providerLookups)
	}
}

func TestOAuthLoginCreatesAndReusesUser(t *testing.T) {
	provider := fakeProvider{name: "google", user: authkit.OAuthUser{ProviderUserID: "google-1", Email: "person@example.com", Name: "Person"}}
	kit := newTestKit(t, nil, []authkit.OAuthProvider{provider})
	ctx := context.Background()

	first, err := kit.LoginWithOAuth(ctx, "google", "code")
	if err != nil {
		t.Fatalf("oauth login: %v", err)
	}
	second, err := kit.LoginWithOAuth(ctx, "google", "code")
	if err != nil {
		t.Fatalf("second oauth login: %v", err)
	}
	if first.User.ID != second.User.ID {
		t.Fatalf("expected same user, got %s and %s", first.User.ID, second.User.ID)
	}
}

func TestUnknownOAuthProvider(t *testing.T) {
	kit := newTestKit(t, nil, nil)
	_, err := kit.LoginWithOAuth(context.Background(), "google", "code")
	if !errors.Is(err, authkit.ErrProviderNotFound) {
		t.Fatalf("expected provider not found, got %v", err)
	}
}

func TestOAuthLoginRejectsBlankProviderUserID(t *testing.T) {
	provider := fakeProvider{name: "google", user: authkit.OAuthUser{ProviderUserID: "   "}}
	kit := newTestKit(t, nil, []authkit.OAuthProvider{provider})

	_, err := kit.LoginWithOAuth(context.Background(), "google", "code")
	if !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestCustomTokenManagerDoesNotRequireSigningKey(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	store := gormrepo.New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_, err = authkit.NewWithStore(authkit.Config{}, store, authkit.WithTokenManager(fakeTokenManager{}))
	if err != nil {
		t.Fatalf("custom token manager should not require signing key: %v", err)
	}
}

func TestBuiltInTokenManagerRequiresSigningKey(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	store := gormrepo.New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	_, err = authkit.NewWithStore(authkit.Config{}, store, authkit.WithTokenManager(authkit.NewJWTManager(authkit.Config{})))
	if err == nil {
		t.Fatal("expected built-in jwt manager without signing key to fail")
	}
}

func TestJWTManagerRejectsShortSigningKeyWhenUsedDirectly(t *testing.T) {
	manager := authkit.NewJWTManager(authkit.Config{})
	if _, _, err := manager.Issue(authkit.User{ID: "user-1"}); err == nil {
		t.Fatal("expected direct jwt manager issue with empty signing key to fail")
	}
	if _, err := manager.Parse("token"); err == nil {
		t.Fatal("expected direct jwt manager parse with empty signing key to fail")
	}
}

func TestNegativePasswordMinLenRejected(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	store := gormrepo.New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	_, err = authkit.NewWithStore(authkit.Config{
		SigningKey:     []byte("0123456789abcdef0123456789abcdef"),
		PasswordMinLen: -1,
	}, store)
	if err == nil {
		t.Fatal("expected negative password minimum length to fail")
	}
}

func TestNewWithStoreRejectsNilStore(t *testing.T) {
	_, err := authkit.NewWithStore(authkit.Config{
		SigningKey: []byte("0123456789abcdef0123456789abcdef"),
	}, nil)
	if err == nil {
		t.Fatal("expected nil store to fail")
	}
}

func newTestKit(t *testing.T, sms authkit.SMSVerifier, providers []authkit.OAuthProvider) *authkit.Kit {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	store := gormrepo.New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	kit, err := authkit.NewWithStore(authkit.Config{
		Issuer:          "test",
		SigningKey:      []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
	}, store, authkit.WithSMSVerifier(sms), authkit.WithOAuthProviders(providers...))
	if err != nil {
		t.Fatalf("new kit: %v", err)
	}
	return kit
}

func newConflictTestKit(t *testing.T, store *identityConflictStore) *authkit.Kit {
	t.Helper()
	kit, err := authkit.NewWithStore(authkit.Config{
		SigningKey:      []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
	}, store, authkit.WithSMSVerifier(fakeSMSVerifier{}), authkit.WithTokenManager(fakeTokenManager{}))
	if err != nil {
		t.Fatalf("new kit: %v", err)
	}
	return kit
}

func stringPtr(s string) *string {
	return &s
}

type fakeSMSVerifier struct{}

func (fakeSMSVerifier) Verify(_ context.Context, _, code string) error {
	if code != "123456" {
		return authkit.ErrVerificationFailed
	}
	return nil
}

type fakeProvider struct {
	name string
	user authkit.OAuthUser
	err  error
}

func (p fakeProvider) Name() string {
	return p.name
}

func (p fakeProvider) Exchange(context.Context, string) (authkit.OAuthUser, error) {
	return p.user, p.err
}

type fakeTokenManager struct{}

func (fakeTokenManager) Issue(authkit.User) (string, int64, error) {
	return "access-token", 60, nil
}

func (fakeTokenManager) Parse(string) (authkit.Claims, error) {
	return authkit.Claims{UserID: "user-1"}, nil
}

type identityConflictStore struct {
	user            authkit.User
	identity        authkit.Identity
	providerLookups int
}

func (s *identityConflictStore) Create(context.Context, authkit.User) (authkit.User, error) {
	return authkit.User{}, authkit.ErrConflict
}

func (s *identityConflictStore) FindByID(_ context.Context, id string) (authkit.User, error) {
	if id == s.user.ID {
		return s.user, nil
	}
	return authkit.User{}, authkit.ErrNotFound
}

func (s *identityConflictStore) FindByEmail(context.Context, string) (authkit.User, error) {
	return authkit.User{}, authkit.ErrNotFound
}

func (s *identityConflictStore) FindByPhone(context.Context, string) (authkit.User, error) {
	return authkit.User{}, authkit.ErrNotFound
}

func (s *identityConflictStore) Update(_ context.Context, user authkit.User) (authkit.User, error) {
	return user, nil
}

func (s *identityConflictStore) CreateUserWithIdentity(context.Context, authkit.User, authkit.Identity) (authkit.User, authkit.Identity, error) {
	return authkit.User{}, authkit.Identity{}, authkit.ErrIdentityExists
}

func (s *identityConflictStore) CreateIdentityRecord(_ context.Context, identity authkit.Identity) (authkit.Identity, error) {
	return identity, nil
}

func (s *identityConflictStore) FindByProvider(context.Context, string, string) (authkit.Identity, error) {
	s.providerLookups++
	if s.providerLookups == 1 {
		return authkit.Identity{}, authkit.ErrNotFound
	}
	return s.identity, nil
}

func (s *identityConflictStore) FindForUser(context.Context, string, string) (authkit.Identity, error) {
	return authkit.Identity{}, authkit.ErrNotFound
}

func (s *identityConflictStore) CreateRefreshToken(_ context.Context, token authkit.RefreshToken) (authkit.RefreshToken, error) {
	return token, nil
}

func (s *identityConflictStore) FindByHash(context.Context, string) (authkit.RefreshToken, error) {
	return authkit.RefreshToken{}, authkit.ErrNotFound
}

func (s *identityConflictStore) Revoke(context.Context, string) error {
	return nil
}

func (s *identityConflictStore) RevokeIfActive(context.Context, string, time.Time) error {
	return nil
}

func (s *identityConflictStore) RevokeAllForUser(context.Context, string) error {
	return nil
}
