package authkit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOAuthLoginCreatesAndReusesUser(t *testing.T) {
	provider := fakeOAuthProvider{name: "google", user: OAuthUser{ProviderUserID: "google-1", Email: "person@example.com", Name: "Person"}}
	kit := newOAuthTestKit(t, provider)
	ctx := context.Background()

	first, err := kit.LoginWithOAuth(ctx, "google", "token")
	if err != nil {
		t.Fatalf("oauth login: %v", err)
	}
	second, err := kit.LoginWithOAuth(ctx, "google", "token")
	if err != nil {
		t.Fatalf("second oauth login: %v", err)
	}
	if first.User.ID != second.User.ID {
		t.Fatalf("expected same user, got %s and %s", first.User.ID, second.User.ID)
	}
}

func TestOAuthLoginRejectsBlankProviderUserID(t *testing.T) {
	provider := fakeOAuthProvider{name: "google", user: OAuthUser{ProviderUserID: "   "}}
	kit := newOAuthTestKit(t, provider)

	_, err := kit.LoginWithOAuth(context.Background(), "google", "token")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func newOAuthTestKit(t *testing.T, providers ...fakeOAuthProvider) *Kit {
	t.Helper()
	store := newMemoryStore()
	oauthProviders := make([]oauthProvider, 0, len(providers))
	for _, provider := range providers {
		oauthProviders = append(oauthProviders, provider)
	}
	kit, err := NewWithStore(Config{
		Issuer:          "test",
		SigningKey:      []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
	}, store, withOAuthProviders(oauthProviders...))
	if err != nil {
		t.Fatalf("new kit: %v", err)
	}
	return kit
}

type fakeOAuthProvider struct {
	name string
	user OAuthUser
	err  error
}

func (p fakeOAuthProvider) Name() string {
	return p.name
}

func (p fakeOAuthProvider) Exchange(context.Context, string) (OAuthUser, error) {
	return p.user, p.err
}

type memoryStore struct {
	users         map[string]User
	identities    map[string]Identity
	refreshTokens map[string]RefreshToken
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		users:         map[string]User{},
		identities:    map[string]Identity{},
		refreshTokens: map[string]RefreshToken{},
	}
}

func (s *memoryStore) Create(_ context.Context, user User) (User, error) {
	s.users[user.ID] = user
	return user, nil
}

func (s *memoryStore) FindByID(_ context.Context, id string) (User, error) {
	user, ok := s.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return user, nil
}

func (s *memoryStore) FindByEmail(_ context.Context, email string) (User, error) {
	for _, user := range s.users {
		if user.Email != nil && *user.Email == email {
			return user, nil
		}
	}
	return User{}, ErrNotFound
}

func (s *memoryStore) FindByPhone(_ context.Context, phone string) (User, error) {
	for _, user := range s.users {
		if user.Phone != nil && *user.Phone == phone {
			return user, nil
		}
	}
	return User{}, ErrNotFound
}

func (s *memoryStore) Update(_ context.Context, user User) (User, error) {
	s.users[user.ID] = user
	return user, nil
}

func (s *memoryStore) CreateUserWithIdentity(_ context.Context, user User, identity Identity) (User, Identity, error) {
	if _, ok := s.identities[identity.Provider+"|"+identity.ProviderUserID]; ok {
		return User{}, Identity{}, ErrIdentityExists
	}
	s.users[user.ID] = user
	s.identities[identity.Provider+"|"+identity.ProviderUserID] = identity
	return user, identity, nil
}

func (s *memoryStore) CreateIdentityRecord(_ context.Context, identity Identity) (Identity, error) {
	s.identities[identity.Provider+"|"+identity.ProviderUserID] = identity
	return identity, nil
}

func (s *memoryStore) FindByProvider(_ context.Context, provider, providerUserID string) (Identity, error) {
	identity, ok := s.identities[provider+"|"+providerUserID]
	if !ok {
		return Identity{}, ErrNotFound
	}
	return identity, nil
}

func (s *memoryStore) FindForUser(_ context.Context, userID, provider string) (Identity, error) {
	for _, identity := range s.identities {
		if identity.UserID == userID && identity.Provider == provider {
			return identity, nil
		}
	}
	return Identity{}, ErrNotFound
}

func (s *memoryStore) CreateRefreshToken(_ context.Context, token RefreshToken) (RefreshToken, error) {
	s.refreshTokens[token.TokenHash] = token
	return token, nil
}

func (s *memoryStore) FindByHash(_ context.Context, tokenHash string) (RefreshToken, error) {
	token, ok := s.refreshTokens[tokenHash]
	if !ok {
		return RefreshToken{}, ErrNotFound
	}
	return token, nil
}

func (s *memoryStore) Revoke(_ context.Context, id string) error {
	for hash, token := range s.refreshTokens {
		if token.ID == id {
			now := time.Now()
			token.RevokedAt = &now
			s.refreshTokens[hash] = token
			return nil
		}
	}
	return ErrNotFound
}

func (s *memoryStore) RevokeIfActive(ctx context.Context, id string, _ time.Time) error {
	return s.Revoke(ctx, id)
}

func (s *memoryStore) RevokeAllForUser(_ context.Context, userID string) error {
	now := time.Now()
	for hash, token := range s.refreshTokens {
		if token.UserID == userID {
			token.RevokedAt = &now
			s.refreshTokens[hash] = token
		}
	}
	return nil
}
