package gormrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/and2long/go-auth/authkit"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAutoMigrateUsesDefaultTablesWithoutPrefix(t *testing.T) {
	db := newTestDB(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	assertTableExists(t, db, "users")
	assertTableExists(t, db, "identities")
	assertTableExists(t, db, "refresh_tokens")
	assertTableMissing(t, db, "authkit_users")
}

func TestAutoMigrateUsesTablePrefix(t *testing.T) {
	db := newTestDB(t)
	store := New(db, WithTablePrefix("auth_"))
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	assertTableExists(t, db, "auth_users")
	assertTableExists(t, db, "auth_identities")
	assertTableExists(t, db, "auth_refresh_tokens")
	assertTableMissing(t, db, "users")
}

func TestAutoMigrateUsesCustomTables(t *testing.T) {
	db := newTestDB(t)
	store := New(db, WithTables(Tables{
		Users:         "app_users",
		Identities:    "app_user_identities",
		RefreshTokens: "app_refresh_tokens",
	}))
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	assertTableExists(t, db, "app_users")
	assertTableExists(t, db, "app_user_identities")
	assertTableExists(t, db, "app_refresh_tokens")
	assertTableMissing(t, db, "users")
}

func TestRevokeIfActiveOnlyRevokesOnce(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	token, err := store.CreateRefreshToken(ctx, authkit.RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: "hash-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	now := time.Now()
	if err := store.RevokeIfActive(ctx, token.ID, now); err != nil {
		t.Fatalf("first revoke should succeed: %v", err)
	}
	if err := store.RevokeIfActive(ctx, token.ID, now); !errors.Is(err, authkit.ErrInvalidToken) {
		t.Fatalf("second revoke should fail as replay, got %v", err)
	}
}

func TestRevokeIfActiveRejectsExpiredTokenAtomically(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	now := time.Now().UTC()
	token, err := store.CreateRefreshToken(ctx, authkit.RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: "hash-1",
		ExpiresAt: now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	if err := store.RevokeIfActive(ctx, token.ID, now); !errors.Is(err, authkit.ErrExpiredToken) {
		t.Fatalf("expired token should fail atomic revoke, got %v", err)
	}
	stored, err := store.FindByHash(ctx, token.TokenHash)
	if err != nil {
		t.Fatalf("find token: %v", err)
	}
	if stored.RevokedAt != nil {
		t.Fatal("expired token should not be revoked by RevokeIfActive")
	}
}

func TestRevokeIfActiveNormalizesCallerTimeToUTC(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	now := time.Now()
	token, err := store.CreateRefreshToken(ctx, authkit.RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: "hash-1",
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	if err := store.RevokeIfActive(ctx, token.ID, now); err != nil {
		t.Fatalf("local-time revoke should succeed after UTC normalization: %v", err)
	}
}

func TestCreateUserWithIdentityRollsBackUserOnIdentityConflict(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	_, _, err := store.CreateUserWithIdentity(ctx,
		authkit.User{ID: "user-1"},
		authkit.Identity{ID: "identity-1", UserID: "user-1", Provider: "email", ProviderUserID: "user@example.com"},
	)
	if err != nil {
		t.Fatalf("create first user with identity: %v", err)
	}

	_, _, err = store.CreateUserWithIdentity(ctx,
		authkit.User{ID: "user-2"},
		authkit.Identity{ID: "identity-2", UserID: "user-2", Provider: "email", ProviderUserID: "user@example.com"},
	)
	if !errors.Is(err, authkit.ErrIdentityExists) {
		t.Fatalf("expected identity exists, got %v", err)
	}
	if _, err := store.FindByID(ctx, "user-2"); !errors.Is(err, authkit.ErrNotFound) {
		t.Fatalf("conflicting identity should roll back user creation, got %v", err)
	}
}

func TestCreateUserWithIdentityMapsUserConflictWithoutTranslateError(t *testing.T) {
	ctx := context.Background()
	db := newTestDBWithoutTranslateError(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	_, _, err := store.CreateUserWithIdentity(ctx,
		authkit.User{ID: "user-1", Email: ptr("user@example.com")},
		authkit.Identity{ID: "identity-1", UserID: "user-1", Provider: "email", ProviderUserID: "user@example.com"},
	)
	if err != nil {
		t.Fatalf("create first user with identity: %v", err)
	}

	_, _, err = store.CreateUserWithIdentity(ctx,
		authkit.User{ID: "user-2", Email: ptr("user@example.com")},
		authkit.Identity{ID: "identity-2", UserID: "user-2", Provider: "email", ProviderUserID: "another@example.com"},
	)
	if !errors.Is(err, authkit.ErrConflict) {
		t.Fatalf("expected user conflict without TranslateError, got %v", err)
	}
}

func TestCreateUserWithIdentityMapsIdentityConflictWithoutTranslateError(t *testing.T) {
	ctx := context.Background()
	db := newTestDBWithoutTranslateError(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	_, _, err := store.CreateUserWithIdentity(ctx,
		authkit.User{ID: "user-1"},
		authkit.Identity{ID: "identity-1", UserID: "user-1", Provider: "email", ProviderUserID: "user@example.com"},
	)
	if err != nil {
		t.Fatalf("create first user with identity: %v", err)
	}

	_, _, err = store.CreateUserWithIdentity(ctx,
		authkit.User{ID: "user-2"},
		authkit.Identity{ID: "identity-2", UserID: "user-2", Provider: "email", ProviderUserID: "user@example.com"},
	)
	if !errors.Is(err, authkit.ErrIdentityExists) {
		t.Fatalf("expected identity exists without TranslateError, got %v", err)
	}
}

func TestUpdateReturnsNotFoundWithoutCreatingUser(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	_, err := store.Update(ctx, authkit.User{ID: "missing-user", Email: ptr("missing@example.com")})
	if !errors.Is(err, authkit.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	if _, err := store.FindByID(ctx, "missing-user"); !errors.Is(err, authkit.ErrNotFound) {
		t.Fatalf("missing user should not be inserted, got %v", err)
	}
}

func TestUpdateCanClearOptionalFields(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	store := New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	user, err := store.Create(ctx, authkit.User{
		ID:        "user-1",
		Email:     ptr("user@example.com"),
		Name:      ptr("User"),
		AvatarURL: ptr("https://example.com/avatar.png"),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	user.Name = nil
	user.AvatarURL = nil
	updated, err := store.Update(ctx, user)
	if err != nil {
		t.Fatalf("update user: %v", err)
	}
	if updated.Name != nil || updated.AvatarURL != nil {
		t.Fatalf("expected optional fields to be cleared, got name=%v avatar=%v", updated.Name, updated.AvatarURL)
	}
}

func TestDuplicateErrDetectionDoesNotMatchEveryConstraintFailure(t *testing.T) {
	if isDuplicateErr(errors.New("CHECK constraint failed: identities")) {
		t.Fatal("check constraint failure should not be treated as duplicate")
	}
	if !isDuplicateErr(errors.New("UNIQUE constraint failed: identities.provider, identities.provider_user_id")) {
		t.Fatal("unique constraint failure should be treated as duplicate")
	}
}

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func newTestDBWithoutTranslateError(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func ptr(s string) *string {
	return &s
}

func assertTableExists(t *testing.T, db *gorm.DB, table string) {
	t.Helper()
	if !db.Migrator().HasTable(table) {
		t.Fatalf("expected table %q to exist", table)
	}
}

func assertTableMissing(t *testing.T, db *gorm.DB, table string) {
	t.Helper()
	if db.Migrator().HasTable(table) {
		t.Fatalf("expected table %q to be missing", table)
	}
}
