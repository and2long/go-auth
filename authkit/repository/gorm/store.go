package gormrepo

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/and2long/go-auth/authkit"
	"gorm.io/gorm"
)

type Store struct {
	db     *gorm.DB
	tables Tables
}

type Tables struct {
	Users         string
	Identities    string
	RefreshTokens string
}

type Option func(*Store)

func New(db *gorm.DB, opts ...Option) *Store {
	store := &Store{
		db:     db,
		tables: defaultTables(),
	}
	for _, opt := range opts {
		opt(store)
	}
	store.tables = store.tables.withDefaults()
	return store
}

func WithTablePrefix(prefix string) Option {
	return func(s *Store) {
		defaults := defaultTables()
		s.tables = Tables{
			Users:         prefix + defaults.Users,
			Identities:    prefix + defaults.Identities,
			RefreshTokens: prefix + defaults.RefreshTokens,
		}
	}
}

func WithTables(tables Tables) Option {
	return func(s *Store) {
		if tables.Users != "" {
			s.tables.Users = tables.Users
		}
		if tables.Identities != "" {
			s.tables.Identities = tables.Identities
		}
		if tables.RefreshTokens != "" {
			s.tables.RefreshTokens = tables.RefreshTokens
		}
	}
}

func (s *Store) AutoMigrate() error {
	if err := s.db.Table(s.tables.Users).AutoMigrate(&UserModel{}); err != nil {
		return err
	}
	if err := s.db.Table(s.tables.Identities).AutoMigrate(&IdentityModel{}); err != nil {
		return err
	}
	return s.db.Table(s.tables.RefreshTokens).AutoMigrate(&RefreshTokenModel{})
}

func (s *Store) Tables() Tables {
	return s.tables
}

func defaultTables() Tables {
	return Tables{
		Users:         "users",
		Identities:    "identities",
		RefreshTokens: "refresh_tokens",
	}
}

func (t Tables) withDefaults() Tables {
	defaults := defaultTables()
	if t.Users == "" {
		t.Users = defaults.Users
	}
	if t.Identities == "" {
		t.Identities = defaults.Identities
	}
	if t.RefreshTokens == "" {
		t.RefreshTokens = defaults.RefreshTokens
	}
	return t
}

type UserModel struct {
	ID        string  `gorm:"primaryKey;size:64"`
	Email     *string `gorm:"uniqueIndex;size:320"`
	Phone     *string `gorm:"uniqueIndex;size:64"`
	Name      *string `gorm:"size:255"`
	AvatarURL *string `gorm:"size:1024"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type IdentityModel struct {
	ID             string  `gorm:"primaryKey;size:64"`
	UserID         string  `gorm:"index;not null;size:64"`
	Provider       string  `gorm:"uniqueIndex:idx_provider_user;not null;size:64"`
	ProviderUserID string  `gorm:"uniqueIndex:idx_provider_user;not null;size:320"`
	Email          *string `gorm:"size:320"`
	Phone          *string `gorm:"size:64"`
	PasswordHash   *string `gorm:"size:255"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type RefreshTokenModel struct {
	ID        string `gorm:"primaryKey;size:64"`
	UserID    string `gorm:"index;not null;size:64"`
	TokenHash string `gorm:"uniqueIndex;not null;size:64"`
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s *Store) Create(ctx context.Context, user authkit.User) (authkit.User, error) {
	model := userToModel(user)
	if err := s.users(ctx).Create(&model).Error; err != nil {
		return authkit.User{}, mapWriteErr(err)
	}
	return modelToUser(model), nil
}

func (s *Store) FindByID(ctx context.Context, id string) (authkit.User, error) {
	var model UserModel
	err := s.users(ctx).First(&model, "id = ?", id).Error
	return modelToUser(model), mapReadErr(err)
}

func (s *Store) FindByEmail(ctx context.Context, email string) (authkit.User, error) {
	var model UserModel
	err := s.users(ctx).First(&model, "email = ?", email).Error
	return modelToUser(model), mapReadErr(err)
}

func (s *Store) FindByPhone(ctx context.Context, phone string) (authkit.User, error) {
	var model UserModel
	err := s.users(ctx).First(&model, "phone = ?", phone).Error
	return modelToUser(model), mapReadErr(err)
}

func (s *Store) Update(ctx context.Context, user authkit.User) (authkit.User, error) {
	if _, err := s.FindByID(ctx, user.ID); err != nil {
		return authkit.User{}, err
	}
	model := userToModel(user)
	result := s.users(ctx).Where("id = ?", model.ID).Updates(map[string]any{
		"email":      model.Email,
		"phone":      model.Phone,
		"name":       model.Name,
		"avatar_url": model.AvatarURL,
	})
	if result.Error != nil {
		return authkit.User{}, mapWriteErr(result.Error)
	}
	updated, err := s.FindByID(ctx, model.ID)
	if err != nil {
		return authkit.User{}, err
	}
	return updated, nil
}

func (s *Store) CreateUserWithIdentity(ctx context.Context, user authkit.User, identity authkit.Identity) (authkit.User, authkit.Identity, error) {
	userModel := userToModel(user)
	identityModel := identityToModel(identity)

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Table(s.tables.Users).Create(&userModel).Error; err != nil {
			return mapWriteErr(err)
		}
		identityModel.UserID = userModel.ID
		if err := tx.Table(s.tables.Identities).Create(&identityModel).Error; err != nil {
			if isDuplicateErr(err) {
				return authkit.ErrIdentityExists
			}
			return err
		}
		return nil
	})
	if err != nil {
		return authkit.User{}, authkit.Identity{}, err
	}
	return modelToUser(userModel), modelToIdentity(identityModel), nil
}

func (s *Store) CreateIdentity(ctx context.Context, identity authkit.Identity) (authkit.Identity, error) {
	return s.CreateIdentityRecord(ctx, identity)
}

func (s *Store) CreateIdentityRecord(ctx context.Context, identity authkit.Identity) (authkit.Identity, error) {
	model := identityToModel(identity)
	if err := s.identities(ctx).Create(&model).Error; err != nil {
		return authkit.Identity{}, mapWriteErr(err)
	}
	return modelToIdentity(model), nil
}

func (s *Store) FindByProvider(ctx context.Context, provider, providerUserID string) (authkit.Identity, error) {
	var model IdentityModel
	err := s.identities(ctx).First(&model, "provider = ? AND provider_user_id = ?", provider, providerUserID).Error
	return modelToIdentity(model), mapReadErr(err)
}

func (s *Store) FindForUser(ctx context.Context, userID, provider string) (authkit.Identity, error) {
	var model IdentityModel
	err := s.identities(ctx).First(&model, "user_id = ? AND provider = ?", userID, provider).Error
	return modelToIdentity(model), mapReadErr(err)
}

func (s *Store) CreateToken(ctx context.Context, token authkit.RefreshToken) (authkit.RefreshToken, error) {
	return s.CreateRefreshToken(ctx, token)
}

func (s *Store) CreateRefreshToken(ctx context.Context, token authkit.RefreshToken) (authkit.RefreshToken, error) {
	model := refreshTokenToModel(token)
	if err := s.refreshTokens(ctx).Create(&model).Error; err != nil {
		return authkit.RefreshToken{}, mapWriteErr(err)
	}
	return modelToRefreshToken(model), nil
}

func (s *Store) FindByHash(ctx context.Context, tokenHash string) (authkit.RefreshToken, error) {
	var model RefreshTokenModel
	err := s.refreshTokens(ctx).First(&model, "token_hash = ?", tokenHash).Error
	return modelToRefreshToken(model), mapReadErr(err)
}

func (s *Store) Revoke(ctx context.Context, id string) error {
	now := time.Now().UTC()
	err := s.refreshTokens(ctx).Where("id = ?", id).Update("revoked_at", &now).Error
	return mapReadErr(err)
}

func (s *Store) RevokeIfActive(ctx context.Context, id string, now time.Time) error {
	now = now.UTC()
	result := s.refreshTokens(ctx).
		Where("id = ? AND revoked_at IS NULL AND expires_at > ?", id, now).
		Update("revoked_at", &now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		var model RefreshTokenModel
		err := s.refreshTokens(ctx).Select("expires_at", "revoked_at").First(&model, "id = ?", id).Error
		if errors.Is(mapReadErr(err), authkit.ErrNotFound) {
			return authkit.ErrInvalidToken
		}
		if err != nil {
			return err
		}
		if model.RevokedAt != nil {
			return authkit.ErrInvalidToken
		}
		if !model.ExpiresAt.After(now) {
			return authkit.ErrExpiredToken
		}
		return authkit.ErrInvalidToken
	}
	return nil
}

func (s *Store) RevokeAllForUser(ctx context.Context, userID string) error {
	now := time.Now().UTC()
	err := s.refreshTokens(ctx).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now).Error
	return err
}

func (s *Store) CreateIdentityAlias(ctx context.Context, identity authkit.Identity) (authkit.Identity, error) {
	return s.CreateIdentityRecord(ctx, identity)
}

func (s *Store) CreateRefreshTokenAlias(ctx context.Context, token authkit.RefreshToken) (authkit.RefreshToken, error) {
	return s.CreateRefreshToken(ctx, token)
}

func userToModel(user authkit.User) UserModel {
	return UserModel{
		ID:        user.ID,
		Email:     user.Email,
		Phone:     user.Phone,
		Name:      user.Name,
		AvatarURL: user.AvatarURL,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func modelToUser(model UserModel) authkit.User {
	return authkit.User{
		ID:        model.ID,
		Email:     model.Email,
		Phone:     model.Phone,
		Name:      model.Name,
		AvatarURL: model.AvatarURL,
		CreatedAt: model.CreatedAt,
		UpdatedAt: model.UpdatedAt,
	}
}

func identityToModel(identity authkit.Identity) IdentityModel {
	return IdentityModel{
		ID:             identity.ID,
		UserID:         identity.UserID,
		Provider:       identity.Provider,
		ProviderUserID: identity.ProviderUserID,
		Email:          identity.Email,
		Phone:          identity.Phone,
		PasswordHash:   identity.PasswordHash,
		CreatedAt:      identity.CreatedAt,
		UpdatedAt:      identity.UpdatedAt,
	}
}

func modelToIdentity(model IdentityModel) authkit.Identity {
	return authkit.Identity{
		ID:             model.ID,
		UserID:         model.UserID,
		Provider:       model.Provider,
		ProviderUserID: model.ProviderUserID,
		Email:          model.Email,
		Phone:          model.Phone,
		PasswordHash:   model.PasswordHash,
		CreatedAt:      model.CreatedAt,
		UpdatedAt:      model.UpdatedAt,
	}
}

func refreshTokenToModel(token authkit.RefreshToken) RefreshTokenModel {
	revokedAt := utcPtr(token.RevokedAt)
	return RefreshTokenModel{
		ID:        token.ID,
		UserID:    token.UserID,
		TokenHash: token.TokenHash,
		ExpiresAt: token.ExpiresAt.UTC(),
		RevokedAt: revokedAt,
		CreatedAt: token.CreatedAt,
		UpdatedAt: token.UpdatedAt,
	}
}

func modelToRefreshToken(model RefreshTokenModel) authkit.RefreshToken {
	return authkit.RefreshToken{
		ID:        model.ID,
		UserID:    model.UserID,
		TokenHash: model.TokenHash,
		ExpiresAt: model.ExpiresAt,
		RevokedAt: model.RevokedAt,
		CreatedAt: model.CreatedAt,
		UpdatedAt: model.UpdatedAt,
	}
}

func mapReadErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return authkit.ErrNotFound
	}
	return err
}

func mapWriteErr(err error) error {
	if err == nil {
		return nil
	}
	if isDuplicateErr(err) {
		return authkit.ErrConflict
	}
	return err
}

func isDuplicateErr(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "duplicate entry") ||
		strings.Contains(msg, "duplicated key") ||
		strings.Contains(msg, "unique constraint failed") ||
		strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "error 1062") ||
		strings.Contains(msg, "sqlstate 23505")
}

var _ authkit.Store = (*Store)(nil)

func (s *Store) users(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx).Table(s.tables.Users).Model(&UserModel{})
}

func (s *Store) identities(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx).Table(s.tables.Identities).Model(&IdentityModel{})
}

func (s *Store) refreshTokens(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx).Table(s.tables.RefreshTokens).Model(&RefreshTokenModel{})
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}
