package core

import (
	"context"
	"errors"
)

func (k *Kit) RegisterWithEmail(ctx context.Context, email, password string, profile Profile) (AuthResult, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return AuthResult{}, ErrInvalidCredentials
	}
	if len(password) < k.cfg.PasswordMinLen {
		return AuthResult{}, ErrWeakPassword
	}
	if _, err := k.users.FindByEmail(ctx, email); err == nil {
		return AuthResult{}, ErrEmailExists
	} else if !errors.Is(err, ErrNotFound) {
		return AuthResult{}, err
	}
	userID, err := newID()
	if err != nil {
		return AuthResult{}, err
	}
	identityID, err := newID()
	if err != nil {
		return AuthResult{}, err
	}
	hash, err := k.hasher.Hash(password)
	if err != nil {
		return AuthResult{}, err
	}
	user := User{
		ID:        userID,
		Email:     ptr(email),
		Name:      optional(profile.Name),
		AvatarURL: optional(profile.AvatarURL),
	}
	identity := Identity{
		ID:             identityID,
		UserID:         user.ID,
		Provider:       ProviderEmail,
		ProviderUserID: email,
		Email:          ptr(email),
		PasswordHash:   ptr(hash),
	}
	user, _, err = k.userIdentities.CreateUserWithIdentity(ctx, user, identity)
	if err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrIdentityExists) {
			return AuthResult{}, ErrEmailExists
		}
		return AuthResult{}, err
	}
	return k.issue(ctx, user)
}
