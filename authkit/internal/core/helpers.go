package core

import (
	"context"
	"errors"
	"net/mail"
	"strings"
)

func (k *Kit) createPhoneUser(ctx context.Context, phone string) (User, error) {
	userID, err := newID()
	if err != nil {
		return User{}, err
	}
	identityID, err := newID()
	if err != nil {
		return User{}, err
	}
	user := User{ID: userID, Phone: ptr(phone)}
	identity := Identity{
		ID:             identityID,
		UserID:         user.ID,
		Provider:       ProviderPhone,
		ProviderUserID: phone,
		Phone:          ptr(phone),
	}
	user, _, err = k.userIdentities.CreateUserWithIdentity(ctx, user, identity)
	if errors.Is(err, ErrIdentityExists) {
		return k.findUserByIdentityConflict(ctx, ProviderPhone, phone)
	}
	return user, err
}

func (k *Kit) createOAuthUser(ctx context.Context, provider string, oauthUser OAuthUser) (User, error) {
	userID, err := newID()
	if err != nil {
		return User{}, err
	}
	identityID, err := newID()
	if err != nil {
		return User{}, err
	}
	email := optionalEmail(oauthUser.Email)
	phone := optionalPhone(oauthUser.Phone)
	user := User{
		ID:        userID,
		Email:     email,
		Phone:     phone,
		Name:      optional(oauthUser.Name),
		AvatarURL: optional(oauthUser.AvatarURL),
	}
	identity := Identity{
		ID:             identityID,
		UserID:         user.ID,
		Provider:       provider,
		ProviderUserID: oauthUser.ProviderUserID,
		Email:          email,
		Phone:          phone,
	}
	user, _, err = k.userIdentities.CreateUserWithIdentity(ctx, user, identity)
	if errors.Is(err, ErrIdentityExists) {
		return k.findUserByIdentityConflict(ctx, provider, oauthUser.ProviderUserID)
	}
	return user, err
}

func (k *Kit) findUserByIdentityConflict(ctx context.Context, provider, providerUserID string) (User, error) {
	user, err := k.findUserByIdentity(ctx, provider, providerUserID)
	if errors.Is(err, ErrNotFound) {
		return User{}, ErrConflict
	}
	return user, err
}

func (k *Kit) findUserByIdentity(ctx context.Context, provider, providerUserID string) (User, error) {
	identity, err := k.identities.FindByProvider(ctx, provider, providerUserID)
	if err != nil {
		return User{}, err
	}
	return k.users.FindByID(ctx, identity.UserID)
}

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", ErrInvalidCredentials
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", err
	}
	if addr.Name != "" || addr.Address != email {
		return "", ErrInvalidCredentials
	}
	return email, nil
}

func normalizePhone(phone string) string {
	return strings.TrimSpace(phone)
}

func optional(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func optionalEmail(s string) *string {
	email, err := normalizeEmail(s)
	if err != nil {
		return nil
	}
	return &email
}

func optionalPhone(s string) *string {
	phone := normalizePhone(s)
	if phone == "" {
		return nil
	}
	return &phone
}

func ptr(s string) *string {
	return &s
}
