package core

import (
	"context"
	"errors"
	"strings"
)

func (k *Kit) LoginWithEmail(ctx context.Context, email, password string) (AuthResult, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return AuthResult{}, ErrInvalidCredentials
	}
	identity, err := k.identities.FindByProvider(ctx, ProviderEmail, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return AuthResult{}, ErrInvalidCredentials
		}
		return AuthResult{}, err
	}
	if identity.PasswordHash == nil {
		return AuthResult{}, ErrInvalidCredentials
	}
	if err := k.hasher.Compare(*identity.PasswordHash, password); err != nil {
		return AuthResult{}, err
	}
	user, err := k.users.FindByID(ctx, identity.UserID)
	if err != nil {
		return AuthResult{}, err
	}
	return k.issue(ctx, user)
}

func (k *Kit) LoginWithPhone(ctx context.Context, phone, code string) (AuthResult, error) {
	phone = normalizePhone(phone)
	if phone == "" || k.sms == nil {
		return AuthResult{}, ErrVerificationFailed
	}
	if err := k.sms.Verify(ctx, phone, code); err != nil {
		return AuthResult{}, ErrVerificationFailed
	}
	identity, err := k.identities.FindByProvider(ctx, ProviderPhone, phone)
	if err == nil {
		user, err := k.users.FindByID(ctx, identity.UserID)
		if err != nil {
			return AuthResult{}, err
		}
		return k.issue(ctx, user)
	}
	if !errors.Is(err, ErrNotFound) {
		return AuthResult{}, err
	}
	user, err := k.createPhoneUser(ctx, phone)
	if err != nil {
		return AuthResult{}, err
	}
	return k.issue(ctx, user)
}

func (k *Kit) LoginWithOAuth(ctx context.Context, providerName, authCode string) (AuthResult, error) {
	provider := k.providers[providerName]
	if provider == nil {
		return AuthResult{}, ErrProviderNotFound
	}
	oauthUser, err := provider.Exchange(ctx, authCode)
	if err != nil {
		return AuthResult{}, err
	}
	oauthUser.ProviderUserID = strings.TrimSpace(oauthUser.ProviderUserID)
	if oauthUser.ProviderUserID == "" {
		return AuthResult{}, ErrInvalidCredentials
	}
	identity, err := k.identities.FindByProvider(ctx, provider.Name(), oauthUser.ProviderUserID)
	if err == nil {
		user, err := k.users.FindByID(ctx, identity.UserID)
		if err != nil {
			return AuthResult{}, err
		}
		return k.issue(ctx, user)
	}
	if !errors.Is(err, ErrNotFound) {
		return AuthResult{}, err
	}
	user, err := k.createOAuthUser(ctx, provider.Name(), oauthUser)
	if err != nil {
		return AuthResult{}, err
	}
	return k.issue(ctx, user)
}

func (k *Kit) CurrentUser(ctx context.Context, accessToken string) (User, error) {
	claims, err := k.tokens.Parse(accessToken)
	if err != nil {
		return User{}, err
	}
	return k.users.FindByID(ctx, claims.UserID)
}
