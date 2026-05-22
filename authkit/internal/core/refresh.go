package core

import (
	"context"
	"errors"
)

func (k *Kit) Refresh(ctx context.Context, refreshToken string) (AuthResult, error) {
	hash := hashToken(refreshToken)
	stored, err := k.refreshTokens.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return AuthResult{}, ErrInvalidToken
		}
		return AuthResult{}, err
	}
	now := k.cfg.Now().UTC()
	if stored.RevokedAt != nil {
		return AuthResult{}, ErrInvalidToken
	}
	if !stored.ExpiresAt.After(now) {
		return AuthResult{}, ErrExpiredToken
	}
	if err := k.refreshTokens.RevokeIfActive(ctx, stored.ID, now); err != nil {
		return AuthResult{}, err
	}
	user, err := k.users.FindByID(ctx, stored.UserID)
	if err != nil {
		return AuthResult{}, err
	}
	return k.issue(ctx, user)
}
