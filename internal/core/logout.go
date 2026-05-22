package core

import (
	"context"
	"errors"
)

func (k *Kit) Logout(ctx context.Context, refreshToken string) error {
	stored, err := k.refreshTokens.FindByHash(ctx, hashToken(refreshToken))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return k.refreshTokens.Revoke(ctx, stored.ID)
}
