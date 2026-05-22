package core

import "context"

func (k *Kit) issue(ctx context.Context, user User) (AuthResult, error) {
	accessToken, expiresIn, err := k.tokens.Issue(user)
	if err != nil {
		return AuthResult{}, err
	}
	refreshToken, err := newSecret()
	if err != nil {
		return AuthResult{}, err
	}
	refreshID, err := newID()
	if err != nil {
		return AuthResult{}, err
	}
	_, err = k.refreshTokens.Create(ctx, RefreshToken{
		ID:        refreshID,
		UserID:    user.ID,
		TokenHash: hashToken(refreshToken),
		ExpiresAt: k.cfg.Now().UTC().Add(k.cfg.RefreshTokenTTL),
	})
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: user, AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: expiresIn}, nil
}
