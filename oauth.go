package authkit

import "github.com/and2long/go-auth/internal/oauth"

const (
	ProviderGoogle = oauth.ProviderGoogle
	ProviderApple  = oauth.ProviderApple
	ProviderWeChat = oauth.ProviderWeChat
)

const (
	EnvGoogleClientID = oauth.EnvGoogleClientID
	EnvAppleClientID  = oauth.EnvAppleClientID
	EnvWeChatAppID    = oauth.EnvWeChatAppID
	EnvWeChatSecret   = oauth.EnvWeChatSecret
)

func WithOAuthProvidersFromEnv() Option {
	return withOAuthProviders(oauth.ProvidersFromEnv()...)
}
