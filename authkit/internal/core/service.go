package core

import "errors"

type Kit struct {
	cfg            Config
	users          UserRepository
	identities     IdentityRepository
	userIdentities UserIdentityRepository
	refreshTokens  RefreshTokenRepository
	hasher         PasswordHasher
	tokens         TokenManager
	sms            SMSVerifier
	providers      map[string]OAuthProvider
}

func New(cfg Config, deps Dependencies) (*Kit, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(deps.TokenManager == nil); err != nil {
		return nil, err
	}
	if deps.UserIdentities == nil {
		if repo, ok := deps.Users.(UserIdentityRepository); ok {
			deps.UserIdentities = repo
		}
	}
	if deps.Users == nil || deps.Identities == nil || deps.UserIdentities == nil || deps.RefreshTokens == nil {
		return nil, errors.New("authkit: repositories are required")
	}
	if deps.PasswordHasher == nil {
		deps.PasswordHasher = BcryptHasher{}
	}
	if deps.TokenManager == nil {
		deps.TokenManager = NewJWTManager(cfg)
	}
	if validator, ok := deps.TokenManager.(interface{ validate() error }); ok {
		if err := validator.validate(); err != nil {
			return nil, err
		}
	}
	providers := make(map[string]OAuthProvider, len(deps.OAuthProviders))
	for _, provider := range deps.OAuthProviders {
		if provider != nil && provider.Name() != "" {
			providers[provider.Name()] = provider
		}
	}
	return &Kit{
		cfg:            cfg,
		users:          deps.Users,
		identities:     deps.Identities,
		userIdentities: deps.UserIdentities,
		refreshTokens:  deps.RefreshTokens,
		hasher:         deps.PasswordHasher,
		tokens:         deps.TokenManager,
		sms:            deps.SMSVerifier,
		providers:      providers,
	}, nil
}
