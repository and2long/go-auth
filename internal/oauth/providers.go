package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/and2long/go-auth/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

const (
	ProviderGoogle = "google"
	ProviderApple  = "apple"
	ProviderWeChat = "wechat"
)

const (
	EnvGoogleClientID = "GOOGLE_CLIENT_ID"
	EnvAppleClientID  = "APPLE_CLIENT_ID"
	EnvWeChatAppID    = "WECHAT_APP_ID"
	EnvWeChatSecret   = "WECHAT_APP_SECRET"
)

func ProvidersFromEnv() []core.OAuthProvider {
	var providers []core.OAuthProvider
	if clientID := os.Getenv(EnvGoogleClientID); clientID != "" {
		providers = append(providers, newGoogleIDTokenProvider(clientID))
	}
	if clientID := os.Getenv(EnvAppleClientID); clientID != "" {
		providers = append(providers, newAppleIDTokenProvider(clientID))
	}
	if appID, secret := os.Getenv(EnvWeChatAppID), os.Getenv(EnvWeChatSecret); appID != "" && secret != "" {
		providers = append(providers, newWeChatCodeProvider(appID, secret))
	}
	return providers
}

type googleIDTokenProvider struct {
	ClientID string
	KeysURL  string
	client   *http.Client
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
}

func newGoogleIDTokenProvider(clientID string) *googleIDTokenProvider {
	return &googleIDTokenProvider{
		ClientID: clientID,
		KeysURL:  "https://www.googleapis.com/oauth2/v3/certs",
		client:   http.DefaultClient,
	}
}

func (p *googleIDTokenProvider) Name() string {
	return ProviderGoogle
}

func (p *googleIDTokenProvider) Exchange(ctx context.Context, idToken string) (core.OAuthUser, error) {
	if p.ClientID == "" {
		return core.OAuthUser{}, errors.New("authkit: google client id is required")
	}
	claims := &googleClaims{}
	token, err := jwt.ParseWithClaims(
		idToken,
		claims,
		p.keyFunc(ctx),
		jwt.WithAudience(p.ClientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return core.OAuthUser{}, err
	}
	if !token.Valid {
		return core.OAuthUser{}, errors.New("authkit: invalid google id token")
	}
	if claims.Issuer != "https://accounts.google.com" && claims.Issuer != "accounts.google.com" {
		return core.OAuthUser{}, errors.New("authkit: invalid google id token issuer")
	}
	return core.OAuthUser{
		ProviderUserID: claims.Subject,
		Email:          claims.Email,
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
	}, nil
}

type googleClaims struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	jwt.RegisteredClaims
}

func (p *googleIDTokenProvider) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("authkit: unexpected google signing method")
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("authkit: missing google key id")
		}
		key, err := p.publicKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}

func (p *googleIDTokenProvider) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	key := p.keys[kid]
	p.mu.RUnlock()
	if key != nil {
		return key, nil
	}

	keys, err := fetchJWKS(ctx, p.client, p.KeysURL, "google")
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.keys = keys
	key = p.keys[kid]
	p.mu.Unlock()
	if key == nil {
		return nil, errors.New("authkit: google public key not found")
	}
	return key, nil
}

type appleIDTokenProvider struct {
	ClientID string
	KeysURL  string
	client   *http.Client
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
}

func newAppleIDTokenProvider(clientID string) *appleIDTokenProvider {
	return &appleIDTokenProvider{
		ClientID: clientID,
		KeysURL:  "https://appleid.apple.com/auth/keys",
		client:   http.DefaultClient,
	}
}

func (p *appleIDTokenProvider) Name() string {
	return ProviderApple
}

func (p *appleIDTokenProvider) Exchange(ctx context.Context, idToken string) (core.OAuthUser, error) {
	if p.ClientID == "" {
		return core.OAuthUser{}, errors.New("authkit: apple client id is required")
	}
	claims := &appleClaims{}
	token, err := jwt.ParseWithClaims(
		idToken,
		claims,
		p.keyFunc(ctx),
		jwt.WithAudience(p.ClientID),
		jwt.WithIssuer("https://appleid.apple.com"),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return core.OAuthUser{}, err
	}
	if !token.Valid {
		return core.OAuthUser{}, errors.New("authkit: invalid apple id token")
	}
	return core.OAuthUser{
		ProviderUserID: claims.Subject,
		Email:          claims.Email,
		Name:           claims.Name,
	}, nil
}

type appleClaims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	jwt.RegisteredClaims
}

type weChatCodeProvider struct {
	AppID       string
	Secret      string
	TokenURL    string
	UserInfoURL string
	client      *http.Client
}

func newWeChatCodeProvider(appID, secret string) *weChatCodeProvider {
	return &weChatCodeProvider{
		AppID:       appID,
		Secret:      secret,
		TokenURL:    "https://api.weixin.qq.com/sns/oauth2/access_token",
		UserInfoURL: "https://api.weixin.qq.com/sns/userinfo",
		client:      http.DefaultClient,
	}
}

func (p *weChatCodeProvider) Name() string {
	return ProviderWeChat
}

func (p *weChatCodeProvider) Exchange(ctx context.Context, code string) (core.OAuthUser, error) {
	if p.AppID == "" || p.Secret == "" {
		return core.OAuthUser{}, errors.New("authkit: wechat app id and secret are required")
	}
	token, err := p.exchangeToken(ctx, code)
	if err != nil {
		return core.OAuthUser{}, err
	}

	user := core.OAuthUser{
		ProviderUserID: firstNonEmpty(token.UnionID, token.OpenID),
	}
	profile, err := p.fetchUserInfo(ctx, token.AccessToken, token.OpenID)
	if err != nil {
		return user, nil
	}
	if profile.UnionID != "" {
		user.ProviderUserID = profile.UnionID
	}
	user.Name = profile.Nickname
	user.AvatarURL = profile.HeadImgURL
	return user, nil
}

type weChatTokenResponse struct {
	AccessToken string `json:"access_token"`
	OpenID      string `json:"openid"`
	UnionID     string `json:"unionid"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

type weChatUserInfoResponse struct {
	OpenID     string `json:"openid"`
	UnionID    string `json:"unionid"`
	Nickname   string `json:"nickname"`
	HeadImgURL string `json:"headimgurl"`
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
}

func (p *weChatCodeProvider) exchangeToken(ctx context.Context, code string) (weChatTokenResponse, error) {
	values := url.Values{}
	values.Set("appid", p.AppID)
	values.Set("secret", p.Secret)
	values.Set("code", code)
	values.Set("grant_type", "authorization_code")

	var token weChatTokenResponse
	if err := getJSON(ctx, p.client, p.TokenURL+"?"+values.Encode(), &token); err != nil {
		return weChatTokenResponse{}, err
	}
	if token.ErrCode != 0 {
		return weChatTokenResponse{}, errors.New("authkit: wechat token exchange failed: " + token.ErrMsg)
	}
	if token.OpenID == "" {
		return weChatTokenResponse{}, errors.New("authkit: wechat openid is required")
	}
	return token, nil
}

func (p *weChatCodeProvider) fetchUserInfo(ctx context.Context, accessToken, openID string) (weChatUserInfoResponse, error) {
	values := url.Values{}
	values.Set("access_token", accessToken)
	values.Set("openid", openID)
	values.Set("lang", "zh_CN")

	var profile weChatUserInfoResponse
	if err := getJSON(ctx, p.client, p.UserInfoURL+"?"+values.Encode(), &profile); err != nil {
		return weChatUserInfoResponse{}, err
	}
	if profile.ErrCode != 0 {
		return weChatUserInfoResponse{}, errors.New("authkit: wechat userinfo failed: " + profile.ErrMsg)
	}
	return profile, nil
}

func (p *appleIDTokenProvider) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("authkit: unexpected apple signing method")
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("authkit: missing apple key id")
		}
		key, err := p.publicKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}

func (p *appleIDTokenProvider) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	key := p.keys[kid]
	p.mu.RUnlock()
	if key != nil {
		return key, nil
	}

	keys, err := fetchJWKS(ctx, p.client, p.KeysURL, "apple")
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.keys = keys
	key = p.keys[kid]
	p.mu.Unlock()
	if key == nil {
		return nil, errors.New("authkit: apple public key not found")
	}
	return key, nil
}

func fetchJWKS(ctx context.Context, client *http.Client, keysURL, provider string) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := getJSON(ctx, client, keysURL, &set); err != nil {
		return nil, errors.New("authkit: " + provider + " jwks request failed: " + err.Error())
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, key := range set.Keys {
		publicKey, err := rsaPublicKey(key.N, key.E)
		if err != nil {
			return nil, err
		}
		keys[key.KID] = publicKey
	}
	return keys, nil
}

func getJSON(ctx context.Context, client *http.Client, requestURL string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("unexpected status code")
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

func rsaPublicKey(nValue, eValue string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nValue)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eValue)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		return nil, errors.New("authkit: invalid rsa public exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
