package authkit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGoogleIDTokenProviderExchange(t *testing.T) {
	privateKey, keysURL := testJWKS(t, "google-key")
	provider := newGoogleIDTokenProvider("google-client-id")
	provider.KeysURL = keysURL

	idToken := signTestToken(t, privateKey, "google-key", jwt.MapClaims{
		"iss":     "https://accounts.google.com",
		"aud":     "google-client-id",
		"sub":     "google-user",
		"email":   "person@example.com",
		"name":    "Person",
		"picture": "https://example.com/avatar.png",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})

	user, err := provider.Exchange(context.Background(), idToken)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if user.ProviderUserID != "google-user" || user.Email != "person@example.com" || user.Name != "Person" || user.AvatarURL == "" {
		t.Fatalf("unexpected google user: %#v", user)
	}
}

func TestAppleIDTokenProviderExchange(t *testing.T) {
	privateKey, keysURL := testJWKS(t, "apple-key")
	provider := newAppleIDTokenProvider("apple-client-id")
	provider.KeysURL = keysURL

	idToken := signTestToken(t, privateKey, "apple-key", jwt.MapClaims{
		"iss":   "https://appleid.apple.com",
		"aud":   "apple-client-id",
		"sub":   "apple-user",
		"email": "person@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	user, err := provider.Exchange(context.Background(), idToken)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if user.ProviderUserID != "apple-user" || user.Email != "person@example.com" {
		t.Fatalf("unexpected apple user: %#v", user)
	}
}

func TestOAuthProvidersFromEnv(t *testing.T) {
	t.Setenv(EnvGoogleClientID, "google-client-id")
	t.Setenv(EnvAppleClientID, "apple-client-id")
	t.Setenv(EnvWeChatAppID, "wechat-app-id")
	t.Setenv(EnvWeChatSecret, "wechat-secret")

	providers := oauthProvidersFromEnv()
	if len(providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(providers))
	}
	if providers[0].Name() != ProviderGoogle || providers[1].Name() != ProviderApple || providers[2].Name() != ProviderWeChat {
		t.Fatalf("unexpected providers: %s, %s, %s", providers[0].Name(), providers[1].Name(), providers[2].Name())
	}
}

func TestWeChatCodeProviderExchange(t *testing.T) {
	var tokenQuery url.Values
	var userInfoQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			tokenQuery = r.URL.Query()
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "wechat-access-token",
				"openid":       "wechat-openid",
				"unionid":      "wechat-unionid",
			})
		case "/userinfo":
			userInfoQuery = r.URL.Query()
			json.NewEncoder(w).Encode(map[string]any{
				"openid":     "wechat-openid",
				"unionid":    "wechat-unionid",
				"nickname":   "WeChat User",
				"headimgurl": "https://example.com/wechat.png",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	provider := newWeChatCodeProvider("wechat-app-id", "wechat-secret")
	provider.TokenURL = server.URL + "/token"
	provider.UserInfoURL = server.URL + "/userinfo"

	user, err := provider.Exchange(context.Background(), "wechat-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if user.ProviderUserID != "wechat-unionid" || user.Name != "WeChat User" || user.AvatarURL == "" {
		t.Fatalf("unexpected wechat user: %#v", user)
	}
	if tokenQuery.Get("appid") != "wechat-app-id" || tokenQuery.Get("secret") != "wechat-secret" || tokenQuery.Get("code") != "wechat-code" {
		t.Fatalf("unexpected token query: %s", tokenQuery.Encode())
	}
	if userInfoQuery.Get("access_token") != "wechat-access-token" || userInfoQuery.Get("openid") != "wechat-openid" {
		t.Fatalf("unexpected userinfo query: %s", userInfoQuery.Encode())
	}
}

func testJWKS(t *testing.T, kid string) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigEndian(privateKey.PublicKey.E)),
			}},
		})
	}))
	t.Cleanup(server.Close)
	return privateKey, server.URL
}

func signTestToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func bigEndian(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var out []byte
	for value > 0 {
		out = append([]byte{byte(value)}, out...)
		value >>= 8
	}
	return out
}
