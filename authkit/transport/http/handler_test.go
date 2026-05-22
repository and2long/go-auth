package httpauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/and2long/go-auth/authkit"
	gormrepo "github.com/and2long/go-auth/authkit/repository/gorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRoutesRegisterAndMe(t *testing.T) {
	kit := newHTTPTestKit(t)
	server := New(kit).Routes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register/email", bytes.NewBufferString(`{"email":"user@example.com","password":"password123"}`))
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register status = %d body = %s", rec.Code, rec.Body.String())
	}
	var authResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &authResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if authResp.AccessToken == "" {
		t.Fatal("missing access token")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+authResp.AccessToken)
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestPhoneVerificationFailureUsesVerificationCode(t *testing.T) {
	kit := newHTTPTestKit(t)
	server := New(kit).Routes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login/phone", bytes.NewBufferString(`{"phone":"+15555550100","code":"000000"}`))
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("phone login status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != string(authkit.CodeVerificationFailed) {
		t.Fatalf("code = %q want %q", resp.Code, authkit.CodeVerificationFailed)
	}
}

func TestDuplicateRegisterUsesEmailExistsCode(t *testing.T) {
	kit := newHTTPTestKit(t)
	server := New(kit).Routes()

	reqBody := `{"email":"user@example.com","password":"password123"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register/email", bytes.NewBufferString(reqBody))
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first register status = %d body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/auth/register/email", bytes.NewBufferString(reqBody))
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second register status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != string(authkit.CodeEmailExists) {
		t.Fatalf("code = %q want %q", resp.Code, authkit.CodeEmailExists)
	}
}

func newHTTPTestKit(t *testing.T) *authkit.Kit {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	store := gormrepo.New(db)
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	kit, err := authkit.NewWithStore(authkit.Config{
		Issuer:          "test",
		SigningKey:      []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
	}, store)
	if err != nil {
		t.Fatalf("new kit: %v", err)
	}
	_ = context.Background()
	return kit
}
