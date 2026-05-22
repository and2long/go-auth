package ginauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/and2long/go-auth/authkit"
	gormrepo "github.com/and2long/go-auth/authkit/repository/gorm"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRegisterEmailUsesSnakeCaseUserFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterRoutes(router, newGinTestKit(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register/email", bytes.NewBufferString(`{"email":"user@example.com","password":"password123","name":"Demo User"}`))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register status = %d body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, key := range []string{"ID", "Email", "Phone", "Name", "AvatarURL", "CreatedAt", "UpdatedAt"} {
		if _, ok := resp.User[key]; ok {
			t.Fatalf("user response contains uppercase field %q: %s", key, rec.Body.String())
		}
	}
	for _, key := range []string{"id", "email", "phone", "name", "avatar_url", "created_at", "updated_at"} {
		if _, ok := resp.User[key]; !ok {
			t.Fatalf("user response missing snake_case field %q: %s", key, rec.Body.String())
		}
	}
}

func newGinTestKit(t *testing.T) *authkit.Kit {
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
	return kit
}
