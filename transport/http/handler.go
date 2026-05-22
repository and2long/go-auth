package httpauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/and2long/go-auth"
)

type Handler struct {
	Kit *authkit.Kit
}

func New(kit *authkit.Kit) *Handler {
	return &Handler{Kit: kit}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register/email", h.RegisterEmail)
	mux.HandleFunc("POST /auth/login/email", h.LoginEmail)
	mux.HandleFunc("POST /auth/login/phone", h.LoginPhone)
	mux.HandleFunc("POST /auth/login/oauth", h.LoginOAuth)
	mux.HandleFunc("POST /auth/refresh", h.Refresh)
	mux.HandleFunc("POST /auth/logout", h.Logout)
	mux.HandleFunc("GET /auth/me", h.Me)
	return mux
}

func (h *Handler) RegisterEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if !decode(w, r, &req) {
		return
	}
	result, err := h.Kit.RegisterWithEmail(r.Context(), req.Email, req.Password, authkit.Profile{Name: req.Name, AvatarURL: req.AvatarURL})
	writeAuthResult(w, result, err)
}

func (h *Handler) LoginEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	result, err := h.Kit.LoginWithEmail(r.Context(), req.Email, req.Password)
	writeAuthResult(w, result, err)
}

func (h *Handler) LoginPhone(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	result, err := h.Kit.LoginWithPhone(r.Context(), req.Phone, req.Code)
	writeAuthResult(w, result, err)
}

func (h *Handler) LoginOAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	result, err := h.Kit.LoginWithOAuth(r.Context(), req.Provider, req.Code)
	writeAuthResult(w, result, err)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &req) {
		return
	}
	result, err := h.Kit.Refresh(r.Context(), req.RefreshToken)
	writeAuthResult(w, result, err)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := h.Kit.Logout(r.Context(), req.RefreshToken); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user, err := h.Kit.CurrentUser(r.Context(), bearerToken(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userResponse(user)})
}

func AuthMiddleware(kit *authkit.Kit, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := kit.CurrentUser(r.Context(), bearerToken(r))
		if err != nil {
			writeError(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserFromContext(ctx context.Context) (authkit.User, bool) {
	user, ok := ctx.Value(userContextKey{}).(authkit.User)
	return user, ok
}

type userContextKey struct{}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "bad_request", Message: "invalid json body"})
		return false
	}
	return true
}

func writeAuthResult(w http.ResponseWriter, result authkit.AuthResult, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          userResponse(result.User),
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    result.ExpiresIn,
	})
}

func writeError(w http.ResponseWriter, err error) {
	status, code := mapError(err)
	writeJSON(w, status, errorResponse{Code: string(code), Message: codeMessage(code)})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func mapError(err error) (int, authkit.ErrorCode) {
	switch {
	case errors.Is(err, authkit.ErrInvalidCredentials):
		return http.StatusUnauthorized, authkit.CodeInvalidCredentials
	case errors.Is(err, authkit.ErrInvalidToken):
		return http.StatusUnauthorized, authkit.CodeInvalidToken
	case errors.Is(err, authkit.ErrExpiredToken):
		return http.StatusUnauthorized, authkit.CodeExpiredToken
	case errors.Is(err, authkit.ErrWeakPassword):
		return http.StatusBadRequest, authkit.CodeWeakPassword
	case errors.Is(err, authkit.ErrEmailExists):
		return http.StatusConflict, authkit.CodeEmailExists
	case errors.Is(err, authkit.ErrIdentityExists):
		return http.StatusConflict, authkit.CodeConflict
	case errors.Is(err, authkit.ErrConflict):
		return http.StatusConflict, authkit.CodeConflict
	case errors.Is(err, authkit.ErrVerificationFailed):
		return http.StatusUnauthorized, authkit.CodeVerificationFailed
	case errors.Is(err, authkit.ErrProviderNotFound):
		return http.StatusBadRequest, authkit.CodeProviderError
	case errors.Is(err, authkit.ErrNotFound):
		return http.StatusNotFound, authkit.CodeNotFound
	default:
		return http.StatusInternalServerError, authkit.CodeInternal
	}
}

func codeMessage(code authkit.ErrorCode) string {
	return strings.ReplaceAll(string(code), "_", " ")
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

func userResponse(user authkit.User) map[string]any {
	return map[string]any{
		"id":         user.ID,
		"email":      user.Email,
		"phone":      user.Phone,
		"name":       user.Name,
		"avatar_url": user.AvatarURL,
		"created_at": user.CreatedAt,
		"updated_at": user.UpdatedAt,
	}
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
