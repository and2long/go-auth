package ginauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/and2long/go-auth/authkit"
	"github.com/gin-gonic/gin"
)

func registerEmail(kit *authkit.Kit) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email     string `json:"email"`
			Password  string `json:"password"`
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
		}
		if !bind(c, &req) {
			return
		}
		result, err := kit.RegisterWithEmail(c.Request.Context(), req.Email, req.Password, authkit.Profile{Name: req.Name, AvatarURL: req.AvatarURL})
		writeAuthResult(c, result, err)
	}
}

func loginEmail(kit *authkit.Kit) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !bind(c, &req) {
			return
		}
		result, err := kit.LoginWithEmail(c.Request.Context(), req.Email, req.Password)
		writeAuthResult(c, result, err)
	}
}

func loginPhone(kit *authkit.Kit) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Phone string `json:"phone"`
			Code  string `json:"code"`
		}
		if !bind(c, &req) {
			return
		}
		result, err := kit.LoginWithPhone(c.Request.Context(), req.Phone, req.Code)
		writeAuthResult(c, result, err)
	}
}

func loginOAuth(kit *authkit.Kit) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Code string `json:"code"`
		}
		if !bind(c, &req) {
			return
		}
		result, err := kit.LoginWithOAuth(c.Request.Context(), c.Param("provider"), req.Code)
		writeAuthResult(c, result, err)
	}
}

func refresh(kit *authkit.Kit) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if !bind(c, &req) {
			return
		}
		result, err := kit.Refresh(c.Request.Context(), req.RefreshToken)
		writeAuthResult(c, result, err)
	}
}

func logout(kit *authkit.Kit) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if !bind(c, &req) {
			return
		}
		if err := kit.Logout(c.Request.Context(), req.RefreshToken); err != nil {
			writeError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

func bind(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "bad_request", "message": "invalid json body"})
		return false
	}
	return true
}

func writeAuthResult(c *gin.Context, result authkit.AuthResult, err error) {
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user":          result.User,
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    result.ExpiresIn,
	})
}

func writeError(c *gin.Context, err error) {
	status, code := mapError(err)
	c.JSON(status, gin.H{"code": string(code), "message": strings.ReplaceAll(string(code), "_", " ")})
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
