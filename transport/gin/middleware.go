package ginauth

import (
	"net/http"
	"strings"

	"github.com/and2long/go-auth"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(kit *authkit.Kit) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := kit.CurrentUser(c.Request.Context(), bearerToken(c.GetHeader("Authorization")))
		if err != nil {
			writeError(c, err)
			c.Abort()
			return
		}
		c.Set("authkit.user", user)
		c.Next()
	}
}

func User(c *gin.Context) (authkit.User, bool) {
	value, ok := c.Get("authkit.user")
	if !ok {
		return authkit.User{}, false
	}
	user, ok := value.(authkit.User)
	return user, ok
}

func me(c *gin.Context) {
	user, _ := User(c)
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func bearerToken(header string) string {
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}
