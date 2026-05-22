package ginauth

import (
	"github.com/and2long/go-auth/authkit"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(router gin.IRouter, kit *authkit.Kit) {
	router.POST("/auth/register/email", registerEmail(kit))
	router.POST("/auth/login/email", loginEmail(kit))
	router.POST("/auth/login/phone", loginPhone(kit))
	router.POST("/auth/login/oauth", loginOAuth(kit))
	router.POST("/auth/refresh", refresh(kit))
	router.POST("/auth/logout", logout(kit))
	router.GET("/auth/me", AuthMiddleware(kit), me)
}
