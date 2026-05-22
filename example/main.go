package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/and2long/go-auth"
	gormrepo "github.com/and2long/go-auth/repository/gorm"
	ginauth "github.com/and2long/go-auth/transport/gin"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	kit := mustAuthKit()

	router := gin.Default()
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	ginauth.RegisterRoutes(router, kit)

	protected := router.Group("/api")
	protected.Use(ginauth.AuthMiddleware(kit))
	protected.GET("/profile", func(c *gin.Context) {
		user, _ := ginauth.User(c)
		c.JSON(http.StatusOK, gin.H{"user": user})
	})

	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}
	log.Printf("authkit gin example listening on %s", addr)
	log.Fatal(router.Run(addr))
}

func mustAuthKit() *authkit.Kit {
	dbPath := os.Getenv("AUTHKIT_DB_PATH")
	if dbPath == "" {
		dbPath = "authkit-example.db"
	}
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{TranslateError: true})
	if err != nil {
		log.Fatalf("open sqlite database: %v", err)
	}

	store := gormrepo.New(db)
	if err := store.AutoMigrate(); err != nil {
		log.Fatalf("migrate authkit tables: %v", err)
	}

	signingKey := os.Getenv("AUTHKIT_SIGNING_KEY")
	if signingKey == "" {
		signingKey = "dev-only-authkit-signing-key-32bytes"
	}

	kit, err := authkit.NewWithStore(authkit.Config{
		Issuer:          "authkit-example",
		SigningKey:      []byte(signingKey),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}, store)
	if err != nil {
		log.Fatalf("create authkit: %v", err)
	}
	return kit
}
