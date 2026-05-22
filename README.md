# AuthKit

AuthKit 是一个可复用的 Go 认证模块，适用于需要邮箱密码登录、可选手机号验证码登录、可选 OAuth 登录、JWT access token 和可撤销 refresh token 的项目。

它的目标是让常见的 GORM 集成尽量简单，同时保留自定义 token 管理器、短信验证码和 OAuth Provider 等扩展能力。

## 功能特性

- 不绑定具体 Web 框架的核心认证服务。
- 内置基于 GORM 的默认存储实现。
- 提供 `net/http` handler 和 Gin 路由注册。
- 默认使用 bcrypt 做密码哈希。
- 使用 JWT access token，并将 refresh token 哈希后存储，支持撤销。
- 支持接入自定义短信验证码校验和 OAuth Provider。
- 支持自定义表名或表名前缀，便于接入已有数据库。

## 安装

```sh
go get github.com/and2long/go-auth
```

按需引入包：

```go
import (
	"github.com/and2long/go-auth"
	gormrepo "github.com/and2long/go-auth/repository/gorm"
	ginauth "github.com/and2long/go-auth/transport/gin"
	httpauth "github.com/and2long/go-auth/transport/http"
)
```

## Gin + GORM 快速开始

```go
db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{TranslateError: true})
if err != nil {
	panic(err)
}

store := gormrepo.New(db)
if err := store.AutoMigrate(); err != nil {
	panic(err)
}

kit, err := authkit.NewWithStore(authkit.Config{
	SigningKey: []byte("replace-with-at-least-32-bytes-secret"),
}, store)
if err != nil {
	panic(err)
}

router := gin.Default()
ginauth.RegisterRoutes(router, kit)

api := router.Group("/api")
api.Use(ginauth.AuthMiddleware(kit))
api.GET("/profile", func(c *gin.Context) {
	user, _ := ginauth.User(c)
	c.JSON(http.StatusOK, gin.H{"user": user})
})

router.Run(":8080")
```

当用户、身份和 refresh token 都由同一个 store 提供时，推荐使用 `NewWithStore`。内置的 GORM store 已经支持这种集成方式。

## net/http 快速开始

```go
db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{TranslateError: true})
if err != nil {
	panic(err)
}

store := gormrepo.New(db)
if err := store.AutoMigrate(); err != nil {
	panic(err)
}

kit, err := authkit.NewWithStore(authkit.Config{
	SigningKey: []byte("replace-with-at-least-32-bytes-secret"),
}, store)
if err != nil {
	panic(err)
}

authHandler := httpauth.New(kit)
mux := http.NewServeMux()
mux.Handle("/auth/", authHandler.Routes())
mux.Handle("/api/profile", httpauth.AuthMiddleware(kit, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user, _ := httpauth.UserFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]any{"user": user})
})))

http.ListenAndServe(":8080", mux)
```

## 默认路由

Gin 和 `net/http` 集成默认暴露同一组路由：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/auth/register/email` | 使用邮箱和密码注册。 |
| `POST` | `/auth/login/email` | 使用邮箱和密码登录。 |
| `POST` | `/auth/login/phone` | 使用手机号和验证码登录。需要配置 `WithSMSVerifier`。 |
| `POST` | `/auth/login/oauth` | 使用 Google、Apple 或微信登录。需要配置 `WithOAuthProvidersFromEnv()`。 |
| `POST` | `/auth/refresh` | 轮换 refresh token，并签发新的 access token。 |
| `POST` | `/auth/logout` | 撤销 refresh token。 |
| `GET` | `/auth/me` | 根据 bearer access token 返回当前用户。 |

认证成功响应格式：

```json
{
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "phone": null,
    "name": "Demo User",
    "avatar_url": null
  },
  "access_token": "...",
  "refresh_token": "...",
  "expires_in": 900
}
```

错误响应格式：

```json
{
  "code": "invalid_credentials",
  "message": "invalid credentials"
}
```

## 请求示例

注册：

```sh
curl -s http://localhost:8080/auth/register/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password123","name":"Demo User"}'
```

登录：

```sh
curl -s http://localhost:8080/auth/login/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password123"}'
```

访问受保护接口：

```sh
curl -s http://localhost:8080/api/profile \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

刷新 token：

```sh
curl -s http://localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```

退出登录：

```sh
curl -s http://localhost:8080/auth/logout \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```

## 配置项

`authkit.Config` 除了 `SigningKey` 以外都有默认值。使用内置 JWT 管理器时，必须配置 `SigningKey`。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `Issuer` | `"authkit"` | JWT issuer。 |
| `SigningKey` | 无 | 内置 JWT 管理器的签名密钥，至少 32 字节。生产环境必须从安全的密钥配置中读取。 |
| `AccessTokenTTL` | `15 * time.Minute` | access token 有效期。 |
| `RefreshTokenTTL` | `30 * 24 * time.Hour` | refresh token 有效期。 |
| `PasswordMinLen` | `8` | 邮箱注册时的最短密码长度。 |
| `Now` | `time.Now` | 当前时间函数，主要用于测试。 |

短信验证码、内置 Google/Apple/微信登录等可选能力可以通过 option 配置，不需要额外的仓储配置：

```go
kit, err := authkit.NewWithStore(
	authkit.Config{SigningKey: []byte(os.Getenv("AUTHKIT_SIGNING_KEY"))},
	store,
	authkit.WithSMSVerifier(mySMSVerifier),
	authkit.WithOAuthProvidersFromEnv(),
)
```

## Google 登录示例

AuthKit 内置 Google ID Token 验证。前端通过 Google Identity Services 拿到 ID Token 后，把它放在默认 OAuth 登录接口的 `code` 字段里提交给后端。后端会验证 JWT 签名、issuer、audience 和过期时间，并映射 Google 的 `sub/email/name/picture`。

后端启用方式：

```go
kit, err := authkit.NewWithStore(
	authkit.Config{SigningKey: []byte(os.Getenv("AUTHKIT_SIGNING_KEY"))},
	store,
	authkit.WithOAuthProvidersFromEnv(),
)
```

客户端提交 Google ID Token：

```sh
curl -s http://localhost:8080/auth/login/oauth \
  -H 'Content-Type: application/json' \
  -d '{"provider":"google","code":"GOOGLE_ID_TOKEN"}'
```

后端需要配置 Google OAuth Client ID，用于校验 ID Token 的 `aud` 是否属于你的应用：

| 变量 | 是否必需 | 用途 |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | 是 | Google OAuth Client ID，用于验证 ID Token 的 audience。 |

## Apple 登录示例

AuthKit 也内置 Apple ID Token 验证。前端拿到 Apple 返回的 `identityToken` 后，把它放在默认 OAuth 登录接口的 `code` 字段里提交给后端。后端会从 Apple JWKS 地址获取公钥，并验证 JWT 签名、issuer、audience 和过期时间。

后端启用方式和 Google 相同：

```go
kit, err := authkit.NewWithStore(
	authkit.Config{SigningKey: []byte(os.Getenv("AUTHKIT_SIGNING_KEY"))},
	store,
	authkit.WithOAuthProvidersFromEnv(),
)
```

客户端提交 Apple ID Token：

```sh
curl -s http://localhost:8080/auth/login/oauth \
  -H 'Content-Type: application/json' \
  -d '{"provider":"apple","code":"APPLE_ID_TOKEN"}'
```

后端需要配置 Apple Client ID。对 iOS 原生应用通常是 Bundle ID；对网页或 Android 使用 Sign in with Apple 时通常是 Services ID，必须和 ID Token 的 `aud` 一致。

| 变量 | 是否必需 | 用途 |
| --- | --- | --- |
| `APPLE_CLIENT_ID` | 是 | Apple Client ID，用于验证 ID Token 的 audience。 |

## 微信登录示例

AuthKit 内置微信授权码登录。前端或客户端完成微信登录后拿到 `code`，把它提交给统一 OAuth 登录接口。后端会使用微信 AppID 和 AppSecret 换取 `access_token/openid`，并尽量拉取用户昵称和头像。

后端启用方式和 Google/Apple 相同：

```go
kit, err := authkit.NewWithStore(
	authkit.Config{SigningKey: []byte(os.Getenv("AUTHKIT_SIGNING_KEY"))},
	store,
	authkit.WithOAuthProvidersFromEnv(),
)
```

客户端提交微信 code：

```sh
curl -s http://localhost:8080/auth/login/oauth \
  -H 'Content-Type: application/json' \
  -d '{"provider":"wechat","code":"WECHAT_CODE"}'
```

后端需要配置微信应用参数：

| 变量 | 是否必需 | 用途 |
| --- | --- | --- |
| `WECHAT_APP_ID` | 是 | 微信开放平台或公众平台应用 AppID。 |
| `WECHAT_APP_SECRET` | 是 | 微信应用 AppSecret，用于后端换取 access token。 |

## 环境变量

AuthKit 库本身不会自动读取认证密钥、数据库路径等环境变量。你的应用应该自己读取这些密钥和运行时配置，然后传给 `authkit.Config` 或数据库初始化代码。Google/Apple/微信登录可以通过 `WithOAuthProvidersFromEnv()` 按环境变量自动启用。

典型生产应用至少需要配置：

| 变量 | 是否必需 | 用途 | 说明 |
| --- | --- | --- | --- |
| `AUTHKIT_SIGNING_KEY` | 是 | `authkit.Config.SigningKey` | JWT 签名密钥。使用内置 JWT 管理器时至少 32 字节。必须保密，并且服务重启前后要保持稳定。 |
| `GOOGLE_CLIENT_ID` | 否 | Google 登录 | 配置后，`WithOAuthProvidersFromEnv()` 会启用内置 Google ID Token 验证。 |
| `APPLE_CLIENT_ID` | 否 | Apple 登录 | 配置后，`WithOAuthProvidersFromEnv()` 会启用内置 Apple ID Token 验证。 |
| `WECHAT_APP_ID` | 否 | 微信登录 | 和 `WECHAT_APP_SECRET` 同时配置后，`WithOAuthProvidersFromEnv()` 会启用内置微信登录。 |
| `WECHAT_APP_SECRET` | 否 | 微信登录 | 和 `WECHAT_APP_ID` 同时配置后，后端会用它换取微信 access token。 |

推荐的生产环境写法：

```go
signingKey := os.Getenv("AUTHKIT_SIGNING_KEY")
if len(signingKey) < 32 {
	return errors.New("AUTHKIT_SIGNING_KEY must be at least 32 bytes")
}

kit, err := authkit.NewWithStore(authkit.Config{
	SigningKey: []byte(signingKey),
}, store)
```

生成开发用密钥：

```sh
openssl rand -base64 32
```

示例应用还会读取这些环境变量：

| 变量 | 是否必需 | 默认值 | 用途 |
| --- | --- | --- | --- |
| `ADDR` | 否 | `:8080` | HTTP 监听地址。 |
| `AUTHKIT_DB_PATH` | 否 | `authkit-example.db` | 示例应用使用的 SQLite 数据库路径。 |
| `AUTHKIT_SIGNING_KEY` | 示例中非必需，生产应用必需 | 仅用于开发的默认值 | JWT 签名密钥。 |

使用显式环境变量启动示例应用：

```sh
AUTHKIT_SIGNING_KEY="$(openssl rand -base64 32)" \
AUTHKIT_DB_PATH=/tmp/authkit-example.db \
ADDR=:8080 \
go run ./example
```

## GORM 表配置

默认表名：

- `users`
- `identities`
- `refresh_tokens`

添加统一前缀：

```go
store := gormrepo.New(db, gormrepo.WithTablePrefix("auth_"))
```

指定完整表名：

```go
store := gormrepo.New(db, gormrepo.WithTables(gormrepo.Tables{
	Users:         "app_users",
	Identities:    "app_user_identities",
	RefreshTokens: "app_refresh_tokens",
}))
```

创建 kit 之前先执行迁移：

```go
if err := store.AutoMigrate(); err != nil {
	return err
}
```

## 示例应用

运行最小 Gin 示例：

```sh
go run ./example
```

示例默认使用 SQLite。环境变量和 curl 命令见 `example/README.md`。
