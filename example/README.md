# AuthKit Gin 示例

这个示例展示最小的 Gin + GORM 集成方式：

- 使用 SQLite 存储。
- 通过 `store.AutoMigrate()` 创建 AuthKit 表。
- 通过 `authkit.NewWithStore(...)` 使用默认依赖。
- 通过 `ginauth.RegisterRoutes(...)` 注册认证接口。
- 通过 `ginauth.AuthMiddleware(...)` 保护业务接口。

## 运行

```sh
go run ./example
```

服务默认监听 `:8080`。

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADDR` | `:8080` | HTTP 监听地址。 |
| `AUTHKIT_DB_PATH` | `authkit-example.db` | SQLite 数据库路径。 |
| `AUTHKIT_SIGNING_KEY` | 仅用于开发的默认值 | JWT 签名密钥。真实应用中请使用至少 32 字节的安全密钥。 |

示例：

```sh
AUTHKIT_SIGNING_KEY="$(openssl rand -base64 32)" \
AUTHKIT_DB_PATH=/tmp/authkit-example.db \
ADDR=:8081 \
go run ./example
```

## 测试

注册：

```sh
curl -s http://localhost:8080/auth/register/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password123","name":"Demo User"}'
```

登录并保存 token：

```sh
LOGIN_RESPONSE=$(curl -s http://localhost:8080/auth/login/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password123"}')

ACCESS_TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | jq -r .access_token)
REFRESH_TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | jq -r .refresh_token)
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
