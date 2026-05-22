package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type BcryptHasher struct {
	Cost int
}

func (h BcryptHasher) Hash(password string) (string, error) {
	cost := h.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(b), err
}

func (h BcryptHasher) Compare(hash, password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

type JWTManager struct {
	issuer string
	key    []byte
	ttl    time.Duration
	now    func() time.Time
}

func NewJWTManager(cfg Config) *JWTManager {
	cfg = cfg.withDefaults()
	return &JWTManager{
		issuer: cfg.Issuer,
		key:    cfg.SigningKey,
		ttl:    cfg.AccessTokenTTL,
		now:    cfg.Now,
	}
}

func (m *JWTManager) validate() error {
	if m == nil {
		return errors.New("authkit: jwt manager is nil")
	}
	if len(m.key) < 32 {
		return errors.New("authkit: signing key must be at least 32 bytes")
	}
	if m.ttl <= 0 {
		return errors.New("authkit: access token ttl must be positive")
	}
	if m.now == nil {
		return errors.New("authkit: clock is required")
	}
	return nil
}

func (m *JWTManager) Issue(user User) (string, int64, error) {
	if err := m.validate(); err != nil {
		return "", 0, err
	}
	now := m.now().UTC()
	expiresAt := now.Add(m.ttl)
	claims := jwt.MapClaims{
		"iss": m.issuer,
		"sub": user.ID,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
	}
	if user.Email != nil {
		claims["email"] = *user.Email
	}
	if user.Phone != nil {
		claims["phone"] = *user.Phone
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.key)
	if err != nil {
		return "", 0, err
	}
	return signed, int64(m.ttl.Seconds()), nil
}

func (m *JWTManager) Parse(accessToken string) (Claims, error) {
	if err := m.validate(); err != nil {
		return Claims{}, err
	}
	parsed, err := jwt.Parse(accessToken, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}
		return m.key, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithExpirationRequired())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Claims{}, ErrExpiredToken
		}
		return Claims{}, ErrInvalidToken
	}
	if !parsed.Valid {
		return Claims{}, ErrInvalidToken
	}
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, ErrInvalidToken
	}
	userID, _ := mapClaims.GetSubject()
	if userID == "" {
		return Claims{}, ErrInvalidToken
	}
	email, _ := mapClaims["email"].(string)
	phone, _ := mapClaims["phone"].(string)
	return Claims{UserID: userID, Email: email, Phone: phone}, nil
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func newSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
