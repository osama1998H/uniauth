// Package token provides JWT and API key utilities.
package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT payload.
type Claims struct {
	UserID  uuid.UUID `json:"uid"`
	OrgID   uuid.UUID `json:"oid"`
	TokenID uuid.UUID `json:"jti"` // unique per token (for blacklisting)
	jwt.RegisteredClaims
}

// Maker handles JWT creation and validation.
type Maker struct {
	secret          []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
}

// NewMaker creates a new JWT Maker.
func NewMaker(secret string, accessDuration, refreshDuration time.Duration) *Maker {
	return &Maker{
		secret:          []byte(secret),
		accessDuration:  accessDuration,
		refreshDuration: refreshDuration,
	}
}

// CreateAccessToken issues a short-lived access token.
func (m *Maker) CreateAccessToken(userID, orgID uuid.UUID) (string, *Claims, error) {
	return m.create(userID, orgID, m.accessDuration)
}

// CreateRefreshToken issues a long-lived refresh token.
func (m *Maker) CreateRefreshToken(userID, orgID uuid.UUID) (string, *Claims, error) {
	return m.create(userID, orgID, m.refreshDuration)
}

func (m *Maker) create(userID, orgID uuid.UUID, duration time.Duration) (string, *Claims, error) {
	now := time.Now()
	claims := &Claims{
		UserID:  userID,
		OrgID:   orgID,
		TokenID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", nil, fmt.Errorf("sign token: %w", err)
	}
	return signed, claims, nil
}

// Verify parses and validates a JWT, returning its claims.
func (m *Maker) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}
