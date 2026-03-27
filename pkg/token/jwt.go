// Package token provides JWT and API key utilities.
package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenPurpose identifies how a JWT is allowed to be used.
type TokenPurpose string

const (
	TokenPurposeAccess  TokenPurpose = "access"
	TokenPurposeRefresh TokenPurpose = "refresh"
)

// Claims represents the JWT payload.
type Claims struct {
	UserID  uuid.UUID    `json:"uid"`
	OrgID   uuid.UUID    `json:"oid"`
	TokenID uuid.UUID    `json:"jti"`          // unique per token (for blacklisting)
	Purpose TokenPurpose `json:"tp,omitempty"` // omitted in legacy untyped tokens
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
	return m.create(userID, orgID, m.accessDuration, TokenPurposeAccess)
}

// CreateRefreshToken issues a long-lived refresh token.
func (m *Maker) CreateRefreshToken(userID, orgID uuid.UUID) (string, *Claims, error) {
	return m.create(userID, orgID, m.refreshDuration, TokenPurposeRefresh)
}

func (m *Maker) create(userID, orgID uuid.UUID, duration time.Duration, purpose TokenPurpose) (string, *Claims, error) {
	now := time.Now()
	claims := &Claims{
		UserID:  userID,
		OrgID:   orgID,
		TokenID: uuid.New(),
		Purpose: purpose,
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

// VerifyAccessToken parses and validates a JWT that is intended for bearer auth.
func (m *Maker) VerifyAccessToken(tokenStr string) (*Claims, error) {
	return m.verifyPurpose(tokenStr, TokenPurposeAccess, false)
}

// VerifyRefreshToken parses and validates a JWT that is intended for refresh-only flows.
// When allowLegacyUntyped is true, tokens without a purpose claim are accepted so they can
// be rotated through the refresh endpoint into the typed format.
func (m *Maker) VerifyRefreshToken(tokenStr string, allowLegacyUntyped bool) (*Claims, error) {
	return m.verifyPurpose(tokenStr, TokenPurposeRefresh, allowLegacyUntyped)
}

func (m *Maker) verifyPurpose(tokenStr string, expected TokenPurpose, allowLegacyUntyped bool) (*Claims, error) {
	claims, err := m.verify(tokenStr)
	if err != nil {
		return nil, err
	}

	switch claims.Purpose {
	case expected:
		return claims, nil
	case "":
		if allowLegacyUntyped {
			return claims, nil
		}
		return nil, fmt.Errorf("token purpose missing")
	default:
		return nil, fmt.Errorf("unexpected token purpose: %s", claims.Purpose)
	}
}

// verify parses and validates a JWT, returning its claims without enforcing token purpose.
func (m *Maker) verify(tokenStr string) (*Claims, error) {
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
