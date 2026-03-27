package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/internal/testutil"
	"github.com/osama1998h/uniauth/pkg/token"
)

const authRedisTestJWTSecret = "supersecretkey-at-least-32-chars!!"

type fakeBlacklistWriter struct {
	err error
}

func (f fakeBlacklistWriter) BlacklistToken(context.Context, string, time.Duration) error {
	return f.err
}

func TestAuthServiceLogoutBlacklistFailureDoesNotRevokeSession(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	svc := newRedisSensitiveAuthService(store, fakeBlacklistWriter{err: errors.New("redis unavailable")})
	user, _, refreshToken := createAuthRedisTestUserAndSession(t, ctx, store, svc.tokenMaker, "logout-blacklist-failure")
	accessTokenID, accessTokenExpiry := createAccessTokenMetadata(t, svc.tokenMaker, user.ID, user.OrgID)

	if err := svc.Logout(ctx, refreshToken, accessTokenID, accessTokenExpiry); !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Fatalf("expected ErrServiceUnavailable, got %v", err)
	}

	assertSessionActive(t, ctx, store, refreshToken)
}

func TestAuthServiceLogoutRevokesSessionWhenBlacklistSucceeds(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	svc := newRedisSensitiveAuthService(store, fakeBlacklistWriter{})
	user, _, refreshToken := createAuthRedisTestUserAndSession(t, ctx, store, svc.tokenMaker, "logout-success")
	accessTokenID, accessTokenExpiry := createAccessTokenMetadata(t, svc.tokenMaker, user.ID, user.OrgID)

	if err := svc.Logout(ctx, refreshToken, accessTokenID, accessTokenExpiry); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	assertSessionRevoked(t, ctx, store, refreshToken)
}

func TestAuthServiceLogoutAllBlacklistFailureDoesNotRevokeSessions(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	svc := newRedisSensitiveAuthService(store, fakeBlacklistWriter{err: errors.New("redis unavailable")})
	user, _, _ := createAuthRedisTestUserAndSession(t, ctx, store, svc.tokenMaker, "logout-all-blacklist-failure")
	_, _, secondRefreshToken := createAuthRedisTestUserAndSessionForExistingUser(t, ctx, store, svc.tokenMaker, user, "logout-all-blacklist-failure-second")
	accessTokenID, accessTokenExpiry := createAccessTokenMetadata(t, svc.tokenMaker, user.ID, user.OrgID)

	if err := svc.LogoutAll(ctx, user.ID, accessTokenID, accessTokenExpiry); !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Fatalf("expected ErrServiceUnavailable, got %v", err)
	}

	assertSessionCount(t, ctx, store, user.ID, 2)
	assertSessionActive(t, ctx, store, secondRefreshToken)
}

func TestAuthServiceLogoutAllRevokesSessionsWhenBlacklistSucceeds(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	svc := newRedisSensitiveAuthService(store, fakeBlacklistWriter{})
	user, _, firstRefreshToken := createAuthRedisTestUserAndSession(t, ctx, store, svc.tokenMaker, "logout-all-success")
	_, _, secondRefreshToken := createAuthRedisTestUserAndSessionForExistingUser(t, ctx, store, svc.tokenMaker, user, "logout-all-success-second")
	accessTokenID, accessTokenExpiry := createAccessTokenMetadata(t, svc.tokenMaker, user.ID, user.OrgID)

	if err := svc.LogoutAll(ctx, user.ID, accessTokenID, accessTokenExpiry); err != nil {
		t.Fatalf("LogoutAll() error = %v", err)
	}

	assertSessionRevoked(t, ctx, store, firstRefreshToken)
	assertSessionRevoked(t, ctx, store, secondRefreshToken)
}

func TestAuthServiceChangePasswordBlacklistFailureDoesNotMutateState(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	svc := newRedisSensitiveAuthService(store, fakeBlacklistWriter{err: errors.New("redis unavailable")})
	user, currentPassword, refreshToken := createAuthRedisTestUserAndSession(t, ctx, store, svc.tokenMaker, "change-password-blacklist-failure")
	accessTokenID, accessTokenExpiry := createAccessTokenMetadata(t, svc.tokenMaker, user.ID, user.OrgID)

	if err := svc.ChangePassword(ctx, user.OrgID, user.ID, currentPassword, "N3wPassword!2", accessTokenID, accessTokenExpiry); !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Fatalf("expected ErrServiceUnavailable, got %v", err)
	}

	reloadedUser, err := store.GetUserByID(ctx, user.OrgID, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(reloadedUser.HashedPassword), []byte(currentPassword)); err != nil {
		t.Fatalf("expected original password hash to remain valid, got %v", err)
	}
	assertSessionActive(t, ctx, store, refreshToken)
}

func TestAuthServiceChangePasswordMutatesStateWhenBlacklistSucceeds(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	svc := newRedisSensitiveAuthService(store, fakeBlacklistWriter{})
	user, currentPassword, refreshToken := createAuthRedisTestUserAndSession(t, ctx, store, svc.tokenMaker, "change-password-success")
	accessTokenID, accessTokenExpiry := createAccessTokenMetadata(t, svc.tokenMaker, user.ID, user.OrgID)
	newPassword := "N3wPassword!2"

	if err := svc.ChangePassword(ctx, user.OrgID, user.ID, currentPassword, newPassword, accessTokenID, accessTokenExpiry); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	reloadedUser, err := store.GetUserByID(ctx, user.OrgID, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(reloadedUser.HashedPassword), []byte(newPassword)); err != nil {
		t.Fatalf("expected new password hash to be stored, got %v", err)
	}
	assertSessionRevoked(t, ctx, store, refreshToken)
}

func newRedisSensitiveAuthService(store *db.Store, blacklistWriter accessTokenBlacklistWriter) *AuthService {
	return &AuthService{
		store:      store,
		tokenMaker: token.NewMaker(authRedisTestJWTSecret, 15*time.Minute, 7*24*time.Hour),
		cache:      blacklistWriter,
		auditSvc:   NewAuditService(store, testutil.DiscardLogger()),
	}
}

func createAuthRedisTestUserAndSession(t *testing.T, ctx context.Context, store *db.Store, maker *token.Maker, prefix string) (*domain.User, string, string) {
	t.Helper()

	org := testutil.CreateOrganization(t, store, prefix+"-org")
	return createAuthRedisTestUserAndSessionInOrg(t, ctx, store, maker, org.ID, prefix)
}

func createAuthRedisTestUserAndSessionForExistingUser(t *testing.T, ctx context.Context, store *db.Store, maker *token.Maker, user *domain.User, prefix string) (*domain.User, string, string) {
	t.Helper()
	return createSessionForExistingUser(t, ctx, store, maker, user)
}

func createAuthRedisTestUserAndSessionInOrg(t *testing.T, ctx context.Context, store *db.Store, maker *token.Maker, orgID uuid.UUID, prefix string) (*domain.User, string, string) {
	t.Helper()

	currentPassword := "Curr3ntPass!"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}

	email := prefix + "-" + uuid.NewString() + "@example.com"
	user, err := store.CreateUser(ctx, orgID, email, string(hashedPassword), nil, false)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	_, _, refreshToken := createSessionForExistingUser(t, ctx, store, maker, user)
	return user, currentPassword, refreshToken
}

func createSessionForExistingUser(t *testing.T, ctx context.Context, store *db.Store, maker *token.Maker, user *domain.User) (*domain.User, string, string) {
	t.Helper()

	refreshToken, refreshClaims, err := maker.CreateRefreshToken(user.ID, user.OrgID)
	if err != nil {
		t.Fatalf("CreateRefreshToken() error = %v", err)
	}
	if _, err := store.CreateSession(ctx, user.ID, hashString(refreshToken), nil, nil, refreshClaims.ExpiresAt.Time); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	return user, "", refreshToken
}

func createAccessTokenMetadata(t *testing.T, maker *token.Maker, userID, orgID uuid.UUID) (uuid.UUID, time.Time) {
	t.Helper()

	_, claims, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}
	return claims.TokenID, claims.ExpiresAt.Time
}

func assertSessionActive(t *testing.T, ctx context.Context, store *db.Store, refreshToken string) {
	t.Helper()

	sess, err := store.GetSessionByTokenHash(ctx, hashString(refreshToken))
	if err != nil {
		t.Fatalf("GetSessionByTokenHash() error = %v", err)
	}
	if sess.RevokedAt != nil {
		t.Fatalf("expected session %s to remain active", sess.ID)
	}
}

func assertSessionRevoked(t *testing.T, ctx context.Context, store *db.Store, refreshToken string) {
	t.Helper()

	sess, err := store.GetSessionByTokenHash(ctx, hashString(refreshToken))
	if err != nil {
		t.Fatalf("GetSessionByTokenHash() error = %v", err)
	}
	if sess.RevokedAt == nil {
		t.Fatalf("expected session %s to be revoked", sess.ID)
	}
}

func assertSessionCount(t *testing.T, ctx context.Context, store *db.Store, userID uuid.UUID, want int) {
	t.Helper()

	sessions, err := store.ListSessionsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListSessionsByUser() error = %v", err)
	}
	if len(sessions) != want {
		t.Fatalf("session count = %d, want %d", len(sessions), want)
	}
}
