package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osama1998h/uniauth/internal/config"
	"github.com/osama1998h/uniauth/internal/domain"
	"github.com/osama1998h/uniauth/internal/repository/cache"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/pkg/token"
)

// AuthService handles authentication logic.
type AuthService struct {
	store      *db.Store
	tokenMaker *token.Maker
	cache      *cache.Cache
	auditSvc   *AuditService
	webhookSvc *WebhookService
	emailSvc   *EmailService
	authCfg    config.AuthConfig
}

// NewAuthService creates an AuthService.
func NewAuthService(
	store *db.Store,
	tokenMaker *token.Maker,
	c *cache.Cache,
	auditSvc *AuditService,
	webhookSvc *WebhookService,
	emailSvc *EmailService,
	authCfg config.AuthConfig,
) *AuthService {
	return &AuthService{
		store:      store,
		tokenMaker: tokenMaker,
		cache:      c,
		auditSvc:   auditSvc,
		webhookSvc: webhookSvc,
		emailSvc:   emailSvc,
		authCfg:    authCfg,
	}
}

// RegisterInput holds the data required to register a new user.
type RegisterInput struct {
	OrgName  string
	Email    string
	Password string
	FullName *string
}

// RegisterOutput holds the result of a successful registration.
type RegisterOutput struct {
	Org  *domain.Organization
	User *domain.User
}

// Register creates a new organization and its first (superuser) user.
func (s *AuthService) Register(ctx context.Context, in RegisterInput, ipAddress, userAgent *string) (*RegisterOutput, error) {
	if err := validatePassword(in.Password); err != nil {
		return nil, err
	}

	slug := slugify(in.OrgName)
	if slug == "" {
		return nil, fmt.Errorf("%w: org_name must contain at least one alphanumeric character", domain.ErrInvalidInput)
	}

	// Check if org slug is taken
	if _, err := s.store.GetOrganizationBySlug(ctx, slug); err == nil {
		return nil, fmt.Errorf("%w: organization slug '%s' already taken", domain.ErrAlreadyExists, slug)
	}

	org, err := s.store.CreateOrganization(ctx, in.OrgName, slug)
	if err != nil {
		return nil, fmt.Errorf("create org: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.store.CreateUser(ctx, org.ID, in.Email, string(hashed), in.FullName, true)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.auditSvc.Log(&domain.AuditLog{
		OrgID:     &org.ID,
		UserID:    &user.ID,
		Action:    domain.AuditActionUserRegistered,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	})
	s.webhookSvc.Dispatch(org.ID, domain.AuditActionUserRegistered, map[string]any{"user_id": user.ID, "email": user.Email})

	return &RegisterOutput{Org: org, User: user}, nil
}

// LoginInput holds credentials for login.
type LoginInput struct {
	OrgSlug   string
	Email     string
	Password  string
	UserAgent *string
	IPAddress *string
}

// TokenPair holds an access and refresh token.
type TokenPair struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

// Login authenticates a user and returns a token pair + session.
func (s *AuthService) Login(ctx context.Context, in LoginInput) (*TokenPair, *domain.User, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, in.OrgSlug)
	if err != nil {
		return nil, nil, domain.ErrInvalidCredentials
	}
	if !org.IsActive {
		return nil, nil, domain.ErrOrgInactive
	}

	user, err := s.store.GetUserByEmail(ctx, org.ID, in.Email)
	if err != nil {
		s.auditSvc.Log(&domain.AuditLog{OrgID: &org.ID, Action: domain.AuditActionUserLoginFailed, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Metadata: map[string]any{"email": in.Email}})
		return nil, nil, domain.ErrInvalidCredentials
	}
	if !user.IsActive {
		return nil, nil, domain.ErrUserInactive
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(in.Password)); err != nil {
		s.auditSvc.Log(&domain.AuditLog{OrgID: &org.ID, UserID: &user.ID, Action: domain.AuditActionUserLoginFailed, IPAddress: in.IPAddress, UserAgent: in.UserAgent})
		return nil, nil, domain.ErrInvalidCredentials
	}

	pair, err := s.issueTokenPair(ctx, user, in.UserAgent, in.IPAddress)
	if err != nil {
		return nil, nil, err
	}

	_ = s.store.UpdateUserLastLogin(ctx, user.ID)

	s.auditSvc.Log(&domain.AuditLog{OrgID: &org.ID, UserID: &user.ID, Action: domain.AuditActionUserLogin, IPAddress: in.IPAddress, UserAgent: in.UserAgent})
	s.webhookSvc.Dispatch(org.ID, domain.AuditActionUserLogin, map[string]any{"user_id": user.ID})

	return pair, user, nil
}

// Refresh exchanges a valid refresh token for a new token pair.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string, userAgent, ipAddress *string) (*TokenPair, *domain.User, error) {
	claims, err := s.verifyRefreshToken(refreshToken)
	if err != nil {
		return nil, nil, domain.ErrTokenInvalid
	}

	tokenHash := hashString(refreshToken)
	sess, err := s.store.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, domain.ErrTokenInvalid
	}
	if !sess.IsValid() {
		return nil, nil, domain.ErrTokenExpired
	}
	if sess.UserID != claims.UserID {
		return nil, nil, domain.ErrTokenInvalid
	}

	user, err := s.store.GetUserByID(ctx, claims.OrgID, claims.UserID)
	if err != nil || !user.IsActive {
		return nil, nil, domain.ErrUnauthorized
	}
	if user.OrgID != claims.OrgID {
		return nil, nil, domain.ErrTokenInvalid
	}

	// Rotate: revoke old session, issue new pair
	if err := s.store.RevokeSession(ctx, sess.ID); err != nil {
		return nil, nil, fmt.Errorf("revoke session: %w", err)
	}

	pair, err := s.issueTokenPair(ctx, user, userAgent, ipAddress)
	if err != nil {
		return nil, nil, err
	}

	s.auditSvc.Log(&domain.AuditLog{OrgID: &user.OrgID, UserID: &user.ID, Action: domain.AuditActionTokenRefreshed, IPAddress: ipAddress, UserAgent: userAgent})
	return pair, user, nil
}

// Logout revokes the session associated with the given refresh token and
// blacklists the current access token so it is rejected on all instances.
func (s *AuthService) Logout(ctx context.Context, refreshToken string, accessTokenID uuid.UUID, accessTokenExpiresAt time.Time) error {
	claims, err := s.verifyRefreshToken(refreshToken)
	if err != nil {
		return domain.ErrTokenInvalid
	}

	tokenHash := hashString(refreshToken)
	sess, err := s.store.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.blacklistAccessToken(ctx, accessTokenID, accessTokenExpiresAt)
			return nil // already gone
		}
		return err
	}
	if sess.UserID != claims.UserID {
		return domain.ErrTokenInvalid
	}
	if !sess.IsValid() {
		s.blacklistAccessToken(ctx, accessTokenID, accessTokenExpiresAt)
		return nil
	}
	if err := s.store.RevokeSession(ctx, sess.ID); err != nil {
		return err
	}
	s.blacklistAccessToken(ctx, accessTokenID, accessTokenExpiresAt)
	return nil
}

// LogoutAll revokes all active sessions for a user and blacklists the current access token.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID, accessTokenID uuid.UUID, accessTokenExpiresAt time.Time) error {
	s.blacklistAccessToken(ctx, accessTokenID, accessTokenExpiresAt)
	return s.store.RevokeAllUserSessions(ctx, userID)
}

// RequestPasswordReset generates a reset token and emails it to the user.
func (s *AuthService) RequestPasswordReset(ctx context.Context, orgSlug, email string, ipAddress, userAgent *string) error {
	org, err := s.store.GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		return nil // don't reveal if org/email exists
	}

	user, err := s.store.GetUserByEmail(ctx, org.ID, email)
	if err != nil {
		return nil // silent fail for security
	}

	rawToken := uuid.New().String()
	tokenHash := hashString(rawToken)
	expiresAt := time.Now().Add(s.authCfg.ResetTokenDuration)

	resetRecord, err := s.store.CreatePasswordResetToken(ctx, user.ID, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("create reset token: %w", err)
	}

	if err := s.emailSvc.SendPasswordReset(email, rawToken); err != nil {
		if cleanupErr := s.store.DeletePasswordResetToken(ctx, resetRecord.ID); cleanupErr != nil {
			if s.emailSvc != nil && s.emailSvc.logger != nil {
				s.emailSvc.logger.Error("password reset token cleanup failed after email delivery failure", "error", cleanupErr)
			}
			return fmt.Errorf("cleanup reset token after email failure: %w", cleanupErr)
		}
		return nil
	}

	return nil
}

// ConfirmPasswordReset validates the token and updates the password.
func (s *AuthService) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	tokenHash := hashString(rawToken)
	prt, err := s.store.GetPasswordResetToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("get reset token: %w", err)
	}
	if prt == nil {
		return domain.ErrTokenInvalid
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.store.UpdateUserPassword(ctx, prt.UserID, string(hashed)); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if err := s.store.MarkPasswordResetTokenUsed(ctx, prt.ID); err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}
	if err := s.store.RevokeAllUserSessions(ctx, prt.UserID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}

	return nil
}

// ChangePassword updates a user's password after verifying the current one,
// then blacklists the current access token so it is rejected on all instances.
func (s *AuthService) ChangePassword(ctx context.Context, orgID, userID uuid.UUID, currentPassword, newPassword string, accessTokenID uuid.UUID, accessTokenExpiresAt time.Time) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	user, err := s.store.GetUserByID(ctx, orgID, userID)
	if err != nil {
		return domain.ErrNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(currentPassword)); err != nil {
		return domain.ErrInvalidCredentials
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.store.UpdateUserPassword(ctx, userID, string(hashed)); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Revoke all existing sessions so old tokens can't be reused
	_ = s.store.RevokeAllUserSessions(ctx, userID)
	s.blacklistAccessToken(ctx, accessTokenID, accessTokenExpiresAt)

	s.auditSvc.Log(&domain.AuditLog{OrgID: &user.OrgID, UserID: &userID, Action: domain.AuditActionPasswordChanged})
	return nil
}

// blacklistAccessToken stores the token JTI in Redis so that all instances
// reject it immediately. Best-effort: errors are silently ignored because the
// short access token TTL (default 15 min) is already a reasonable security bound.
func (s *AuthService) blacklistAccessToken(ctx context.Context, tokenID uuid.UUID, expiresAt time.Time) {
	ttl := time.Until(expiresAt)
	if ttl > 0 {
		_ = s.cache.BlacklistToken(ctx, tokenID.String(), ttl)
	}
}

// issueTokenPair creates access+refresh tokens and persists the session.
func (s *AuthService) issueTokenPair(ctx context.Context, user *domain.User, userAgent, ipAddress *string) (*TokenPair, error) {
	accessToken, accessClaims, err := s.tokenMaker.CreateAccessToken(user.ID, user.OrgID)
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	refreshToken, refreshClaims, err := s.tokenMaker.CreateRefreshToken(user.ID, user.OrgID)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	tokenHash := hashString(refreshToken)
	if _, err := s.store.CreateSession(ctx, user.ID, tokenHash, userAgent, ipAddress, refreshClaims.ExpiresAt.Time); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessClaims.ExpiresAt.Time,
		RefreshTokenExpiresAt: refreshClaims.ExpiresAt.Time,
	}, nil
}

func (s *AuthService) verifyRefreshToken(refreshToken string) (*token.Claims, error) {
	return s.tokenMaker.VerifyRefreshToken(refreshToken, true)
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func validatePassword(p string) error {
	if len(p) < 8 {
		return fmt.Errorf("%w: minimum 8 characters", domain.ErrWeakPassword)
	}
	var hasUpper, hasDigit, hasSpecial bool
	for _, c := range p {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsDigit(c):
			hasDigit = true
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return fmt.Errorf("%w: must contain at least one uppercase letter", domain.ErrWeakPassword)
	}
	if !hasDigit {
		return fmt.Errorf("%w: must contain at least one digit", domain.ErrWeakPassword)
	}
	if !hasSpecial {
		return fmt.Errorf("%w: must contain at least one special character", domain.ErrWeakPassword)
	}
	return nil
}

func slugify(name string) string {
	slug := ""
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z':
			slug += string(c)
		case c >= 'A' && c <= 'Z':
			slug += string(c + 32)
		case c >= '0' && c <= '9':
			slug += string(c)
		case c == ' ' || c == '-' || c == '_':
			if len(slug) > 0 && slug[len(slug)-1] != '-' {
				slug += "-"
			}
		}
	}
	// trim trailing dash
	for len(slug) > 0 && slug[len(slug)-1] == '-' {
		slug = slug[:len(slug)-1]
	}
	return slug
}
