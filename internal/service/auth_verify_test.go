package service

import (
	"context"
	"errors"
	"net/smtp"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/config"
	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/internal/testutil"
)

func TestAuthServiceRequestEmailVerificationCleansUpOnDeliveryFailure(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "email-verify-failure-org")
	user := testutil.CreateUser(t, store, org.ID, "email-verify-failure-user")

	tests := []struct {
		name     string
		emailSvc *EmailService
	}{
		{
			name: "smtp not configured",
			emailSvc: NewEmailService(config.EmailConfig{
				BaseURL: "https://app.example.com",
			}, testutil.DiscardLogger(), false),
		},
		{
			name: "smtp send failure",
			emailSvc: func() *EmailService {
				svc := NewEmailService(config.EmailConfig{
					Host:    "smtp.example.com",
					Port:    587,
					From:    "noreply@example.com",
					BaseURL: "https://app.example.com",
				}, testutil.DiscardLogger(), false)
				svc.sendMail = func(string, smtp.Auth, string, []string, []byte) error {
					return errors.New("smtp unavailable")
				}
				return svc
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &AuthService{
				store:    store,
				emailSvc: tc.emailSvc,
				authCfg:  config.AuthConfig{VerifyEmailTokenDuration: 24 * time.Hour},
			}

			err := svc.requestEmailVerificationInternal(ctx, user.ID, user.Email)
			if err == nil {
				t.Fatal("expected error from email delivery failure")
			}

			if got := countEmailVerificationTokensForUser(t, ctx, store, user.ID); got != 0 {
				t.Fatalf("expected no verification tokens after cleanup, got %d", got)
			}
		})
	}
}

func TestAuthServiceRequestEmailVerificationSkipsAlreadyVerified(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "email-verify-already-org")
	user := testutil.CreateUser(t, store, org.ID, "email-verify-already-user")

	// Mark user as verified
	if err := store.VerifyUserEmail(ctx, user.ID); err != nil {
		t.Fatalf("VerifyUserEmail() error: %v", err)
	}

	svc := &AuthService{
		store:      store,
		auditSvc:   NewAuditService(store, testutil.DiscardLogger()),
		webhookSvc: NewWebhookService(store, testutil.DiscardLogger()),
		emailSvc: NewEmailService(config.EmailConfig{
			BaseURL: "https://app.example.com",
		}, testutil.DiscardLogger(), false),
		authCfg: config.AuthConfig{VerifyEmailTokenDuration: 24 * time.Hour},
	}

	err := svc.RequestEmailVerification(ctx, user.ID, org.ID)
	if !errors.Is(err, domain.ErrEmailAlreadyVerified) {
		t.Fatalf("expected ErrEmailAlreadyVerified, got %v", err)
	}
}

func TestAuthServiceRequestEmailVerificationPersistsTokenOnSuccess(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "email-verify-success-org")
	user := testutil.CreateUser(t, store, org.ID, "email-verify-success-user")

	emailSvc := NewEmailService(config.EmailConfig{
		Host:    "smtp.example.com",
		Port:    587,
		From:    "noreply@example.com",
		BaseURL: "https://app.example.com",
	}, testutil.DiscardLogger(), false)

	var deliveredBody []byte
	emailSvc.sendMail = func(_ string, _ smtp.Auth, _ string, _ []string, msg []byte) error {
		deliveredBody = append([]byte(nil), msg...)
		return nil
	}

	svc := &AuthService{
		store:      store,
		auditSvc:   NewAuditService(store, testutil.DiscardLogger()),
		webhookSvc: NewWebhookService(store, testutil.DiscardLogger()),
		emailSvc:   emailSvc,
		authCfg:    config.AuthConfig{VerifyEmailTokenDuration: 24 * time.Hour},
	}

	if err := svc.RequestEmailVerification(ctx, user.ID, org.ID); err != nil {
		t.Fatalf("RequestEmailVerification() unexpected error: %v", err)
	}

	if got := countEmailVerificationTokensForUser(t, ctx, store, user.ID); got != 1 {
		t.Fatalf("expected one verification token after successful delivery, got %d", got)
	}

	rawToken := extractVerificationToken(t, string(deliveredBody))
	tokenRecord, err := store.GetEmailVerificationToken(ctx, hashString(rawToken))
	if err != nil {
		t.Fatalf("GetEmailVerificationToken() error: %v", err)
	}
	if tokenRecord == nil {
		t.Fatal("expected active email verification token record")
	}
}

func TestAuthServiceConfirmEmailVerification(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "email-verify-confirm-org")
	user := testutil.CreateUser(t, store, org.ID, "email-verify-confirm-user")

	// Create a verification token directly
	rawToken := uuid.New().String()
	tokenHash := hashString(rawToken)
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err := store.CreateEmailVerificationToken(ctx, user.ID, tokenHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken() error: %v", err)
	}

	svc := &AuthService{
		store:      store,
		auditSvc:   NewAuditService(store, testutil.DiscardLogger()),
		webhookSvc: NewWebhookService(store, testutil.DiscardLogger()),
		authCfg:    config.AuthConfig{VerifyEmailTokenDuration: 24 * time.Hour},
	}

	if err := svc.ConfirmEmailVerification(ctx, rawToken); err != nil {
		t.Fatalf("ConfirmEmailVerification() unexpected error: %v", err)
	}

	// Verify user's email_verified_at is set
	updatedUser, err := store.GetUserByID(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}
	if updatedUser.EmailVerifiedAt == nil {
		t.Fatal("expected email_verified_at to be set after confirmation")
	}

	// Verify token is marked as used (second use should fail)
	tokenRecord, err := store.GetEmailVerificationToken(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetEmailVerificationToken() error: %v", err)
	}
	if tokenRecord != nil {
		t.Fatal("expected token to be consumed (not returned by query)")
	}
}

func TestAuthServiceConfirmEmailVerificationInvalidToken(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	svc := &AuthService{
		store:      store,
		auditSvc:   NewAuditService(store, testutil.DiscardLogger()),
		webhookSvc: NewWebhookService(store, testutil.DiscardLogger()),
		authCfg:    config.AuthConfig{VerifyEmailTokenDuration: 24 * time.Hour},
	}

	err := svc.ConfirmEmailVerification(ctx, "garbage-token-value")
	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func countEmailVerificationTokensForUser(t *testing.T, ctx context.Context, store *db.Store, userID uuid.UUID) int {
	t.Helper()

	var count int
	if err := store.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("count email verification tokens: %v", err)
	}
	return count
}

func extractVerificationToken(t *testing.T, body string) string {
	t.Helper()

	matches := regexp.MustCompile(`token=([0-9a-fA-F-]+)`).FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("verification token not found in email body: %q", body)
	}
	return matches[1]
}
