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
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/internal/testutil"
)

func TestAuthServiceRequestPasswordResetCleansUpOnDeliveryFailure(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "auth-reset-failure-org")
	user := testutil.CreateUser(t, store, org.ID, "auth-reset-failure-user")

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
				authCfg:  config.AuthConfig{ResetTokenDuration: time.Hour},
			}

			if err := svc.RequestPasswordReset(ctx, org.Slug, user.Email, nil, nil); err != nil {
				t.Fatalf("RequestPasswordReset() unexpected error: %v", err)
			}

			if got := countPasswordResetTokensForUser(t, ctx, store, user.ID); got != 0 {
				t.Fatalf("expected no reset tokens after cleanup, got %d", got)
			}
		})
	}
}

func TestAuthServiceRequestPasswordResetSkipsUnknownAccounts(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "auth-reset-missing-org")
	user := testutil.CreateUser(t, store, org.ID, "auth-reset-missing-user")
	svc := &AuthService{
		store: store,
		emailSvc: NewEmailService(config.EmailConfig{
			BaseURL: "https://app.example.com",
		}, testutil.DiscardLogger(), false),
		authCfg: config.AuthConfig{ResetTokenDuration: time.Hour},
	}

	if err := svc.RequestPasswordReset(ctx, "missing-org", user.Email, nil, nil); err != nil {
		t.Fatalf("missing org should return nil, got %v", err)
	}
	if err := svc.RequestPasswordReset(ctx, org.Slug, "missing@example.com", nil, nil); err != nil {
		t.Fatalf("missing email should return nil, got %v", err)
	}

	if got := countPasswordResetTokensForUser(t, ctx, store, user.ID); got != 0 {
		t.Fatalf("expected no reset tokens for unknown account paths, got %d", got)
	}
}

func TestAuthServiceRequestPasswordResetPersistsTokenOnSuccessfulDelivery(t *testing.T) {
	store := testutil.RequireTestStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "auth-reset-success-org")
	user := testutil.CreateUser(t, store, org.ID, "auth-reset-success-user")
	svc := &AuthService{
		store: store,
		emailSvc: func() *EmailService {
			emailSvc := NewEmailService(config.EmailConfig{
				Host:    "smtp.example.com",
				Port:    587,
				From:    "noreply@example.com",
				BaseURL: "https://app.example.com",
			}, testutil.DiscardLogger(), false)
			emailSvc.sendMail = func(string, smtp.Auth, string, []string, []byte) error {
				return nil
			}
			return emailSvc
		}(),
		authCfg: config.AuthConfig{ResetTokenDuration: time.Hour},
	}

	var deliveredBody []byte
	svc.emailSvc.sendMail = func(_ string, _ smtp.Auth, _ string, _ []string, msg []byte) error {
		deliveredBody = append([]byte(nil), msg...)
		return nil
	}

	if err := svc.RequestPasswordReset(ctx, org.Slug, user.Email, nil, nil); err != nil {
		t.Fatalf("RequestPasswordReset() unexpected error: %v", err)
	}

	if got := countPasswordResetTokensForUser(t, ctx, store, user.ID); got != 1 {
		t.Fatalf("expected one reset token after successful delivery, got %d", got)
	}

	rawToken := extractResetToken(t, string(deliveredBody))
	tokenRecord, err := store.GetPasswordResetToken(ctx, hashString(rawToken))
	if err != nil {
		t.Fatalf("GetPasswordResetToken() error: %v", err)
	}
	if tokenRecord == nil {
		t.Fatal("expected active password reset token record")
	}
}

func countPasswordResetTokensForUser(t *testing.T, ctx context.Context, store *db.Store, userID uuid.UUID) int {
	t.Helper()

	var count int
	if err := store.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("count password reset tokens: %v", err)
	}
	return count
}

func extractResetToken(t *testing.T, body string) string {
	t.Helper()

	matches := regexp.MustCompile(`token=([0-9a-fA-F-]+)`).FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("reset token not found in email body: %q", body)
	}
	return matches[1]
}
