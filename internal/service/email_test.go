package service

import (
	"bytes"
	"errors"
	"log/slog"
	"net/smtp"
	"strings"
	"testing"

	"github.com/osama1998h/uniauth/internal/config"
)

func TestEmailServiceSendPasswordReset(t *testing.T) {
	const resetToken = "11111111-2222-3333-4444-555555555555"
	const resetLink = "https://app.example.com/reset-password?token=" + resetToken

	t.Run("no smtp in production returns error without logging token", func(t *testing.T) {
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		svc := NewEmailService(config.EmailConfig{
			BaseURL: "https://app.example.com",
		}, logger, false)

		err := svc.SendPasswordReset("alice@example.com", resetToken)
		if !errors.Is(err, errEmailDeliveryUnavailable) {
			t.Fatalf("expected errEmailDeliveryUnavailable, got %v", err)
		}

		output := logs.String()
		if !strings.Contains(output, "SMTP is not configured") {
			t.Fatalf("expected SMTP configuration log, got %q", output)
		}
		if strings.Contains(output, resetToken) {
			t.Fatalf("log output leaked reset token: %q", output)
		}
		if strings.Contains(output, resetLink) {
			t.Fatalf("log output leaked reset link: %q", output)
		}
	})

	t.Run("no smtp in development logs safe informational message only", func(t *testing.T) {
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		svc := NewEmailService(config.EmailConfig{
			BaseURL: "https://app.example.com",
		}, logger, true)

		err := svc.SendPasswordReset("alice@example.com", resetToken)
		if !errors.Is(err, errEmailDeliveryUnavailable) {
			t.Fatalf("expected errEmailDeliveryUnavailable, got %v", err)
		}

		output := logs.String()
		if !strings.Contains(output, "password reset email suppressed because SMTP is not configured") {
			t.Fatalf("expected development suppression log, got %q", output)
		}
		if strings.Contains(output, resetToken) {
			t.Fatalf("log output leaked reset token: %q", output)
		}
		if strings.Contains(output, resetLink) {
			t.Fatalf("log output leaked reset link: %q", output)
		}
	})

	t.Run("smtp send failure logs sanitized error", func(t *testing.T) {
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		svc := NewEmailService(config.EmailConfig{
			Host:    "smtp.example.com",
			Port:    587,
			From:    "noreply@example.com",
			BaseURL: "https://app.example.com",
		}, logger, false)
		svc.sendMail = func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
			if addr != "smtp.example.com:587" {
				t.Fatalf("unexpected SMTP address: %s", addr)
			}
			if from != "noreply@example.com" {
				t.Fatalf("unexpected from address: %s", from)
			}
			if len(to) != 1 || to[0] != "alice@example.com" {
				t.Fatalf("unexpected recipients: %#v", to)
			}
			if !bytes.Contains(msg, []byte(resetToken)) {
				t.Fatalf("expected email body to contain reset token")
			}
			return errors.New("dial tcp: connection refused")
		}

		err := svc.SendPasswordReset("alice@example.com", resetToken)
		if !errors.Is(err, errEmailDeliveryUnavailable) {
			t.Fatalf("expected errEmailDeliveryUnavailable, got %v", err)
		}

		output := logs.String()
		if !strings.Contains(output, "password reset email delivery failed") {
			t.Fatalf("expected delivery failure log, got %q", output)
		}
		if strings.Contains(output, resetToken) {
			t.Fatalf("log output leaked reset token: %q", output)
		}
		if strings.Contains(output, resetLink) {
			t.Fatalf("log output leaked reset link: %q", output)
		}
	})
}
