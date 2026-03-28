package service

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/smtp"

	"github.com/osama1998h/uniauth/internal/config"
)

var errEmailDeliveryUnavailable = errors.New("email delivery unavailable")

// EmailService sends transactional emails via SMTP.
type EmailService struct {
	cfg           config.EmailConfig
	logger        *slog.Logger
	isDevelopment bool
	sendMail      func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// NewEmailService creates an EmailService.
func NewEmailService(cfg config.EmailConfig, logger *slog.Logger, isDevelopment bool) *EmailService {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &EmailService{
		cfg:           cfg,
		logger:        logger,
		isDevelopment: isDevelopment,
		sendMail:      smtp.SendMail,
	}
}

// SendPasswordReset emails a password reset link to the given address.
func (e *EmailService) SendPasswordReset(toEmail, resetToken string) error {
	if e.cfg.Host == "" {
		if e.isDevelopment {
			e.logger.Info("password reset email suppressed because SMTP is not configured")
		} else {
			e.logger.Warn("password reset email unavailable because SMTP is not configured")
		}
		return errEmailDeliveryUnavailable
	}

	link := fmt.Sprintf("%s/reset-password?token=%s", e.cfg.BaseURL, resetToken)
	body := fmt.Sprintf("Subject: Password Reset\r\n\r\nClick the link to reset your password:\r\n%s\r\n\r\nThis link expires in 1 hour.", link)

	auth := smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
	addr := fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port)
	if err := e.sendMail(addr, auth, e.cfg.From, []string{toEmail}, []byte(body)); err != nil {
		e.logger.Error("password reset email delivery failed", "error", err)
		return fmt.Errorf("%w: %v", errEmailDeliveryUnavailable, err)
	}

	return nil
}

// SendEmailVerification emails a verification link to the given address.
func (e *EmailService) SendEmailVerification(toEmail, verificationToken string) error {
	if e.cfg.Host == "" {
		if e.isDevelopment {
			e.logger.Info("email verification email suppressed because SMTP is not configured")
		} else {
			e.logger.Warn("email verification email unavailable because SMTP is not configured")
		}
		return errEmailDeliveryUnavailable
	}

	link := fmt.Sprintf("%s/verify-email?token=%s", e.cfg.BaseURL, verificationToken)
	body := fmt.Sprintf("Subject: Verify Your Email Address\r\n\r\nClick the link to verify your email address:\r\n%s\r\n\r\nThis link expires in 24 hours.", link)

	auth := smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
	addr := fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port)
	if err := e.sendMail(addr, auth, e.cfg.From, []string{toEmail}, []byte(body)); err != nil {
		e.logger.Error("email verification email delivery failed", "error", err)
		return fmt.Errorf("%w: %v", errEmailDeliveryUnavailable, err)
	}

	return nil
}
