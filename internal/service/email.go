package service

import (
	"fmt"
	"net/smtp"

	"github.com/osama1998h/uniauth/internal/config"
)

// EmailService sends transactional emails via SMTP.
type EmailService struct {
	cfg config.EmailConfig
}

// NewEmailService creates an EmailService.
func NewEmailService(cfg config.EmailConfig) *EmailService {
	return &EmailService{cfg: cfg}
}

// SendPasswordReset emails a password reset link to the given address.
func (e *EmailService) SendPasswordReset(toEmail, resetToken string) error {
	if e.cfg.Host == "" {
		// SMTP not configured — log and skip (dev mode)
		fmt.Printf("[email] password reset for %s — token: %s\n", toEmail, resetToken)
		return nil
	}
	link := fmt.Sprintf("%s/reset-password?token=%s", e.cfg.BaseURL, resetToken)
	body := fmt.Sprintf("Subject: Password Reset\r\n\r\nClick the link to reset your password:\r\n%s\r\n\r\nThis link expires in 1 hour.", link)

	auth := smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
	addr := fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port)
	return smtp.SendMail(addr, auth, e.cfg.From, []string{toEmail}, []byte(body))
}
