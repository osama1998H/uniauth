package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type EmailVerificationToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (s *Store) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) (*EmailVerificationToken, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3)
		 RETURNING id, user_id, token_hash, expires_at, used_at, created_at`,
		userID, tokenHash, expiresAt,
	)
	t := &EmailVerificationToken{}
	if err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan email verification token: %w", err)
	}
	return t, nil
}

func (s *Store) GetEmailVerificationToken(ctx context.Context, tokenHash string) (*EmailVerificationToken, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, used_at, created_at
		 FROM email_verification_tokens
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		tokenHash,
	)
	t := &EmailVerificationToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan email verification token: %w", err)
	}
	return t, nil
}

func (s *Store) MarkEmailVerificationTokenUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE email_verification_tokens SET used_at = now() WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteEmailVerificationToken(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM email_verification_tokens WHERE id = $1`, id)
	return err
}
