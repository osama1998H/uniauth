package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type PasswordResetToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (s *Store) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3)
		 RETURNING id, user_id, token_hash, expires_at, used_at, created_at`,
		userID, tokenHash, expiresAt,
	)
	t := &PasswordResetToken{}
	if err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan password reset token: %w", err)
	}
	return t, nil
}

func (s *Store) GetPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, token_hash, expires_at, used_at, created_at
		 FROM password_reset_tokens
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		tokenHash,
	)
	t := &PasswordResetToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan password reset token: %w", err)
	}
	return t, nil
}

func (s *Store) MarkPasswordResetTokenUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE password_reset_tokens SET used_at = now() WHERE id = $1`, id)
	return err
}
