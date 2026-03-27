package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/osama1998h/uniauth/internal/domain"
)

func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, tokenHash string, userAgent, ipAddress *string, expiresAt time.Time) (*domain.Session, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip_address, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, revoked_at, created_at`,
		userID, tokenHash, userAgent, ipAddress, expiresAt,
	)
	return scanSession(row)
}

func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, revoked_at, created_at
		 FROM sessions WHERE refresh_token_hash = $1`, tokenHash,
	)
	sess, err := scanSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return sess, err
}

func (s *Store) ListSessionsByUser(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, revoked_at, created_at
		 FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*domain.Session
	for rows.Next() {
		sess := &domain.Session{}
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.RefreshTokenHash, &sess.UserAgent, &sess.IPAddress, &sess.ExpiresAt, &sess.RevokedAt, &sess.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, id)
	return err
}

func (s *Store) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID,
	)
	return err
}

func scanSession(row pgx.Row) (*domain.Session, error) {
	s := &domain.Session{}
	err := row.Scan(&s.ID, &s.UserID, &s.RefreshTokenHash, &s.UserAgent, &s.IPAddress, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	return s, nil
}
