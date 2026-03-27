// Package db provides the database repository layer using pgx/v5.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps a pgxpool.Pool and provides all query methods.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new Store connected to the given PostgreSQL URL.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Pool returns the underlying connection pool (for migrations, etc.).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close closes the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
