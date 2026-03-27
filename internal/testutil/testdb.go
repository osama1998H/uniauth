package testutil

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// RequireTestStore returns a postgres store backed by DATABASE_URL.
func RequireTestStore(t testing.TB) *db.Store {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping database-dependent test in short mode")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := db.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(store.Close)

	return store
}

// CreateOrganization inserts an organization and cleans it up after the test.
func CreateOrganization(t testing.TB, store *db.Store, prefix string) *domain.Organization {
	t.Helper()

	name := uniqueString(prefix)
	slug := strings.ToLower(uniqueString(prefix + "-slug"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org, err := store.CreateOrganization(ctx, name, slug)
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, cleanupErr := store.Pool().Exec(cleanupCtx, `DELETE FROM organizations WHERE id = $1`, org.ID); cleanupErr != nil {
			t.Fatalf("cleanup organization %s: %v", org.ID, cleanupErr)
		}
	})

	return org
}

// CreateUser inserts a user in the given organization.
func CreateUser(t testing.TB, store *db.Store, orgID uuid.UUID, prefix string) *domain.User {
	t.Helper()

	fullName := uniqueString(prefix + "-name")
	email := fmt.Sprintf("%s@example.com", uniqueString(prefix+"-email"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	user, err := store.CreateUser(ctx, orgID, email, "hashed-password", &fullName, false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	return user
}

// CreateRole inserts a role in the given organization.
func CreateRole(t testing.TB, store *db.Store, orgID uuid.UUID, prefix string) *domain.Role {
	t.Helper()

	description := uniqueString(prefix + "-description")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	role, err := store.CreateRole(ctx, orgID, uniqueString(prefix+"-role"), &description)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	return role
}

// DiscardLogger returns a logger suitable for tests.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func uniqueString(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(uuid.NewString()))
}
