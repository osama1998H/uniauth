package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/osama1998h/uniauth/internal/testutil"
	"github.com/osama1998h/uniauth/pkg/token"
)

func TestStoreUserHandlesNullableTimestamps(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "nullable-user-org")
	user := testutil.CreateUser(t, store, org.ID, "nullable-user")

	got, err := store.GetUserByID(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil", got.EmailVerifiedAt)
	}
	if got.LastLoginAt != nil {
		t.Fatalf("LastLoginAt = %v, want nil", got.LastLoginAt)
	}

	users, err := store.ListUsersByOrg(ctx, org.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListUsersByOrg() error = %v", err)
	}
	if len(users) == 0 {
		t.Fatal("expected at least one user in organization")
	}

	updatedName := "Nullable User"
	updatedEmail := "nullable-user-updated@example.com"
	updated, err := store.UpdateUser(ctx, org.ID, user.ID, &updatedName, &updatedEmail)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}
	if updated.EmailVerifiedAt != nil {
		t.Fatalf("updated EmailVerifiedAt = %v, want nil", updated.EmailVerifiedAt)
	}
	if updated.LastLoginAt != nil {
		t.Fatalf("updated LastLoginAt = %v, want nil", updated.LastLoginAt)
	}
}

func TestStoreAPIKeyHandlesNullableFieldsAndNilScopes(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "nullable-api-key-org")
	keyHash := token.HashAPIKey("router-nullable-api-key")

	key, err := store.CreateAPIKey(ctx, org.ID, "nullable-api-key", "uni", keyHash, nil, nil)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if len(key.Scopes) != 0 {
		t.Fatalf("created scopes = %v, want empty", key.Scopes)
	}
	if key.ExpiresAt != nil || key.LastUsedAt != nil || key.RevokedAt != nil {
		t.Fatalf("created nullable timestamps = (%v, %v, %v), want nil", key.ExpiresAt, key.LastUsedAt, key.RevokedAt)
	}

	got, err := store.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		t.Fatalf("GetAPIKeyByHash() error = %v", err)
	}
	if len(got.Scopes) != 0 {
		t.Fatalf("loaded scopes = %v, want empty", got.Scopes)
	}
	if got.ExpiresAt != nil || got.LastUsedAt != nil || got.RevokedAt != nil {
		t.Fatalf("loaded nullable timestamps = (%v, %v, %v), want nil", got.ExpiresAt, got.LastUsedAt, got.RevokedAt)
	}

	keys, err := store.ListAPIKeysByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListAPIKeysByOrg() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 api key, got %d", len(keys))
	}
	if len(keys[0].Scopes) != 0 {
		t.Fatalf("listed scopes = %v, want empty", keys[0].Scopes)
	}
	if keys[0].ExpiresAt != nil || keys[0].LastUsedAt != nil || keys[0].RevokedAt != nil {
		t.Fatalf("listed nullable timestamps = (%v, %v, %v), want nil", keys[0].ExpiresAt, keys[0].LastUsedAt, keys[0].RevokedAt)
	}
}
