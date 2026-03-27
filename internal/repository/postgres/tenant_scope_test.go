package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/osama1998h/uniauth/internal/domain"
	"github.com/osama1998h/uniauth/internal/testutil"
)

func TestStoreUserTenantScoping(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	orgA := testutil.CreateOrganization(t, store, "users-org-a")
	orgB := testutil.CreateOrganization(t, store, "users-org-b")
	userA := testutil.CreateUser(t, store, orgA.ID, "user-a")
	userB := testutil.CreateUser(t, store, orgB.ID, "user-b")

	t.Run("GetUserByID only returns same-org users", func(t *testing.T) {
		got, err := store.GetUserByID(ctx, orgA.ID, userA.ID)
		if err != nil {
			t.Fatalf("get scoped user: %v", err)
		}
		if got.ID != userA.ID {
			t.Fatalf("got user %s, want %s", got.ID, userA.ID)
		}

		_, err = store.GetUserByID(ctx, orgA.ID, userB.ID)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org user, got %v", err)
		}
	})

	t.Run("UpdateUser only updates same-org users", func(t *testing.T) {
		fullName := "Updated User A"
		email := "updated-user-a@example.com"

		updated, err := store.UpdateUser(ctx, orgA.ID, userA.ID, &fullName, &email)
		if err != nil {
			t.Fatalf("update scoped user: %v", err)
		}
		if updated.FullName == nil || *updated.FullName != fullName {
			t.Fatalf("full name = %v, want %q", updated.FullName, fullName)
		}
		if updated.Email != email {
			t.Fatalf("email = %q, want %q", updated.Email, email)
		}

		_, err = store.UpdateUser(ctx, orgA.ID, userB.ID, &fullName, &email)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org update, got %v", err)
		}
	})

	t.Run("DeactivateUser only deactivates same-org users", func(t *testing.T) {
		activeUser := testutil.CreateUser(t, store, orgA.ID, "active-user")
		foreignUser := testutil.CreateUser(t, store, orgB.ID, "foreign-user")

		if err := store.DeactivateUser(ctx, orgA.ID, activeUser.ID); err != nil {
			t.Fatalf("deactivate scoped user: %v", err)
		}

		got, err := store.GetUserByID(ctx, orgA.ID, activeUser.ID)
		if err != nil {
			t.Fatalf("get deactivated user: %v", err)
		}
		if got.IsActive {
			t.Fatal("expected user to be inactive after scoped deactivation")
		}

		err = store.DeactivateUser(ctx, orgA.ID, foreignUser.ID)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org deactivate, got %v", err)
		}
	})
}

func TestStoreRoleTenantScoping(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	orgA := testutil.CreateOrganization(t, store, "roles-org-a")
	orgB := testutil.CreateOrganization(t, store, "roles-org-b")
	roleA := testutil.CreateRole(t, store, orgA.ID, "role-a")
	roleB := testutil.CreateRole(t, store, orgB.ID, "role-b")

	t.Run("GetRoleByID only returns same-org roles", func(t *testing.T) {
		got, err := store.GetRoleByID(ctx, orgA.ID, roleA.ID)
		if err != nil {
			t.Fatalf("get scoped role: %v", err)
		}
		if got.ID != roleA.ID {
			t.Fatalf("got role %s, want %s", got.ID, roleA.ID)
		}

		_, err = store.GetRoleByID(ctx, orgA.ID, roleB.ID)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org role, got %v", err)
		}
	})

	t.Run("UpdateRole only updates same-org roles", func(t *testing.T) {
		description := "Updated role description"
		updated, err := store.UpdateRole(ctx, orgA.ID, roleA.ID, "updated-role-a", &description)
		if err != nil {
			t.Fatalf("update scoped role: %v", err)
		}
		if updated.Name != "updated-role-a" {
			t.Fatalf("role name = %q, want %q", updated.Name, "updated-role-a")
		}

		_, err = store.UpdateRole(ctx, orgA.ID, roleB.ID, "blocked-role", &description)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org role update, got %v", err)
		}
	})

	t.Run("DeleteRole only deletes same-org roles", func(t *testing.T) {
		deletableRole := testutil.CreateRole(t, store, orgA.ID, "deletable-role")
		foreignRole := testutil.CreateRole(t, store, orgB.ID, "foreign-role")

		if err := store.DeleteRole(ctx, orgA.ID, deletableRole.ID); err != nil {
			t.Fatalf("delete scoped role: %v", err)
		}

		_, err := store.GetRoleByID(ctx, orgA.ID, deletableRole.ID)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected deleted role to be missing, got %v", err)
		}

		err = store.DeleteRole(ctx, orgA.ID, foreignRole.ID)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org role delete, got %v", err)
		}
	})
}

func TestStoreDeactivateUserReturnsNotFoundForMissingOrgMatch(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "missing-user-org")

	err := store.DeactivateUser(ctx, org.ID, uuid.New())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing user, got %v", err)
	}
}

func TestStoreDeleteRoleReturnsNotFoundForMissingOrgMatch(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "missing-role-org")

	err := store.DeleteRole(ctx, org.ID, uuid.New())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing role, got %v", err)
	}
}

func TestStoreUserRoleTenantIntegrity(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	orgA := testutil.CreateOrganization(t, store, "user-roles-org-a")
	orgB := testutil.CreateOrganization(t, store, "user-roles-org-b")
	userA := testutil.CreateUser(t, store, orgA.ID, "user-roles-user-a")
	userB := testutil.CreateUser(t, store, orgB.ID, "user-roles-user-b")
	roleA := testutil.CreateRole(t, store, orgA.ID, "user-roles-role-a")
	roleB := testutil.CreateRole(t, store, orgB.ID, "user-roles-role-b")

	t.Run("AssignRoleToUser inserts same-org links", func(t *testing.T) {
		if err := store.AssignRoleToUser(ctx, orgA.ID, userA.ID, roleA.ID); err != nil {
			t.Fatalf("assign scoped role: %v", err)
		}

		roles, err := store.ListRolesByUser(ctx, userA.ID)
		if err != nil {
			t.Fatalf("list roles by user: %v", err)
		}
		if len(roles) != 1 {
			t.Fatalf("expected 1 role for user, got %d", len(roles))
		}
		if roles[0].ID != roleA.ID {
			t.Fatalf("role id = %s, want %s", roles[0].ID, roleA.ID)
		}
	})

	t.Run("AssignRoleToUser rejects foreign-org user", func(t *testing.T) {
		err := store.AssignRoleToUser(ctx, orgA.ID, userB.ID, roleA.ID)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org user, got %v", err)
		}
	})

	t.Run("AssignRoleToUser rejects foreign-org role", func(t *testing.T) {
		err := store.AssignRoleToUser(ctx, orgA.ID, userA.ID, roleB.ID)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for foreign-org role, got %v", err)
		}
	})

	t.Run("raw SQL insert rejects mismatched org tuples", func(t *testing.T) {
		_, err := store.Pool().Exec(ctx,
			`INSERT INTO user_roles (org_id, user_id, role_id) VALUES ($1, $2, $3)`,
			orgA.ID, userB.ID, roleA.ID,
		)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("expected foreign-key violation for mismatched org tuple, got %v", err)
		}
	})
}

func TestStoreUserHasPermissionHonorsOrgScope(t *testing.T) {
	store := testutil.RequireTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	orgA := testutil.CreateOrganization(t, store, "user-perm-org-a")
	orgB := testutil.CreateOrganization(t, store, "user-perm-org-b")
	userA := testutil.CreateUser(t, store, orgA.ID, "user-perm-user-a")
	userB := testutil.CreateUser(t, store, orgB.ID, "user-perm-user-b")
	roleA := testutil.CreateRole(t, store, orgA.ID, "user-perm-role-a")
	roleB := testutil.CreateRole(t, store, orgB.ID, "user-perm-role-b")

	perm, err := store.GetPermissionByName(ctx, domain.PermissionUsersRead)
	if err != nil {
		t.Fatalf("GetPermissionByName() error = %v", err)
	}
	if err := store.AssignPermissionToRole(ctx, roleA.ID, perm.ID); err != nil {
		t.Fatalf("AssignPermissionToRole(roleA) error = %v", err)
	}
	if err := store.AssignPermissionToRole(ctx, roleB.ID, perm.ID); err != nil {
		t.Fatalf("AssignPermissionToRole(roleB) error = %v", err)
	}
	if err := store.AssignRoleToUser(ctx, orgA.ID, userA.ID, roleA.ID); err != nil {
		t.Fatalf("AssignRoleToUser() error = %v", err)
	}
	if err := store.AssignRoleToUser(ctx, orgB.ID, userB.ID, roleB.ID); err != nil {
		t.Fatalf("AssignRoleToUser() error = %v", err)
	}

	allowed, err := store.UserHasPermission(ctx, orgA.ID, userA.ID, domain.PermissionUsersRead)
	if err != nil {
		t.Fatalf("UserHasPermission(orgA, userA) error = %v", err)
	}
	if !allowed {
		t.Fatal("expected userA to have users:read in orgA")
	}

	allowed, err = store.UserHasPermission(ctx, orgA.ID, userB.ID, domain.PermissionUsersRead)
	if err != nil {
		t.Fatalf("UserHasPermission(orgA, userB) error = %v", err)
	}
	if allowed {
		t.Fatal("expected foreign-org user to be denied")
	}

	allowed, err = store.UserHasPermission(ctx, orgA.ID, userA.ID, domain.PermissionUsersDelete)
	if err != nil {
		t.Fatalf("UserHasPermission(orgA, userA, users:delete) error = %v", err)
	}
	if allowed {
		t.Fatal("expected missing permission to be denied")
	}
}
