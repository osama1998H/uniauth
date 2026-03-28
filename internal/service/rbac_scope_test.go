package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	"github.com/osama1998h/uniauth/internal/testutil"
)

func TestRBACServiceRejectsCrossOrgRoleAssignments(t *testing.T) {
	store := testutil.RequireTestStore(t)
	svc := NewRBACService(store, NewAuditService(store, testutil.DiscardLogger()))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	orgA := testutil.CreateOrganization(t, store, "svc-roles-org-a")
	orgB := testutil.CreateOrganization(t, store, "svc-roles-org-b")
	userA := testutil.CreateUser(t, store, orgA.ID, "svc-user-a")
	userB := testutil.CreateUser(t, store, orgB.ID, "svc-user-b")
	roleA := testutil.CreateRole(t, store, orgA.ID, "svc-role-a")
	roleB := testutil.CreateRole(t, store, orgB.ID, "svc-role-b")
	actorID := uuid.New()

	err := svc.AssignRoleToUser(ctx, orgA.ID, userB.ID, roleA.ID, actorID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for foreign-org user assignment, got %v", err)
	}

	err = svc.AssignRoleToUser(ctx, orgA.ID, userA.ID, roleB.ID, actorID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for foreign-org role assignment, got %v", err)
	}
}

func TestRBACServiceRejectsCrossOrgPermissionAssignment(t *testing.T) {
	store := testutil.RequireTestStore(t)
	svc := NewRBACService(store, NewAuditService(store, testutil.DiscardLogger()))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	orgA := testutil.CreateOrganization(t, store, "svc-perms-org-a")
	orgB := testutil.CreateOrganization(t, store, "svc-perms-org-b")
	_ = testutil.CreateRole(t, store, orgA.ID, "svc-perms-role-a")
	roleB := testutil.CreateRole(t, store, orgB.ID, "svc-perms-role-b")

	err := svc.AssignPermissions(ctx, orgA.ID, roleB.ID, []string{"users:read"})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for foreign-org permission assignment, got %v", err)
	}
}

func TestRBACServiceAuthorize(t *testing.T) {
	store := testutil.RequireTestStore(t)
	svc := NewRBACService(store, NewAuditService(store, testutil.DiscardLogger()))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "svc-authorize-org")
	regularUser := testutil.CreateUser(t, store, org.ID, "svc-authorize-user")
	superuser, err := store.CreateUser(ctx, org.ID, "svc-authorize-superuser@example.com", "hashed-password", nil, true)
	if err != nil {
		t.Fatalf("CreateUser(superuser) error = %v", err)
	}

	t.Run("denies user without permission", func(t *testing.T) {
		err := svc.Authorize(ctx, org.ID, regularUser.ID, domain.PermissionUsersRead)
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("allows user with permission", func(t *testing.T) {
		role := testutil.CreateRole(t, store, org.ID, "svc-authorize-role")
		perm, err := store.GetPermissionByName(ctx, domain.PermissionUsersRead)
		if err != nil {
			t.Fatalf("GetPermissionByName() error = %v", err)
		}
		if err := store.AssignPermissionToRole(ctx, role.ID, perm.ID); err != nil {
			t.Fatalf("AssignPermissionToRole() error = %v", err)
		}
		if err := store.AssignRoleToUser(ctx, org.ID, regularUser.ID, role.ID); err != nil {
			t.Fatalf("AssignRoleToUser() error = %v", err)
		}

		if err := svc.Authorize(ctx, org.ID, regularUser.ID, domain.PermissionUsersRead); err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
	})

	t.Run("allows superuser without role assignments", func(t *testing.T) {
		if err := svc.Authorize(ctx, org.ID, superuser.ID, domain.PermissionUsersDelete); err != nil {
			t.Fatalf("Authorize(superuser) error = %v", err)
		}
	})

	t.Run("returns unauthorized for missing user", func(t *testing.T) {
		err := svc.Authorize(ctx, org.ID, uuid.New(), domain.PermissionUsersRead)
		if !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
	})
}
