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
