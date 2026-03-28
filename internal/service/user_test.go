package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/internal/testutil"
)

func newTestUserService(t *testing.T) (*UserService, *db.Store) {
	t.Helper()

	store := testutil.RequireTestStore(t)
	logger := testutil.DiscardLogger()
	auditSvc := NewAuditService(store, logger)
	webhookSvc := NewWebhookService(store, logger)
	svc := NewUserService(store, auditSvc, webhookSvc)

	return svc, store
}

func TestUserService_Create(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database-dependent test in short mode")
	}

	svc, store := newTestUserService(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "user-create-org")
	actor := testutil.CreateUser(t, store, org.ID, "user-create-actor")

	tests := []struct {
		name    string
		input   CreateUserInput
		orgID   uuid.UUID
		setup   func(t *testing.T)
		check   func(t *testing.T, user *domain.User)
		wantErr error
	}{
		{
			name: "happy path — no roles",
			input: CreateUserInput{
				Email:    "happy-no-roles@example.com",
				Password: "S3cur3P@ss!",
			},
			orgID: org.ID,
			check: func(t *testing.T, user *domain.User) {
				if user.IsSuperuser {
					t.Error("expected is_superuser=false")
				}
				if !user.IsActive {
					t.Error("expected is_active=true")
				}
				if user.OrgID != org.ID {
					t.Errorf("org_id = %s, want %s", user.OrgID, org.ID)
				}
			},
		},
		{
			name: "happy path — with roles",
			input: func() CreateUserInput {
				role1 := testutil.CreateRole(t, store, org.ID, "create-role1")
				role2 := testutil.CreateRole(t, store, org.ID, "create-role2")
				return CreateUserInput{
					Email:    "happy-with-roles@example.com",
					Password: "S3cur3P@ss!",
					RoleIDs:  []uuid.UUID{role1.ID, role2.ID},
				}
			}(),
			orgID: org.ID,
			check: func(t *testing.T, user *domain.User) {
				roles, err := store.ListRolesByUser(ctx, user.ID)
				if err != nil {
					t.Fatalf("ListRolesByUser: %v", err)
				}
				if len(roles) != 2 {
					t.Errorf("expected 2 roles, got %d", len(roles))
				}
			},
		},
		{
			name: "password is hashed with bcrypt",
			input: CreateUserInput{
				Email:    "hashed-pw@example.com",
				Password: "S3cur3P@ss!",
			},
			orgID: org.ID,
			check: func(t *testing.T, user *domain.User) {
				dbUser, err := store.GetUserByID(ctx, org.ID, user.ID)
				if err != nil {
					t.Fatalf("GetUserByID: %v", err)
				}
				if err := bcrypt.CompareHashAndPassword([]byte(dbUser.HashedPassword), []byte("S3cur3P@ss!")); err != nil {
					t.Error("password was not hashed with bcrypt")
				}
			},
		},
		{
			name: "created user is never superuser",
			input: CreateUserInput{
				Email:    "never-superuser@example.com",
				Password: "S3cur3P@ss!",
			},
			orgID: org.ID,
			check: func(t *testing.T, user *domain.User) {
				if user.IsSuperuser {
					t.Error("expected is_superuser=false, even when created by admin")
				}
			},
		},
		{
			name: "full name is set",
			input: CreateUserInput{
				Email:    "with-name@example.com",
				Password: "S3cur3P@ss!",
				FullName: strPtr("John Doe"),
			},
			orgID: org.ID,
			check: func(t *testing.T, user *domain.User) {
				if user.FullName == nil || *user.FullName != "John Doe" {
					t.Errorf("full_name = %v, want %q", user.FullName, "John Doe")
				}
			},
		},
		{
			name: "weak password — too short",
			input: CreateUserInput{
				Email:    "weak-short@example.com",
				Password: "Abc1!e",
			},
			orgID:   org.ID,
			wantErr: domain.ErrWeakPassword,
		},
		{
			name: "weak password — no uppercase",
			input: CreateUserInput{
				Email:    "weak-noup@example.com",
				Password: "secure@123",
			},
			orgID:   org.ID,
			wantErr: domain.ErrWeakPassword,
		},
		{
			name: "weak password — no digit",
			input: CreateUserInput{
				Email:    "weak-nodig@example.com",
				Password: "Secure@abc",
			},
			orgID:   org.ID,
			wantErr: domain.ErrWeakPassword,
		},
		{
			name: "weak password — no special char",
			input: CreateUserInput{
				Email:    "weak-nospec@example.com",
				Password: "Secure1234",
			},
			orgID:   org.ID,
			wantErr: domain.ErrWeakPassword,
		},
		{
			name: "empty email",
			input: CreateUserInput{
				Email:    "",
				Password: "S3cur3P@ss!",
			},
			orgID:   org.ID,
			wantErr: domain.ErrInvalidInput,
		},
		{
			name: "duplicate email in same org",
			input: CreateUserInput{
				Email:    "duplicate@example.com",
				Password: "S3cur3P@ss!",
			},
			orgID: org.ID,
			setup: func(t *testing.T) {
				// Pre-create a user with the same email in the same org
				_, err := svc.Create(ctx, org.ID, actor.ID, CreateUserInput{
					Email:    "duplicate@example.com",
					Password: "S3cur3P@ss!",
				}, nil, nil)
				if err != nil {
					t.Fatalf("setup duplicate: %v", err)
				}
			},
			wantErr: domain.ErrAlreadyExists,
		},
		{
			name: "same email in different org succeeds",
			input: CreateUserInput{
				Email:    "cross-org@example.com",
				Password: "S3cur3P@ss!",
			},
			orgID: func() uuid.UUID {
				org2 := testutil.CreateOrganization(t, store, "user-create-org2")
				// Pre-create a user in org1 with this email
				_, err := svc.Create(ctx, org.ID, actor.ID, CreateUserInput{
					Email:    "cross-org@example.com",
					Password: "S3cur3P@ss!",
				}, nil, nil)
				if err != nil {
					t.Fatalf("setup cross-org: %v", err)
				}
				return org2.ID
			}(),
			check: func(t *testing.T, user *domain.User) {
				if user.Email != "cross-org@example.com" {
					t.Errorf("email = %q, want %q", user.Email, "cross-org@example.com")
				}
			},
		},
		{
			name: "role from different org rejected",
			input: func() CreateUserInput {
				otherOrg := testutil.CreateOrganization(t, store, "other-org-role")
				foreignRole := testutil.CreateRole(t, store, otherOrg.ID, "foreign-role")
				return CreateUserInput{
					Email:    "foreign-role@example.com",
					Password: "S3cur3P@ss!",
					RoleIDs:  []uuid.UUID{foreignRole.ID},
				}
			}(),
			orgID:   org.ID,
			wantErr: domain.ErrInvalidInput,
		},
		{
			name: "non-existent role ID rejected",
			input: CreateUserInput{
				Email:    "bad-role@example.com",
				Password: "S3cur3P@ss!",
				RoleIDs:  []uuid.UUID{uuid.New()},
			},
			orgID:   org.ID,
			wantErr: domain.ErrInvalidInput,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}

			user, err := svc.Create(ctx, tc.orgID, actor.ID, tc.input, nil, nil)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error wrapping %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want errors.Is(%v)", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, user)
			}
		})
	}
}

func TestUserService_Create_AuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database-dependent test in short mode")
	}

	store := testutil.RequireTestStore(t)
	logger := slog.Default()
	auditSvc := NewAuditService(store, logger)
	webhookSvc := NewWebhookService(store, logger)
	svc := NewUserService(store, auditSvc, webhookSvc)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "audit-org")
	actor := testutil.CreateUser(t, store, org.ID, "audit-actor")

	user, err := svc.Create(ctx, org.ID, actor.ID, CreateUserInput{
		Email:    "audit-test@example.com",
		Password: "S3cur3P@ss!",
	}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Give async audit log goroutine time to complete
	time.Sleep(500 * time.Millisecond)

	action := domain.AuditActionUserCreated
	logs, err := store.ListAuditLogs(ctx, org.ID, domain.AuditFilter{
		Action: &action,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}

	var found bool
	for _, log := range logs {
		if log.ResourceID != nil && *log.ResourceID == user.ID.String() {
			found = true
			if log.UserID == nil || *log.UserID != actor.ID {
				t.Errorf("audit log actor = %v, want %s", log.UserID, actor.ID)
			}
			if log.ResourceType == nil || *log.ResourceType != "user" {
				t.Errorf("audit log resource_type = %v, want %q", log.ResourceType, "user")
			}
			break
		}
	}
	if !found {
		t.Error("expected user.created audit log entry, found none")
	}
}
