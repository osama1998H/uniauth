# CLAUDE.md — UniAuth Codebase Guide

This file provides AI assistants with essential context about the UniAuth codebase: architecture, conventions, workflows, and development patterns.

---

## Project Overview

**UniAuth** is a self-hosted, multi-tenant authentication and authorization service written in Go. It provides JWT-based authentication, RBAC, API keys, audit logging, and webhook event delivery as a standalone service.

- **Language:** Go 1.24+
- **Database:** PostgreSQL 16 (via `pgx/v5`, no ORM)
- **Cache / Rate-limiting:** Redis 7
- **HTTP Router:** `go-chi/chi/v5`
- **Config:** Viper (reads `.env` + environment variables)
- **Logging:** `log/slog` (JSON in production, text in development)

---

## Repository Layout

```
uniauth/
├── cmd/server/main.go          # Entry point — init logger, DB, Redis, server
├── internal/
│   ├── api/
│   │   ├── router.go           # DI wiring, middleware chain, route registration
│   │   ├── handlers/           # HTTP handlers (decode → service call → encode)
│   │   └── middleware/         # Auth, rate-limit, logger, recovery
│   ├── config/config.go        # Viper-based config struct
│   ├── domain/                 # Domain models and sentinel errors
│   ├── repository/
│   │   ├── cache/redis.go      # Redis abstraction
│   │   └── postgres/           # pgx queries, one file per entity
│   └── service/                # Business logic, one file per domain
├── pkg/token/                  # JWT and API key primitives
├── migrations/                 # golang-migrate SQL files (up/down)
├── sql/                        # sqlc schema and query sources
├── sqlc.yaml                   # sqlc code generation config
├── uniauth/                    # Helm chart for Kubernetes
├── Dockerfile                  # Multi-stage: go:1.24-alpine → scratch
├── docker-compose.yml          # Local dev stack (app, postgres, redis, mailhog)
├── Makefile                    # All developer commands (see below)
├── .env.example                # All supported environment variables
├── go.mod / go.sum             # Module definition
├── README.md                   # User-facing documentation
└── CONTRIBUTING.md             # Contribution guide and code conventions
```

---

## Architecture

UniAuth uses a strict **three-layer clean architecture**. Never skip layers or import across them in the wrong direction.

```
HTTP Request
     │
     ▼
handlers/        ← Decode request, validate input, call service, encode JSON response
     │              No business logic. No direct DB calls.
     ▼
service/         ← All business logic. Orchestrates repositories.
     │              No net/http imports. Records audit logs. Triggers webhooks.
     ▼
repository/      ← Database and cache only. No business logic.
```

### Dependency Injection

All dependencies are constructed in `internal/api/router.go` (`NewRouter`) and injected via constructors. There is **no global state**. Every struct receives its dependencies through `New*()` functions.

### Context Propagation

Every function accepts `ctx context.Context` as its first parameter. Authenticated user identity is stored in context via typed keys:

```go
// Set by middleware:
ctx.Value(middleware.ContextKeyUserID)  // uuid.UUID
ctx.Value(middleware.ContextKeyOrgID)   // uuid.UUID
```

---

## Domain Models (`internal/domain/`)

| File | Key Types |
|------|-----------|
| `user.go` | `User` — id, org_id, email, hashed_password, is_active, is_superuser |
| `organization.go` | `Organization` — id, name, slug (unique), is_active |
| `role.go` | `Role`, `Permission` — RBAC objects |
| `session.go` | `Session` — refresh token storage (hash only) |
| `apikey.go` | `APIKey` — scoped, hashed, with revocation |
| `audit.go` | `AuditLog` — action, resource, metadata (JSONB), IP, UA |
| `errors.go` | All sentinel errors (see below) |

### Sentinel Errors

Always use sentinel errors from `internal/domain/errors.go`. Handlers map these to HTTP status codes.

```go
domain.ErrNotFound
domain.ErrAlreadyExists
domain.ErrInvalidCredentials
domain.ErrUnauthorized
domain.ErrForbidden
domain.ErrTokenExpired
domain.ErrTokenInvalid
domain.ErrUserInactive
domain.ErrOrgInactive
domain.ErrAPIKeyRevoked
domain.ErrAPIKeyExpired
domain.ErrWeakPassword
domain.ErrInvalidInput
```

Wrap errors with context: `fmt.Errorf("service.Login: %w", domain.ErrInvalidCredentials)`

---

## API Routes

All API routes live under `/api/v1/`. Public routes need no auth; protected routes require `Authorization: Bearer <JWT>` or `X-API-Key: <key>`.

| Group | Path Prefix | Auth |
|-------|-------------|------|
| Auth | `/api/v1/auth/` | Mixed (register/login public; change-password JWT) |
| Users | `/api/v1/users/` | JWT |
| Organizations | `/api/v1/organizations/` | JWT |
| Roles | `/api/v1/roles/` | JWT |
| API Keys | `/api/v1/api-keys/` | JWT |
| Audit Logs | `/api/v1/audit/` | JWT |
| Webhooks | `/api/v1/webhooks/` | JWT |
| Health | `/health`, `/ready` | None |

---

## Database

**PostgreSQL 16** with `pgx/v5`. No ORM — queries are written by hand or generated by `sqlc`.

### Schema Overview (`migrations/000001_init_schema.up.sql`)

| Table | Purpose |
|-------|---------|
| `organizations` | Multi-tenancy root; every resource is org-scoped |
| `users` | Auth subjects; email unique per org |
| `sessions` | Refresh token hashes (never store raw tokens) |
| `password_reset_tokens` | One-time reset tokens (hashed) |
| `roles` | RBAC roles per org |
| `permissions` | System-level named permissions (seeded) |
| `role_permissions` | Many-to-many role ↔ permission |
| `user_roles` | Many-to-many user ↔ role |
| `api_keys` | Hashed API keys with scopes array |
| `audit_logs` | Append-only audit trail; metadata is JSONB |
| `webhooks` | Event subscriptions per org |

### Key Conventions

- All primary keys are `UUID` (generated in Go with `github.com/google/uuid`)
- Tokens (refresh, reset, API keys) are **always stored as hashes** — never raw values
- Multi-tenancy is enforced by filtering every query by `org_id`
- Migrations managed by `golang-migrate`; files live in `migrations/`

### Running Migrations

```bash
make migrate-up      # Apply pending migrations
make migrate-down    # Rollback one migration
make migrate-status  # Show migration state
```

---

## Authentication Flow

1. **Register** → creates org + admin user atomically
2. **Login** → verifies credentials, creates session, returns `access_token` (15m) + `refresh_token` (7d)
3. **Refresh** → validates refresh token hash, rotates tokens, invalidates old session
4. **Logout** → revokes current session by hash
5. **Password reset** → sends email (or stdout in dev) with short-lived token

JWT signing: HS256 with `JWT_SECRET` (min 32 chars). Claims include `user_id`, `org_id`, `jti` (for blacklisting).

---

## Configuration (`internal/config/config.go`)

All configuration is loaded from `.env` (or environment variables) via Viper. See `.env.example` for all keys.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP port |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `DATABASE_URL` | — | Required PostgreSQL DSN |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `JWT_SECRET` | — | Required; min 32 chars |
| `ACCESS_TOKEN_DURATION` | `15m` | Short-lived access token TTL |
| `REFRESH_TOKEN_DURATION` | `168h` | Refresh token TTL (7 days) |
| `RATE_LIMIT_PER_MINUTE` | `60` | Requests per IP per minute |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `SMTP_*` | — | Optional; prints emails to stdout if unset |

---

## Development Workflow

### Prerequisites

- Go 1.24+
- Docker & Docker Compose
- `make`

### Local Setup

```bash
cp .env.example .env          # Configure environment
make docker-up                # Start postgres, redis, mailhog
make migrate-up               # Apply migrations
make run                      # Start server on :8080
```

### All Make Targets

| Target | Action |
|--------|--------|
| `make build` | Compile binary to `./bin/uniauth` |
| `make run` | Start deps + run server |
| `make test` | Full test suite with race detection (`-race -timeout 120s`) |
| `make test-short` | Fast tests, skip DB-dependent tests |
| `make lint` | Run `golangci-lint` |
| `make fmt` | Format all Go code |
| `make vet` | Run `go vet` |
| `make migrate-up` | Apply migrations |
| `make migrate-down` | Rollback one migration |
| `make migrate-status` | Show migration state |
| `make generate` | Run `go generate ./...` |
| `make sqlc` | Regenerate repository code from SQL |
| `make docker-build` | Build Docker image |
| `make docker-up` | Start full stack via compose |
| `make docker-down` | Stop compose stack |
| `make setup` | Install dev tools (migrate, sqlc, golangci-lint) |

---

## Code Conventions

### Adding a New Endpoint (Step-by-Step)

1. **Domain** — Add new types or errors to `internal/domain/` if needed
2. **Repository** — Add query function in `internal/repository/postgres/<entity>.go`
3. **Service** — Add business logic in `internal/service/<entity>.go`; call audit/webhook as needed
4. **Handler** — Add HTTP handler in `internal/api/handlers/<entity>.go`; map domain errors to HTTP codes
5. **Router** — Register route in `internal/api/router.go`

### Error Handling

```go
// Service layer: wrap with context
if err != nil {
    return fmt.Errorf("UserService.GetByID: %w", err)
}

// Handler layer: map to HTTP
switch {
case errors.Is(err, domain.ErrNotFound):
    respondError(w, http.StatusNotFound, "not found")
case errors.Is(err, domain.ErrForbidden):
    respondError(w, http.StatusForbidden, "forbidden")
default:
    respondError(w, http.StatusInternalServerError, "internal error")
}
```

### Logging

Use `slog` from the standard library. Never use `log.Println` or global loggers.

```go
slog.InfoContext(ctx, "user created", "user_id", user.ID, "org_id", user.OrgID)
slog.ErrorContext(ctx, "failed to send email", "error", err)
```

### Tests

- Use table-driven tests with `t.Run()` subtests
- Use `testing.Short()` guard for DB-dependent tests
- No global state in tests

```go
func TestAuthService_Login(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping DB test in short mode")
    }
    tests := []struct {
        name    string
        input   LoginInput
        wantErr error
    }{
        {"valid credentials", validInput, nil},
        {"wrong password", wrongPassInput, domain.ErrInvalidCredentials},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) { ... })
    }
}
```

### Password Validation

Enforced in `internal/service/auth.go`. Passwords must be:
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 digit
- At least 1 special character

### Commit Messages

Follow Conventional Commits:

```
feat: add email verification endpoint
fix: rotate refresh token on concurrent requests
docs: update API endpoint table in README
refactor: extract token validation to pkg/token
test: add table-driven tests for RBAC service
```

---

## CI/CD Pipeline (`.github/workflows/ci.yml`)

Three jobs triggered on push/PR to `main`/`master`:

1. **test** — Spins up Postgres 16 + Redis 7, applies migrations, runs `go test ./... -race`
2. **lint** — Runs `golangci-lint`
3. **build** — On push to main only: builds and pushes Docker image to `ghcr.io/osama1998h/uniauth`

Always ensure `make test` and `make lint` pass locally before pushing.

---

## Docker & Kubernetes

### Docker

```bash
make docker-build    # Build image (multi-stage, ~10MB)
make docker-up       # Start full stack (app + postgres + redis + mailhog)
make docker-down     # Tear down
```

The final Docker image uses `scratch` as base — no shell, no package manager. Only the binary, CA certificates, and migration files are included.

### Helm (Kubernetes)

Helm chart lives in `uniauth/`. Key values to override:

```yaml
image:
  repository: ghcr.io/osama1998h/uniauth
  tag: latest

replicaCount: 2

postgres:
  enabled: true   # deploys bundled postgres; use false + DATABASE_URL for external

redis:
  enabled: true
```

Horizontal Pod Autoscaler is configured (2–10 replicas). Readiness and liveness probes point to `/ready` and `/health`.

---

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/go-chi/chi/v5` | HTTP router and middleware |
| `github.com/golang-jwt/jwt/v5` | JWT creation and verification |
| `github.com/jackc/pgx/v5` | PostgreSQL driver (no ORM) |
| `github.com/redis/go-redis/v9` | Redis client |
| `github.com/golang-migrate/migrate/v4` | Database migrations |
| `github.com/spf13/viper` | Configuration management |
| `golang.org/x/crypto` | bcrypt password hashing |
| `github.com/google/uuid` | UUID generation |

---

## Security Considerations

- **Never log raw tokens** (access, refresh, reset, API keys) — log only IDs or prefixes
- **Always hash** tokens before storing: use `crypto/sha256` or bcrypt
- **Multi-tenancy isolation** — every repository query must filter by `org_id`
- **Rate limiting** is Redis-backed and applied globally before route dispatch
- **CORS** defaults to `*` in development; set explicit origins in production
- `JWT_SECRET` must be at least 32 characters and kept secret
- API key scopes control access — always verify scopes in the service layer
