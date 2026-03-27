# Contributing to UniAuth

Thank you for your interest in contributing! This document explains how to get started and the conventions we follow.

## Getting Started

### Prerequisites

- Go 1.24+
- Docker & Docker Compose
- `make`

### Local Setup

```bash
# Clone the repo
git clone https://github.com/osama1998h/uniauth.git
cd uniauth

# Start dependencies
docker compose up -d postgres redis mailhog

# Copy env file
cp .env.example .env

# Run the server
make run
```

The server starts at `http://localhost:8080`.
MailHog UI (email testing) at `http://localhost:8025`.

## Architecture Overview

UniAuth follows a clean three-layer architecture:

```
HTTP Request
    │
    ▼
handlers/          ← Decode request, call service, encode response
    │
    ▼
service/           ← Business logic, orchestration, audit logging
    │
    ▼
repository/postgres/ ← Database queries (pgx/v5)
repository/cache/    ← Redis (rate limiting, token blacklisting)
```

**Rules:**
- Handlers must not contain business logic — only HTTP encoding/decoding
- Services must not import `net/http` packages
- Repository functions must not call other repository functions
- Use `fmt.Errorf("context: %w", err)` for error wrapping everywhere
- All functions accept `ctx context.Context` as the first parameter

## Adding a New Endpoint

Follow these steps (example: `GET /api/v1/sessions`):

### 1. Domain type (if needed) — `internal/domain/`
```go
type Session struct { ... }
```

### 2. Repository query — `internal/repository/postgres/sessions.go`
```go
func (s *Store) ListSessionsByUser(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) { ... }
```

### 3. Service method — `internal/service/auth.go`
```go
func (s *AuthService) ListSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) { ... }
```

### 4. Handler — `internal/api/handlers/auth.go`
```go
func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) { ... }
```

### 5. Route — `internal/api/router.go`
```go
r.Get("/sessions", authH.ListSessions)
```

### 6. Test — `internal/api/handlers/auth_test.go`
```go
func TestListSessions(t *testing.T) { ... }
```

## Code Conventions

- **Error values:** Return domain sentinel errors (`domain.ErrNotFound`) from the repository layer; the handler maps them to HTTP codes via `handleServiceError()`
- **No global state:** All dependencies are injected via constructors
- **Table-driven tests:** Use `t.Run()` with named subtests
- **Logging:** Use `slog.Logger` (injected, never global `log.Println`)
- **IDs:** Always `uuid.UUID`, never `int`

## Running Tests

```bash
# Unit + integration tests (requires Docker for testcontainers)
make test

# Short tests only (no DB)
make test-short

# Lint
make lint
```

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add session listing endpoint
fix: correct token expiry calculation
docs: update README with new env vars
refactor: extract slugify to pkg/slug
test: add integration tests for API keys
```

## Submitting a PR

1. Fork the repo and create a feature branch: `git checkout -b feat/my-feature`
2. Make your changes following the conventions above
3. Ensure `go build ./...` and `go test ./...` pass
4. Open a PR with the provided template filled out

## Roadmap

Looking to contribute something meaningful? Check the open issues for items labeled `good first issue` or `help wanted`.

**Planned features:**
- [ ] Multi-Factor Authentication (TOTP)
- [ ] OAuth2 provider (use UniAuth as your OAuth2 server)
- [ ] Social login (Google, GitHub OAuth2 client)
- [ ] Email verification flow
- [ ] Admin dashboard API
- [ ] SDKs (TypeScript, Python)
- [ ] Prometheus metrics endpoint
- [ ] Horizontal scaling (session clustering)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
