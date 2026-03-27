# UniAuth

<img width="1536" height="1024" alt="ChatGPT Image Mar 27, 2026, 08_00_27 PM" src="https://github.com/user-attachments/assets/33204822-ac87-40af-a13e-2757e45f3461" />


**UniAuth** is a self-hosted, production-grade authentication and authorization service built in Go. Use it as the auth backend for any of your applications — a lightweight alternative to Keycloak or Auth0.

> **Status:** Active development · v0.1.0 coming soon

## Features

- **JWT authentication** — access tokens (15m) + refresh tokens (7d) with rotation
- **Multi-tenancy** — organizations with isolated users, roles, and API keys
- **Role-Based Access Control (RBAC)** — fine-grained permissions (`users:read`, `roles:write`, etc.)
- **API keys** — server-to-server authentication with scopes
- **Audit logs** — every auth event recorded with actor, IP, and metadata
- **Webhooks** — receive HTTP callbacks on auth events (HMAC-signed)
- **Password reset** — secure token flow via SMTP email
- **Rate limiting** — per-IP via Redis sliding window
- **Health endpoints** — `/health` + `/ready` for Kubernetes probes
- **Single binary** — ships as a ~10MB Docker image, no runtime deps beyond Postgres and Redis

## Quick Start

```bash
# 1. Clone
git clone https://github.com/osama1998h/uniauth.git && cd uniauth

# 2. Configure
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET

# 3. Start
docker compose up
```

Server is running at `http://localhost:8080`. Docker Compose configures password reset email delivery through MailHog by default, and the MailHog UI is available at `http://localhost:8025`.

## API

### Authentication

Protected routes accept `Authorization: Bearer <access-token>` only. Refresh tokens are reserved for `/api/v1/auth/refresh` and the logout request body.

```bash
# Register a new organization + admin user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"org_name":"Acme Corp","email":"admin@acme.com","password":"securepass123"}'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"org_slug":"acme-corp","email":"admin@acme.com","password":"securepass123"}'
# => { "access_token": "...", "refresh_token": "..." }
# Use only the access token in the Authorization header on protected routes.

# Refresh tokens
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<your-refresh-token>"}'

# Logout
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer <access-token>" \
  -d '{"refresh_token":"<refresh-token>"}'
```

### Users

```bash
# Get own profile
curl http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer <access-token>"

# Update profile
curl -X PUT http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{"full_name":"Jane Doe"}'
```

### RBAC

```bash
# Create a role
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer <access-token>" \
  -d '{"name":"editor","description":"Can read and write content"}'

# Assign permissions to role
curl -X POST http://localhost:8080/api/v1/roles/<role-id>/permissions \
  -H "Authorization: Bearer <access-token>" \
  -d '{"permissions":["users:read","roles:read"]}'

# Assign role to user
curl -X POST http://localhost:8080/api/v1/users/<user-id>/roles \
  -H "Authorization: Bearer <access-token>" \
  -d '{"role_id":"<role-id>"}'
```

### API Keys

```bash
# Create an API key (key shown only once)
curl -X POST http://localhost:8080/api/v1/api-keys \
  -H "Authorization: Bearer <access-token>" \
  -d '{"name":"CI pipeline","scopes":["users:read"]}'
# => { "key": "uk_abcdef...", ... }

# Use an API key
curl http://localhost:8080/api/v1/users/me \
  -H "X-API-Key: uk_abcdef..."
```

### Webhooks

```bash
# Register a webhook
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Authorization: Bearer <access-token>" \
  -d '{"url":"https://myapp.com/hooks/auth","events":["user.login","user.registered"]}'
# => { "secret": "whsec_...", ... }
```

Webhook payloads are HMAC-signed with `X-UniAuth-Signature: sha256=<hash>`.

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `DATABASE_URL` | — | PostgreSQL connection string (required) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `JWT_SECRET` | — | HMAC secret for JWTs (required, min 32 chars) |
| `ACCESS_TOKEN_DURATION` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_DURATION` | `168h` | Refresh token lifetime (7 days) |
| `RESET_TOKEN_DURATION` | `1h` | Password reset token lifetime |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per IP per minute |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `SMTP_HOST` | — | SMTP server for password reset delivery; leave empty to disable delivery without exposing reset tokens |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_FROM` | — | From address for emails |
| `APP_BASE_URL` | `http://localhost:8080` | Base URL for email links |

## Deployment

### Docker

```bash
docker run -d \
  -e DATABASE_URL="postgres://..." \
  -e REDIS_URL="redis://..." \
  -e JWT_SECRET="your-secret" \
  -p 8080:8080 \
  ghcr.io/osama1998h/uniauth:latest
```

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | None | Liveness probe |
| `GET` | `/ready` | None | Readiness probe |
| `POST` | `/api/v1/auth/register` | None | Register org + admin user |
| `POST` | `/api/v1/auth/login` | None | Login, returns token pair |
| `POST` | `/api/v1/auth/refresh` | None | Exchange refresh token |
| `POST` | `/api/v1/auth/logout` | JWT | Revoke session |
| `POST` | `/api/v1/auth/logout-all` | JWT | Revoke all sessions |
| `POST` | `/api/v1/auth/password/reset-request` | None | Request password reset email |
| `POST` | `/api/v1/auth/password/reset-confirm` | None | Confirm reset with token |
| `PUT` | `/api/v1/auth/password/change` | JWT | Change password |
| `GET` | `/api/v1/users/me` | JWT | Get own profile |
| `PUT` | `/api/v1/users/me` | JWT | Update own profile |
| `GET` | `/api/v1/users` | JWT | List org users |
| `GET` | `/api/v1/users/{id}` | JWT | Get user |
| `DELETE` | `/api/v1/users/{id}` | JWT | Deactivate user |
| `POST` | `/api/v1/users/{id}/roles` | JWT | Assign role to user |
| `GET` | `/api/v1/organizations/me` | JWT | Get own org |
| `PUT` | `/api/v1/organizations/me` | JWT | Update own org |
| `GET` | `/api/v1/roles` | JWT | List roles |
| `POST` | `/api/v1/roles` | JWT | Create role |
| `PUT` | `/api/v1/roles/{id}` | JWT | Update role |
| `DELETE` | `/api/v1/roles/{id}` | JWT | Delete role |
| `GET` | `/api/v1/roles/permissions` | JWT | List all built-in permissions |
| `POST` | `/api/v1/roles/{id}/permissions` | JWT | Assign permissions to role |
| `GET` | `/api/v1/api-keys` | JWT | List API keys |
| `POST` | `/api/v1/api-keys` | JWT | Create API key |
| `DELETE` | `/api/v1/api-keys/{id}` | JWT | Revoke API key |
| `GET` | `/api/v1/audit` | JWT | List audit logs |
| `GET` | `/api/v1/webhooks` | JWT | List webhooks |
| `POST` | `/api/v1/webhooks` | JWT | Create webhook |
| `PUT` | `/api/v1/webhooks/{id}` | JWT | Update webhook |
| `DELETE` | `/api/v1/webhooks/{id}` | JWT | Delete webhook |

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Go 1.24 |
| HTTP Router | [chi](https://github.com/go-chi/chi) |
| Database | PostgreSQL 16 (pgx/v5) |
| Cache | Redis 7 |
| Migrations | golang-migrate |
| JWT | golang-jwt/jwt v5 |
| Password hashing | bcrypt |
| Logging | log/slog (stdlib) |
| Config | Viper |

## Roadmap

- [ ] Email verification flow
- [ ] Multi-Factor Authentication (TOTP)
- [ ] OAuth2 provider (use UniAuth as your OAuth2 server)
- [ ] Social login (Google, GitHub)
- [ ] Admin dashboard API
- [ ] TypeScript + Python SDKs
- [ ] Prometheus metrics
- [x] Horizontal scaling guide (see [docs/horizontal-scaling.md](docs/horizontal-scaling.md))

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
