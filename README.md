# UniAuth

[![CI](https://github.com/osama1998H/uniauth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/osama1998H/uniauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Self-hosted auth backend for SaaS apps, internal tools, and multi-tenant APIs.

**UniAuth** is an API-first authentication and authorization service written in Go. It gives you organization-scoped JWT auth, RBAC, audit logs, webhook delivery, and API key lifecycle management in a single service backed by PostgreSQL and Redis.

> **Status:** Active development. UniAuth is strongest today as a self-hosted auth backend for your own APIs. OAuth/OIDC provider flows, MFA, social login, SDKs, and an admin UI are roadmap work.

## Why teams try it

- **Single Go service** backed by PostgreSQL and Redis
- **Multi-tenant by default** with isolated organizations, users, roles, and API keys
- **JWT sessions with rotation** for access and refresh tokens
- **Operational visibility** with audit logs, health endpoints, and webhook events
- **Deployable anywhere** with Docker, Helm, Kubernetes manifests, and generated Swagger/OpenAPI docs

## Best fit

Use UniAuth when:

- you want a self-hosted auth service that runs next to your application stack
- your backend already speaks REST/JSON and you want auth to stay API-first
- you need organization isolation, RBAC, auditability, and webhook hooks without adopting a full IAM suite

Consider alternatives when:

- you need hosted auth with wide SDK coverage, social login, and enterprise SSO today
- you need a full identity provider with OIDC/SAML federation or a polished admin console out of the box
- you need protected HTTP routes to accept scoped API keys today; UniAuth currently supports API-key issuance, revocation, and validation primitives, while protected routes are JWT-first

## Quick start

### 1. Clone the repo

```bash
git clone https://github.com/osama1998H/uniauth.git
cd uniauth
```

### 2. Configure the environment

```bash
cp .env.example .env
openssl rand -hex 32
```

Set the generated value as `JWT_SECRET` in `.env`.

### 3. Start the stack

```bash
docker compose up --build
```

UniAuth will:

- start PostgreSQL, Redis, and MailHog
- connect to the database
- run pending migrations on startup
- serve the API on `http://localhost:8080`

### 4. Verify the service is up

```bash
curl http://localhost:8080/health
```

Swagger UI is available at [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html). MailHog is available at [http://localhost:8025](http://localhost:8025).

## Try the core auth flow

The example password below satisfies UniAuth's current password policy: minimum 8 characters, at least one uppercase letter, one digit, and one special character.

```bash
# Register a new organization + first admin user.
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"org_name":"Acme Corp","email":"admin@acme.com","password":"StrongPass1!"}'

# Login with the same credentials.
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"org_slug":"acme-corp","email":"admin@acme.com","password":"StrongPass1!"}'

# Copy the access_token from the login response, then call a protected route.
curl http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer <access-token>"
```

## What you get today

- **JWT authentication** with short-lived access tokens and rotating refresh tokens
- **Multi-tenancy** with organization-scoped users, roles, sessions, audit logs, webhooks, and API keys
- **Role-based access control (RBAC)** with built-in permission names such as `users:read` and `roles:write`
- **API key lifecycle management** to issue, scope, revoke, and audit keys
- **Audit logs** for authentication and authorization events
- **Webhooks** for auth events with HMAC signatures
- **Password reset** via SMTP
- **Rate limiting** backed by Redis
- **Health and readiness endpoints** for orchestration
- **Scratch-based Docker image** and a single Go server binary

## Docs and deployment

- [Swagger UI](http://localhost:8080/swagger/index.html)
- [OpenAPI spec](docs/swagger.yaml)
- [Horizontal scaling guide](docs/horizontal-scaling.md)
- [Security report](docs/security-report.md)
- [Helm chart](helm/uniauth)
- [Kubernetes manifests](k8s)
- [Contributing guide](CONTRIBUTING.md)

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `TRUSTED_PROXY_CIDRS` | — | Comma-separated proxy CIDRs or IPs allowed to supply forwarded client IP headers |
| `DATABASE_URL` | — | PostgreSQL connection string (required) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `JWT_SECRET` | — | HMAC secret for JWTs (required, random 32+ chars) |
| `ACCESS_TOKEN_DURATION` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_DURATION` | `168h` | Refresh token lifetime (7 days) |
| `RESET_TOKEN_DURATION` | `1h` | Password reset token lifetime |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per IP per minute |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `SMTP_HOST` | — | SMTP server for password reset delivery |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_FROM` | — | From address for emails |
| `APP_BASE_URL` | `http://localhost:8080` | Base URL used in password-reset emails; point it at your frontend or recovery UI when applicable |

If UniAuth is deployed behind a reverse proxy or load balancer, set `TRUSTED_PROXY_CIDRS` to that proxy's CIDR or IP. If it is left empty, UniAuth ignores forwarded IP headers and uses the direct peer IP instead.

## API surface

Protected routes currently require `Authorization: Bearer <access-token>`. Refresh tokens are reserved for `/api/v1/auth/refresh` and the logout request body.

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
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

## Tech stack

| Layer | Technology |
| --- | --- |
| Language | Go 1.24 |
| HTTP Router | [chi](https://github.com/go-chi/chi) |
| Database | PostgreSQL 16 (`pgx/v5`) |
| Cache | Redis 7 |
| Migrations | golang-migrate |
| JWT | golang-jwt/jwt v5 |
| Password hashing | bcrypt |
| Logging | `log/slog` |
| Config | Viper |

## Roadmap

- [ ] Scoped API-key auth on protected routes
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
