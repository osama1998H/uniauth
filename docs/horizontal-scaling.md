# Horizontal Scaling Guide

UniAuth is designed to run as multiple stateless instances behind a load balancer. This guide explains what makes it safe to scale horizontally and how to deploy it that way.

---

## How UniAuth Scales

UniAuth keeps **no instance-local state**. All shared state lives in two external services:

| State | Where | Notes |
|-------|-------|-------|
| Users, orgs, roles, sessions | PostgreSQL | All instances share one DB |
| Rate-limit counters | Redis | Atomic `INCR`, safe across instances |
| Revoked access token JTIs | Redis | Blacklist checked on every authenticated request |
| API keys | PostgreSQL | Validated on every request |

Because every request is fully self-contained, any instance can handle any request at any time. There are no sticky sessions or affinity requirements.

---

## Prerequisites

### External PostgreSQL

Do not use the bundled single-container Postgres when running multiple app replicas. Use a managed service (AWS RDS, GCP Cloud SQL, Azure Database, Supabase, etc.) or a properly clustered self-hosted Postgres.

```
DATABASE_URL=postgres://user:pass@your-postgres-host:5432/uniauth?sslmode=require
```

Run migrations once during deploy, not on every startup:

```bash
make migrate-up
```

### External Redis

Similarly, use a managed Redis (AWS ElastiCache, GCP Memorystore, Redis Cloud, etc.) or a Redis Sentinel / Cluster setup.

```
REDIS_URL=redis://:password@your-redis-host:6379/0
```

Redis is used for rate limiting and access token blacklisting. If Redis is temporarily unavailable:
- Rate limiting is **skipped** (requests are allowed — graceful degradation)
- Blacklist checks are **skipped** (already-revoked tokens may be accepted until Redis recovers)

This means Redis is **not** a hard availability dependency, but it should be highly available in production.

### Shared JWT Secret

Every instance must use the **same** `JWT_SECRET`. Tokens are signed with HMAC-SHA256; a token signed by one instance must be verifiable by any other.

```
JWT_SECRET=your-secret-minimum-32-characters-long
```

Never rotate this secret without a coordinated rollout strategy — all existing tokens become invalid immediately.

---

## Token Lifecycle in a Multi-Instance Deployment

### Login / Token Refresh

Each instance can issue tokens independently. Sessions are written to PostgreSQL, so any instance can validate a refresh token.

### Logout / Password Change

When a user logs out or changes their password, UniAuth:

1. Revokes the session in PostgreSQL (invalidates the refresh token for all instances)
2. Blacklists the current access token JTI in Redis with the remaining TTL

The blacklist entry is checked by the `JWTAuth` middleware on every subsequent authenticated request across all instances. This ensures that a user who logs out cannot continue using their short-lived access token on a different instance.

### Access Token Expiry

Access tokens have a short TTL (default 15 minutes). Even without Redis, a blacklisted token expires naturally within that window. The Redis blacklist entry TTL matches the remaining token lifetime — it cleans itself up automatically.

---

## Kubernetes Deployment

UniAuth is stateless and works well with Kubernetes. Deploy it with any standard Kubernetes manifests or your preferred tooling.

### Health and Readiness Probes

Kubernetes uses these endpoints automatically:

| Endpoint | Type | Checks |
|----------|------|--------|
| `GET /health` | Liveness | Process is alive (always 200) |
| `GET /ready` | Readiness | PostgreSQL + Redis reachable (503 if either is down) |

During a rolling deploy, new pods only receive traffic after `/ready` returns 200, ensuring zero-downtime upgrades.

### Rolling Updates

The default Kubernetes rolling update strategy works correctly because:
- Requests can be handled by old or new instances simultaneously
- There is no shared in-memory state to migrate
- Database schema changes must be backwards-compatible during the rollout window (old instances must still work against the new schema until fully replaced)

---

## Docker Compose (Multi-Instance Example)

For local testing or simple deployments, you can run multiple app instances behind an Nginx or Traefik reverse proxy:

```yaml
# docker-compose.scale.yml
version: "3.8"
services:
  app:
    image: ghcr.io/osama1998h/uniauth:latest
    deploy:
      replicas: 3
    environment:
      DATABASE_URL: postgres://postgres:postgres@postgres:5432/uniauth?sslmode=disable
      REDIS_URL: redis://redis:6379/0
      JWT_SECRET: your-secret-minimum-32-characters
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: uniauth
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

volumes:
  pgdata:
```

Scale with Docker Compose:

```bash
docker compose -f docker-compose.scale.yml up --scale app=3
```

---

## Session Clustering

Sessions are stored in PostgreSQL and are fully distributed by design:

- `CreateSession` — called when a user logs in or refreshes tokens; writes to DB
- `GetSessionByTokenHash` — called when validating a refresh token; reads from DB
- `RevokeSession` / `RevokeAllUserSessions` — called on logout or password change; updates DB

Any instance can create, read, or revoke any session. No session affinity is needed.

---

## Rate Limiting

Rate limiting uses a Redis sliding-window counter keyed on the client IP address. Because all instances share the same Redis, the limit is enforced globally across the entire cluster, not per-instance.

Default: 60 requests per IP per minute (configurable via `RATE_LIMIT_PER_MINUTE`).

---

## Webhook Delivery

Webhooks are dispatched asynchronously (fire-and-forget goroutines) from the instance that handled the triggering request. There is **no distributed coordination** for webhook delivery — if you are running multiple instances, only the instance that processed the event will dispatch the webhook.

Current limitations:
- No retry on delivery failure
- No delivery log

If your webhook consumers require strong at-least-once delivery guarantees, implement idempotency handling on the receiver side using the `X-UniAuth-Event` header and the `delivered_at` timestamp in the payload.

---

## Configuration Reference

All instances must share these values:

| Variable | Requirement |
|----------|-------------|
| `JWT_SECRET` | Identical on all instances; min 32 chars |
| `DATABASE_URL` | Points to the same PostgreSQL instance/cluster |
| `REDIS_URL` | Points to the same Redis instance/cluster |
| `ACCESS_TOKEN_DURATION` | Should be consistent (default `15m`) |
| `REFRESH_TOKEN_DURATION` | Should be consistent (default `168h`) |

Per-instance variables (can differ):

| Variable | Notes |
|----------|-------|
| `PORT` | Each instance may listen on a different port if not using Kubernetes |
| `ENVIRONMENT` | Can differ between staging and production |

---

## Checklist

Before going to production with multiple instances:

- [ ] External PostgreSQL with connection pooling (e.g. PgBouncer)
- [ ] External Redis with persistence or Sentinel for HA
- [ ] `JWT_SECRET` set identically on all instances via a secret manager
- [ ] `DATABASE_URL` and `REDIS_URL` pointing at the shared services
- [ ] Migrations run exactly once before app rollout (`make migrate-up`)
- [ ] Load balancer health check configured to use `GET /ready`
- [ ] Rolling update strategy enabled (default in Kubernetes)
