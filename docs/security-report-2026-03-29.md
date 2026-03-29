# 1. Executive Summary

This review found several real security weaknesses in the current codebase, but no evidence-backed Critical issue in the checked-in snapshot.

The highest-signal findings are business-logic and state-transition flaws in the auth/RBAC layer:

- Role-permission updates are documented as replacement, but the implementation is additive only. A privilege downgrade can silently fail, leaving old permissions active.
- Refresh-token rotation is not atomic. The same refresh token can mint multiple new sessions under concurrency.
- Password-reset and email-verification tokens are not consumed atomically, so concurrent replay remains possible.
- User deactivation and password-change flows do not consistently revoke all effective auth state.

Lower-severity issues remain in audit durability, readiness error leakage, and CI/deployment hardening.

Evidence basis:

- Read-only review across router, handlers, middleware, services, repositories, migrations, Docker/Kubernetes/Helm, and CI.
- Local verification: `GOCACHE=/tmp/uniauth-gocache go test ./...` passed on March 29, 2026.
- No live environment access was available, so ingress, TLS termination, secret delivery, network policy, and dependency-vulnerability status still require runtime review.

# 2. Architecture and Attack Surface

## Architecture

- Entry point: `cmd/server/main.go`
- HTTP/router and middleware wiring: `internal/api/router.go`
- Business logic: `internal/service/*.go`
- Persistence: `internal/repository/postgres/*.go`
- Cache/rate-limit/token blacklist: `internal/repository/cache/redis.go`
- Token primitives: `pkg/token/*.go`

## Trust boundaries

- Untrusted client input enters through JSON bodies, path params, query params, headers, and proxy-supplied client IP headers.
- Auth state is split across signed JWTs, PostgreSQL session rows, Redis blacklist keys, password-reset tokens, email-verification tokens, API keys, and RBAC assignments.
- External egress goes to SMTP and webhook destinations.

## Public entry points

- `/health`
- `/ready`
- `/swagger/*`
- `/api/v1/auth/register`
- `/api/v1/auth/login`
- `/api/v1/auth/refresh`
- `/api/v1/auth/password/reset-request`
- `/api/v1/auth/password/reset-confirm`
- `/api/v1/auth/email/verify-confirm`

## Protected entry points

- JWT-only auth flows:
  - `/api/v1/auth/logout`
  - `/api/v1/auth/logout-all`
  - `/api/v1/auth/password/change`
  - `/api/v1/auth/email/verify-request`
- JWT + permission-protected admin/data flows:
  - `/api/v1/users/*`
  - `/api/v1/organizations/me`
  - `/api/v1/roles/*`
  - `/api/v1/api-keys/*`
  - `/api/v1/audit`
  - `/api/v1/webhooks/*`

## Sensitive assets

- `JWT_SECRET`
- Access and refresh tokens
- Password-reset and email-verification tokens
- User passwords
- API keys
- Webhook secrets
- RBAC assignments and permission mappings
- Audit logs

## Assumptions and unknowns

- I reviewed the repository state only, not a running production environment.
- I did not perform live race-condition exploitation; the concurrency findings are based on concrete read-then-update code paths that need dynamic confirmation under load.
- I did not run `govulncheck`, because it is not installed in this workspace.

# 3. Prioritized Review Plan

I prioritized the review in this order:

1. Authentication/session state transitions
2. Authorization and privilege revocation
3. One-time token handling
4. Auditability and incident response support
5. Operational exposure and infrastructure defaults
6. Input-hardening and abuse-resistance gaps

Repository-specific checklist:

- Verify JWT access/refresh separation and blacklist behavior.
- Inspect session rotation, logout, password-change, and deactivation flows for revocation gaps.
- Inspect RBAC assignment/update flows for privilege persistence and cross-tenant bugs.
- Inspect password-reset and email-verification token lifecycle for replay/race issues.
- Inspect public endpoints for rate-limit placement, readiness leakage, and request parsing hardening.
- Inspect Docker/Kubernetes/Helm/CI for unsafe defaults and mutable supply-chain inputs.

# 4. Findings List

## Finding 1: Role permission “replacement” is additive only, so privilege downgrades can silently fail

- Title: Role permission replacement does not remove stale permissions
- Severity: Medium
- Confidence: High
- Affected files and functions:
  - `internal/api/handlers/roles.go` - `AssignPermissions`
  - `internal/service/rbac.go` - `AssignPermissions`
  - `internal/repository/postgres/roles.go` - `AssignPermissionToRole`, `RemovePermissionFromRole`
- Evidence from the code:
  - The handler documents this endpoint as: “Replaces the permission set of the specified role with the provided list.”
  - The service only loops over the requested permissions and calls `AssignPermissionToRole`.
  - There is a repository helper to remove permissions from a role, but it is never called by the update flow.
- Why it is a security issue:
  - Administrative privilege reduction is a security control. If an attempted downgrade silently leaves old permissions active, users can retain access that administrators believe they removed.
- Realistic attack scenario:
  - An administrator removes `users:delete` or `apikeys:write` from a role after an incident. The API returns success, but the old permission remains attached. Users with that role keep their previous access.
- Preconditions required for exploitation:
  - The affected user already holds a role whose permissions are later “updated” through this endpoint.
- Recommended fix:
  - Make permission updates transactional and authoritative:
    - read current permissions
    - compute additions and removals
    - apply both in one transaction
  - Align the API contract and tests with true replace semantics.
- How to verify the fix:
  - Add an integration test that starts with a role having permissions `A,B`, updates it to `A`, and proves `B` is no longer authorized afterward.
- Category:
  - OWASP A01: Broken Access Control

## Finding 2: Refresh-token rotation is non-atomic and can mint multiple live sessions from one token

- Title: Concurrent refresh requests can bypass single-use rotation
- Severity: Medium
- Confidence: High
- Affected files and functions:
  - `internal/service/auth.go` - `Refresh`
  - `internal/repository/postgres/sessions.go` - `GetSessionByTokenHash`, `RevokeSession`, `CreateSession`
- Evidence from the code:
  - `Refresh` reads the session, checks validity, revokes it, then creates a new session.
  - `RevokeSession` is an unconditional update and does not fail if the row was already revoked.
  - There is no transaction, row lock, or compare-and-swap condition tying “still unrevoked” to session issuance.
- Why it is a security issue:
  - Refresh rotation is meant to make a stolen refresh token single-use. In the current flow, concurrent replay can produce multiple valid child sessions before the old token is effectively retired.
- Realistic attack scenario:
  - An attacker steals a refresh token and races the legitimate client. Both refresh requests succeed, and both parties receive fresh token pairs.
- Preconditions required for exploitation:
  - The attacker has a valid refresh token and can race the holder before or during first refresh use.
- Recommended fix:
  - Make refresh rotation atomic:
    - `SELECT ... FOR UPDATE` / transaction, or
    - one `UPDATE ... WHERE revoked_at IS NULL AND expires_at > now() RETURNING ...` gate,
    - then create exactly one replacement session in the same transaction.
  - Consider storing a rotation counter or family ID to support replay detection.
- How to verify the fix:
  - Add a concurrency test with two simultaneous refresh calls against the same token and assert that only one succeeds.
- Category:
  - OWASP A07: Identification and Authentication Failures

## Finding 3: Password-reset and email-verification tokens are not consumed atomically

- Title: One-time tokens can be replayed under concurrency
- Severity: Medium
- Confidence: Medium
- Affected files and functions:
  - `internal/service/auth.go` - `ConfirmPasswordReset`, `ConfirmEmailVerification`
  - `internal/repository/postgres/password_resets.go` - `GetPasswordResetToken`, `MarkPasswordResetTokenUsed`
  - `internal/repository/postgres/email_verifications.go` - `GetEmailVerificationToken`, `MarkEmailVerificationTokenUsed`
- Evidence from the code:
  - Both flows first read a token row where `used_at IS NULL`, then mutate user state, then mark the token as used in a separate query.
  - The “mark used” query does not guard on `used_at IS NULL` and does not return whether the update actually won a race.
- Why it is a security issue:
  - One-time tokens should be single-consumption primitives. The current read-then-mark pattern allows concurrent reuse windows.
- Realistic attack scenario:
  - Two confirmation requests using the same reset token arrive at nearly the same time. Both pass the initial lookup before either marks the token used.
- Preconditions required for exploitation:
  - The attacker already has the same token value, or can replay the request concurrently.
- Recommended fix:
  - Consume tokens atomically in the database:
    - `UPDATE ... SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING user_id, ...`
  - Perform the rest of the state change in the same transaction.
- How to verify the fix:
  - Add concurrency tests for both reset and email-verification confirmation paths showing only one request can win.
- Category:
  - OWASP A07: Identification and Authentication Failures

## Finding 4: User deactivation and password-change flows do not consistently revoke all effective auth state

- Title: Revocation gaps leave existing auth state usable longer than intended
- Severity: Medium
- Confidence: High
- Affected files and functions:
  - `internal/service/user.go` - `Deactivate`
  - `internal/repository/postgres/users.go` - `DeactivateUser`
  - `internal/api/middleware/auth.go` - `JWTAuth`
  - `internal/service/auth.go` - `ChangePassword`
  - `internal/repository/postgres/sessions.go` - `RevokeAllUserSessions`
- Evidence from the code:
  - `Deactivate` marks the user inactive but does not revoke session rows.
  - `JWTAuth` trusts the access token plus blacklist state only; it does not re-check user `is_active`.
  - `ChangePassword` updates the password, then calls `RevokeAllUserSessions`, but explicitly ignores any error from that revocation step.
- Why it is a security issue:
  - After deactivation, a previously issued access token remains valid until expiry.
  - After password change, the caller receives success even if old refresh sessions were not revoked.
- Realistic attack scenario:
  - An admin deactivates a compromised user expecting immediate cutoff. The attacker continues using the existing access token until it expires.
  - A password is changed after suspected compromise, but a transient DB error prevents refresh-session revocation, leaving old sessions alive.
- Preconditions required for exploitation:
  - The attacker already has an active access token or refresh session for the account.
- Recommended fix:
  - On deactivation:
    - revoke all sessions
    - decide whether immediate access-token invalidation is required, then implement token versioning, user-state cache checks, or a broader revocation strategy
  - On password change:
    - treat session-revocation failure as a hard error or wrap the state change in a transaction that preserves the intended security semantics
- How to verify the fix:
  - Add tests proving deactivation revokes refresh sessions.
  - Add tests proving password change fails closed if session revocation fails, or that revocation and password update are atomic.
- Category:
  - OWASP A07: Identification and Authentication Failures

## Finding 5: Email verification state remains trusted after a user changes email

- Title: `email_verified_at` survives email changes
- Severity: Medium
- Confidence: High
- Affected files and functions:
  - `internal/api/handlers/users.go` - `UpdateMe`
  - `internal/service/user.go` - `UpdateProfile`
  - `internal/repository/postgres/users.go` - `UpdateUser`
  - `internal/service/auth.go` - `RequestEmailVerification`
- Evidence from the code:
  - Profile updates can change `email`.
  - `UpdateUser` updates `email` but does not clear `email_verified_at`.
  - `RequestEmailVerification` refuses to send a new verification if `EmailVerifiedAt != nil`.
- Why it is a security issue:
  - The verification flag stops representing control of the current email address once the address changes.
- Realistic attack scenario:
  - A user verifies one mailbox, changes the account email to another address, and the system continues to treat the new address as verified.
- Preconditions required for exploitation:
  - The account already had a verified email.
- Recommended fix:
  - Clear `email_verified_at` when `email` changes.
  - Prefer a staged pending-email flow so the new address is only committed after verification.
- How to verify the fix:
  - Add a test proving an email change clears verification state and allows a fresh verification request for the new address.
- Category:
  - OWASP A04: Insecure Design

## Finding 6: Security audit coverage is incomplete and audit logging is lossy under pressure

- Title: Audit trail can be incomplete during auth events and burst load
- Severity: Low
- Confidence: High
- Affected files and functions:
  - `internal/domain/audit.go`
  - `internal/service/audit.go`
  - `internal/service/async.go`
  - `internal/service/auth.go` - `Logout`, `LogoutAll`, `ConfirmPasswordReset`
- Evidence from the code:
  - Domain constants exist for `user.logout` and `user.password_reset`, but the corresponding auth flows do not emit them.
  - Audit writes go through a bounded async queue.
  - When the queue is full, events are dropped and only a warning is logged.
- Why it is a security issue:
  - Missing or dropped security events weaken incident response and forensic confidence.
- Realistic attack scenario:
  - During a noisy auth event or dependency slowdown, audit events are silently dropped, leaving investigators with an incomplete timeline.
- Preconditions required for exploitation:
  - Elevated audit volume or slower audit-log persistence.
- Recommended fix:
  - Emit missing auth audit events.
  - Make security-critical audit writes durable or fail loudly instead of silently dropping them.
- How to verify the fix:
  - Add tests for logout/logout-all/password-reset audit creation and queue-pressure behavior.
- Category:
  - OWASP A09: Security Logging and Monitoring Failures

## Finding 7: `/ready` is public, unthrottled, and leaks backend error strings

- Title: Readiness endpoint exposes internal failure details
- Severity: Low
- Confidence: High
- Affected files and functions:
  - `internal/api/router.go`
  - `internal/api/handlers/health.go` - `Ready`
- Evidence from the code:
  - `/ready` is registered outside `/api/v1`, so it is not covered by the API rate limiter.
  - Each request pings both PostgreSQL and Redis.
  - Failure responses include `"error: " + err.Error()`.
- Why it is a security issue:
  - Unauthenticated callers can learn backend failure details and repeatedly force dependency health checks.
- Realistic attack scenario:
  - During an outage, an external caller polls `/ready` and collects backend error details while generating extra dependency traffic.
- Preconditions required for exploitation:
  - The endpoint is reachable by untrusted callers.
- Recommended fix:
  - Return generic component states only.
  - Restrict `/ready` to probe traffic or add caching/rate limiting.
- How to verify the fix:
  - Add a handler test proving dependency error strings are not reflected in the response.
- Category:
  - OWASP A05: Security Misconfiguration

## Finding 8: CI and deployment inputs remain partially mutable or unverified

- Title: Build and deployment path still trusts mutable artifacts
- Severity: Low
- Confidence: High
- Affected files and functions:
  - `.github/workflows/ci.yml`
  - `helm/uniauth/values.yaml`
  - `k8s/deployment.yaml`
- Evidence from the code:
  - CI downloads `migrate` via `curl | tar` with no integrity verification.
  - `golangci-lint-action` is configured with `version: latest`.
  - Kubernetes/Helm image tags still use `latest`.
- Why it is a security issue:
  - Mutable inputs weaken build reproducibility and raise supply-chain risk.
- Realistic attack scenario:
  - A compromised upstream release artifact or retagged container image changes what CI or deployment executes without a repository code change.
- Preconditions required for exploitation:
  - Upstream compromise or artifact drift.
- Recommended fix:
  - Pin versions and preferably digests.
  - Verify downloaded artifacts with checksums or signatures.
  - Avoid `latest` in CI and deployment artifacts.
- How to verify the fix:
  - Add policy checks that reject mutable tags and unverified downloads.
- Category:
  - OWASP A06: Vulnerable and Outdated Components

## Dead Ends / False Positives

- I did not find a current SQL injection path. Repository queries are parameterized.
- I did not find file-upload, shell-exec, or server-side template-execution surfaces in the current codebase.
- Webhook delivery is better-than-average from an SSRF perspective: HTTPS-only, no embedded credentials, proxy disabled, redirect following disabled, and private/link-local/loopback targets rejected.
- API-key scopes are currently stored but not enforced in the router because API-key auth is not wired into protected routes. That is a product gap, not an active authorization bypass in the current route graph.
- The repository contains ingress examples and deployment templates, but I could not verify how production TLS termination is actually implemented. I did not score TLS configuration as a confirmed code finding without environment evidence.

# 5. Remediation Roadmap

## 1. Immediate hotfixes

- Fix role-permission replacement semantics so privilege revocation actually removes stale permissions.
  - Complexity: Medium
  - Regression risk: Medium
  - Suggested order: 1
- Make refresh-token rotation atomic.
  - Complexity: Medium
  - Regression risk: Medium
  - Suggested order: 2
- Make password-reset and email-verification token consumption atomic.
  - Complexity: Medium
  - Regression risk: Medium
  - Suggested order: 3

## 2. Short-term hardening

- Fix deactivation/password-change revocation gaps.
  - Complexity: Medium
  - Regression risk: Medium
  - Suggested order: 4
- Clear verification state on email change and implement a pending-email verification flow.
  - Complexity: Medium
  - Regression risk: Medium
  - Suggested order: 5
- Sanitize and optionally restrict `/ready`.
  - Complexity: Small
  - Regression risk: Low
  - Suggested order: 6

## 3. Structural improvements

- Make security-critical audit events durable and complete.
  - Complexity: Medium
  - Regression risk: Medium
  - Suggested order: 7
- Harden request parsing centrally:
  - strict JSON decoding
  - body-size limits
  - trailing-content rejection
  - Complexity: Small-Medium
  - Regression risk: Low-Medium
  - Suggested order: 8
- Improve abuse controls with account-centric throttling on login and reset flows.
  - Complexity: Medium
  - Regression risk: Medium
  - Suggested order: 9
- Pin mutable CI/deployment artifacts and add integrity verification.
  - Complexity: Small-Medium
  - Regression risk: Low
  - Suggested order: 10

# 6. Verification Checklist

- Run `GOCACHE=/tmp/uniauth-gocache go test ./...`.
- Add an RBAC regression test proving a permission removed from a role is no longer effective.
- Add a refresh-token concurrency test proving only one of two simultaneous refresh requests can succeed.
- Add reset-token and email-verification concurrency tests proving single-consumption semantics.
- Add tests proving deactivation revokes sessions and password change fails closed if session revocation fails.
- Add a regression test proving email change clears verification state.
- Add audit tests for logout, logout-all, and password reset.
- Add readiness tests proving backend error strings are not returned to unauthenticated clients.
- Run `govulncheck ./...` once the tool is available.
- Review rendered deployment manifests for immutable image references and verified artifact installs.

# 7. Open Questions / Assumptions

- Does production require immediate cutoff for deactivated users, or is “access token remains valid until TTL expiry” currently accepted?
- Is the intended API contract for `POST /api/v1/roles/{id}/permissions` true replacement or additive assignment? The handler documentation says replacement, and I treated that as the security expectation.
- How is TLS enforced in the real production deployment: ingress TLS, external load balancer termination, service mesh, or something else?
- Are Docker/Compose deployments expected to be local-development-only, or are they supported operational targets?
- `govulncheck` and runtime SCA were not available in this session, so dependency advisories remain unverified.
