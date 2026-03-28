-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Organizations (multi-tenancy)
CREATE TABLE organizations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    slug       TEXT        NOT NULL UNIQUE,
    is_active  BOOLEAN     NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users
CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email            TEXT        NOT NULL,
    hashed_password  TEXT        NOT NULL,
    full_name        TEXT,
    is_active        BOOLEAN     NOT NULL DEFAULT true,
    is_superuser     BOOLEAN     NOT NULL DEFAULT false,
    email_verified_at TIMESTAMPTZ,
    last_login_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, email)
);

CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_org_id ON users (org_id);

-- Sessions (refresh tokens)
CREATE TABLE sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    refresh_token_hash TEXT        NOT NULL UNIQUE,
    user_agent         TEXT,
    ip_address         TEXT,
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Email verification tokens
CREATE TABLE email_verification_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Roles
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- Permissions
CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

-- Seed built-in permissions
INSERT INTO permissions (name, description) VALUES
    ('users:read',         'Read user data'),
    ('users:write',        'Create and update users'),
    ('users:delete',       'Deactivate users'),
    ('roles:read',         'Read roles and permissions'),
    ('roles:write',        'Create and update roles'),
    ('roles:delete',       'Delete roles'),
    ('apikeys:read',       'List API keys'),
    ('apikeys:write',      'Create API keys'),
    ('apikeys:delete',     'Revoke API keys'),
    ('audit:read',         'Read audit logs'),
    ('webhooks:read',      'List webhooks'),
    ('webhooks:write',     'Create and update webhooks'),
    ('webhooks:delete',    'Delete webhooks'),
    ('organizations:read', 'Read organization profile data'),
    ('organizations:write','Update organization profile data');

-- Role <-> Permission
CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- User <-> Role
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- API Keys (server-to-server auth)
CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    key_prefix  TEXT        NOT NULL,
    key_hash    TEXT        NOT NULL UNIQUE,
    scopes      TEXT[]      NOT NULL DEFAULT '{}',
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_keys_org_id ON api_keys (org_id);

-- Audit logs
CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID REFERENCES organizations (id) ON DELETE SET NULL,
    user_id       UUID REFERENCES users (id) ON DELETE SET NULL,
    action        TEXT        NOT NULL,
    resource_type TEXT,
    resource_id   TEXT,
    metadata      JSONB,
    ip_address    TEXT,
    user_agent    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_org_id    ON audit_logs (org_id);
CREATE INDEX idx_audit_logs_user_id   ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_action    ON audit_logs (action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);

-- Webhooks
CREATE TABLE webhooks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    url        TEXT        NOT NULL,
    events     TEXT[]      NOT NULL,
    secret     TEXT        NOT NULL,
    is_active  BOOLEAN     NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhooks_org_id ON webhooks (org_id);
