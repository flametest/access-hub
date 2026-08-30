-- Access-Hub init schema (M1-M3, design doc v6)
-- Conventions (design.md §5):
--   * unique constraints are partial (WHERE deleted_at IS NULL) to coexist with soft delete
--   * username/email uniqueness and lookups are lower()-normalized
--   * grant relations carry granted_by/granted_at/expires_at (NULL = never expires)

CREATE TABLE orgs
(
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version    BIGINT       NOT NULL DEFAULT 0,
    key        VARCHAR(64)  NOT NULL,
    name       VARCHAR(255) NOT NULL,
    status     VARCHAR(16)  NOT NULL DEFAULT 'active', -- active | disabled
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_orgs_key ON orgs (key) WHERE deleted_at IS NULL;

-- org_members is governance-only (owner/admin manage the org itself);
-- business membership is derived from holding an account in an org-owned app.
CREATE TABLE org_members
(
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version    BIGINT      NOT NULL DEFAULT 0,
    org_id     UUID        NOT NULL,
    user_id    UUID        NOT NULL, -- soft-FK to users.id
    org_role   VARCHAR(16) NOT NULL DEFAULT 'member', -- owner | admin | member
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_org_members_org_user ON org_members (org_id, user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_org_members_user ON org_members (user_id) WHERE deleted_at IS NULL;

-- users = primary identity (Company ID): holds portal credentials only.
CREATE TABLE users
(
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version              BIGINT      NOT NULL DEFAULT 0,
    username             VARCHAR(64) NOT NULL,
    email                VARCHAR(255) NOT NULL,
    email_verified       BOOLEAN     NOT NULL DEFAULT FALSE,
    password_hash        TEXT, -- NULL = auto-provisioned, portal login blocked until set
    nickname             VARCHAR(255),
    avatar_url           TEXT,
    status               VARCHAR(16) NOT NULL DEFAULT 'active', -- active | disabled
    must_change_password BOOLEAN     NOT NULL DEFAULT FALSE,
    last_login_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at           TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_users_username ON users (LOWER(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_email ON users (LOWER(email)) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email ON users (LOWER(email));

-- accounts = workspace (per-app) accounts: independent password + roles;
-- identity_id is NOT NULL by design (v6: always bound to a primary identity,
-- auto-created when missing). Sub-account email != identity email is the norm.
CREATE TABLE accounts
(
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version       BIGINT       NOT NULL DEFAULT 0,
    identity_id   UUID         NOT NULL, -- soft-FK to users.id
    app_id        UUID         NOT NULL, -- soft-FK to apps.id
    email         VARCHAR(255) NOT NULL,
    username      VARCHAR(64),
    password_hash TEXT        NOT NULL,
    display_name  VARCHAR(255),
    status        VARCHAR(32) NOT NULL DEFAULT 'pending_activation', -- pending_activation | active | disabled
    source        VARCHAR(16) NOT NULL DEFAULT 'invite', -- invite | provisioned
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at    TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_accounts_app_email ON accounts (app_id, LOWER(email)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_accounts_app_username ON accounts (app_id, username) WHERE deleted_at IS NULL AND username IS NOT NULL;
CREATE INDEX idx_accounts_identity ON accounts (identity_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_accounts_app ON accounts (app_id) WHERE deleted_at IS NULL;

CREATE TABLE invitations
(
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version             BIGINT       NOT NULL DEFAULT 0,
    app_id              UUID         NOT NULL,
    email               VARCHAR(255) NOT NULL,
    role_ids            JSONB        NOT NULL DEFAULT '[]',
    invited_by          UUID         NOT NULL, -- admin account id
    code_hash           VARCHAR(128) NOT NULL,
    expires_at          TIMESTAMPTZ  NOT NULL,
    accepted_at         TIMESTAMPTZ,
    accepted_account_id UUID,
    status              VARCHAR(16)  NOT NULL DEFAULT 'pending', -- pending | accepted | revoked | expired
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX idx_invitations_app_email ON invitations (app_id, LOWER(email));
CREATE INDEX idx_invitations_status ON invitations (status);
CREATE INDEX idx_invitations_code_hash ON invitations (code_hash);

CREATE TABLE apps
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version     BIGINT       NOT NULL DEFAULT 0,
    key         VARCHAR(64)  NOT NULL,
    org_id      UUID, -- NULL = platform app (e.g. admin console)
    name        VARCHAR(255) NOT NULL,
    type        VARCHAR(16)  NOT NULL DEFAULT 'web', -- web | native | service
    description TEXT,
    logo_url    TEXT,
    status      VARCHAR(16)  NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_apps_key ON apps (key) WHERE deleted_at IS NULL;
CREATE INDEX idx_apps_org ON apps (org_id) WHERE deleted_at IS NULL;

CREATE TABLE resources
(
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version    BIGINT       NOT NULL DEFAULT 0,
    app_id     UUID         NOT NULL,
    parent_id  UUID, -- tree; NULL = root
    type       VARCHAR(16)  NOT NULL, -- menu | api | button
    code       VARCHAR(128) NOT NULL, -- permission code, exact match (no wildcards)
    name       VARCHAR(255) NOT NULL,
    sort       INT          NOT NULL DEFAULT 0,
    status     VARCHAR(16)  NOT NULL DEFAULT 'active',
    visible    BOOLEAN      NOT NULL DEFAULT TRUE, -- menu only
    icon       VARCHAR(128), -- menu only
    method     VARCHAR(8),  -- api only
    route_path VARCHAR(255), -- api only
    extra      JSONB,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_resources_app_code ON resources (app_id, code) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_resources_app_route ON resources (app_id, method, route_path)
    WHERE deleted_at IS NULL AND method IS NOT NULL AND route_path IS NOT NULL;
CREATE INDEX idx_resources_app_type ON resources (app_id, type) WHERE deleted_at IS NULL;
CREATE INDEX idx_resources_parent ON resources (parent_id);

CREATE TABLE roles
(
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version    BIGINT       NOT NULL DEFAULT 0,
    app_id     UUID         NOT NULL,
    code       VARCHAR(64)  NOT NULL,
    name       VARCHAR(255) NOT NULL,
    scope      VARCHAR(16)  NOT NULL DEFAULT 'app', -- app | global
    built_in   BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_roles_app_code ON roles (app_id, code) WHERE deleted_at IS NULL;

CREATE TABLE role_resources
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version     BIGINT      NOT NULL DEFAULT 0,
    role_id     UUID        NOT NULL,
    resource_id UUID        NOT NULL,
    effect      VARCHAR(16) NOT NULL DEFAULT 'allow', -- deny reserved (M6)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_role_resources ON role_resources (role_id, resource_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_role_resources_resource ON role_resources (resource_id);

CREATE TABLE account_roles
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version     BIGINT       NOT NULL DEFAULT 0,
    account_id  UUID         NOT NULL,
    role_id     UUID         NOT NULL,
    granted_by  UUID, -- admin account id
    granted_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMPTZ, -- NULL = never
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_account_roles ON account_roles (account_id, role_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_account_roles_role ON account_roles (role_id);

CREATE TABLE account_grants
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version     BIGINT       NOT NULL DEFAULT 0,
    account_id  UUID         NOT NULL,
    resource_id UUID         NOT NULL,
    granted_by  UUID,
    granted_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMPTZ, -- NULL = never
    effect      VARCHAR(16)  NOT NULL DEFAULT 'allow',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_account_grants ON account_grants (account_id, resource_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_account_grants_resource ON account_grants (resource_id);

-- sessions: refresh-token records. Rotation is in-place (same row: new hash,
-- rotation_count++). Reuse of a replaced hash => revoke whole session.
CREATE TABLE sessions
(
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version            BIGINT       NOT NULL DEFAULT 0,
    user_id            UUID         NOT NULL, -- owning identity (portal user)
    scope              VARCHAR(16)  NOT NULL DEFAULT 'identity', -- identity | account
    account_id         UUID, -- set when scope=account (app token refresh)
    app_id             UUID, -- login-entry app
    refresh_token_hash VARCHAR(128) NOT NULL,
    device             VARCHAR(255),
    ip                 VARCHAR(64),
    last_used_at       TIMESTAMPTZ,
    rotation_count     BIGINT       NOT NULL DEFAULT 0,
    expires_at         TIMESTAMPTZ  NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at         TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_sessions_token_hash ON sessions (refresh_token_hash) WHERE deleted_at IS NULL;
CREATE INDEX idx_sessions_user ON sessions (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_sessions_account ON sessions (account_id) WHERE deleted_at IS NULL;

CREATE TABLE audit_logs
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version     BIGINT       NOT NULL DEFAULT 0,
    actor_type  VARCHAR(16)  NOT NULL, -- identity | account | system
    actor_id    UUID,
    org_id      UUID, -- context, nullable
    action      VARCHAR(64)  NOT NULL,
    target_type VARCHAR(64),
    target_id   UUID,
    detail      JSONB,
    ip          VARCHAR(64),
    user_agent  TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMPTZ
);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs (actor_type, actor_id);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
