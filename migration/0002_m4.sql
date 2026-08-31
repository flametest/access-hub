-- M4: OAuth2/OIDC Provider + TOTP two-factor (design.md §12)

-- accounts.password_hash becomes nullable: OIDC auto-provisioned workspace
-- accounts cannot password-login until activated via email code (v6 decision:
-- sub-accounts keep independent passwords, but SSO-provisioned ones start
-- passwordless and may activate later).
ALTER TABLE accounts ALTER COLUMN password_hash DROP NOT NULL;

-- OAuth2/OIDC clients belong to an app. Confidential clients authenticate with
-- a secret (stored hashed); public clients (SPA/native) MUST use PKCE.
CREATE TABLE oauth_clients
(
    id          VARCHAR(48) PRIMARY KEY, -- client_id, generated "cli_<16hex>"
    version     BIGINT       NOT NULL DEFAULT 0,
    app_id      UUID         NOT NULL,
    name        VARCHAR(255) NOT NULL,
    client_type VARCHAR(16)  NOT NULL DEFAULT 'confidential', -- confidential | public
    secret_hash VARCHAR(128), -- NULL for public clients
    grant_types JSONB        NOT NULL DEFAULT '[]', -- authorization_code | refresh_token | client_credentials
    redirect_uris JSONB      NOT NULL DEFAULT '[]',
    scopes      JSONB        NOT NULL DEFAULT '[]',
    status      VARCHAR(16)  NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMPTZ
);
CREATE INDEX idx_oauth_clients_app ON oauth_clients (app_id) WHERE deleted_at IS NULL;

-- Refresh tokens issued by the OAuth2 token endpoint. Rotation is in-place
-- (same row: new hash, rotation_count++); presenting a replaced hash revokes
-- the whole token family (same semantics as sessions).
CREATE TABLE oauth_refresh_tokens
(
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version        BIGINT       NOT NULL DEFAULT 0,
    client_id      VARCHAR(48)  NOT NULL,
    user_id        UUID, -- identity subject (authorization_code flows)
    account_id     UUID, -- account subject when resolved (sub=account:{id})
    token_hash     VARCHAR(128) NOT NULL,
    scope          TEXT         NOT NULL DEFAULT '',
    rotation_count BIGINT       NOT NULL DEFAULT 0,
    last_used_at   TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ  NOT NULL,
    revoked_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_oauth_refresh_hash ON oauth_refresh_tokens (token_hash) WHERE deleted_at IS NULL;
CREATE INDEX idx_oauth_refresh_client ON oauth_refresh_tokens (client_id) WHERE deleted_at IS NULL;

-- TOTP per identity. The secret is stored base32; backup codes as sha256 hex
-- hashes. One row per user (unique), confirmed only after a valid code check.
CREATE TABLE totp_secrets
(
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version        BIGINT       NOT NULL DEFAULT 0,
    user_id        UUID         NOT NULL,
    secret         TEXT         NOT NULL,
    confirmed      BOOLEAN      NOT NULL DEFAULT FALSE,
    last_used_step BIGINT       NOT NULL DEFAULT 0, -- replay guard (accept step > last_used_step)
    backup_codes   JSONB        NOT NULL DEFAULT '[]',
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_totp_user ON totp_secrets (user_id) WHERE deleted_at IS NULL;
