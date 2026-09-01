-- M5: social login identities (design.md §12 M5)

CREATE TABLE identities
(
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version          BIGINT       NOT NULL DEFAULT 0,
    user_id          UUID         NOT NULL, -- owning primary identity
    provider         VARCHAR(32)  NOT NULL, -- google | microsoft | facebook | apple
    provider_user_id VARCHAR(255) NOT NULL,
    email            VARCHAR(255), -- email at the provider (may be private relay for apple)
    email_verified   BOOLEAN      NOT NULL DEFAULT FALSE,
    display_name     VARCHAR(255),
    avatar_url       TEXT,
    raw_profile      JSONB,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at       TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_identities_provider_uid ON identities (provider, provider_user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_identities_user ON identities (user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_identities_email ON identities (LOWER(email)) WHERE deleted_at IS NULL AND email IS NOT NULL;
