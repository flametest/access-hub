-- M6: custom ABAC rules (design.md §12 M6)

-- Custom rules are per-app expressions evaluated inside the casbin matcher
-- (abacEval custom function). env: {sub, dom, obj, act, roles, now}; the
-- expression decides allow/deny for requests it matches; priority resolves
-- against the fixed ladder (super_admin 1 < grant deny 20 < grant allow 30 <
-- custom (default 40) < role deny 45 < role allow 50 < client 60).
CREATE TABLE custom_rules
(
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version    BIGINT       NOT NULL DEFAULT 0,
    app_id     UUID         NOT NULL,
    name       VARCHAR(255) NOT NULL,
    expr       TEXT         NOT NULL,
    effect     VARCHAR(16)  NOT NULL DEFAULT 'allow', -- allow | deny
    priority   INT          NOT NULL DEFAULT 40,
    status     VARCHAR(16)  NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_custom_rules_app_name ON custom_rules (app_id, name) WHERE deleted_at IS NULL;
CREATE INDEX idx_custom_rules_app ON custom_rules (app_id) WHERE deleted_at IS NULL;
