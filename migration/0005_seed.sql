-- Access-Hub static seed (idempotent bootstrap data; runtime secrets NOT here).
-- Fixed UUIDs so cross-references stay stable across reruns.

-- Platform admin app (org_id NULL = platform app)
INSERT INTO apps (id, key, org_id, name, type, description, status)
VALUES ('00000000-0000-0000-0000-0000000000a1', 'admin', NULL,
        'Access-Hub Console', 'web', 'Platform admin console (dogfood domain)', 'active')
ON CONFLICT DO NOTHING;

-- Built-in global roles on the admin app (loader special-cases super_admin -> wildcard policy)
INSERT INTO roles (id, app_id, code, name, scope, built_in)
VALUES
  ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000a1', 'super_admin', 'Platform Super Admin', 'global', TRUE),
  ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-0000000000a1', 'org_admin', 'Organization Admin', 'global', TRUE)
ON CONFLICT DO NOTHING;

-- Demo org + demo app for local development
INSERT INTO orgs (id, key, name, status)
VALUES ('00000000-0000-0000-0000-0000000000c1', 'demo', 'Demo Organization', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO apps (id, key, org_id, name, type, description, status)
VALUES ('00000000-0000-0000-0000-0000000000d1', 'demo-app', '00000000-0000-0000-0000-0000000000c1',
        'Demo Workspace', 'web', 'Sample business app wired to access-hub', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO roles (id, app_id, code, name, scope, built_in)
VALUES ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1',
        'member', 'Demo Member', 'app', FALSE)
ON CONFLICT DO NOTHING;
