-- Internal cluster API: per-app secret for resource self-registration
-- (PUT /internal/v1/apps/{appKey}/resources:batch, header X-App-Key).

-- The plaintext is shown once at app creation / secret rotation; only the
-- SHA-256 hex hash is stored. NULL = no internal credential (platform apps
-- and apps created before this migration, until an admin rotates a secret).
ALTER TABLE apps ADD COLUMN IF NOT EXISTS secret_hash VARCHAR(64);
