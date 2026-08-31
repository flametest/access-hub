package casbinx

import (
	"fmt"
	"testing"
	"time"

	"github.com/flametest/vita/vgorm"
	"gorm.io/gorm"
)

// setupDB opens a uniquely-named shared in-memory sqlite DB via vgorm.NewDB
// (the production code path) and creates the policy-relevant tables with
// sqlite-adapted DDL — the Postgres init.sql DDL (gen_random_uuid() defaults)
// is not exercised here, matching the taskd test conventions. IDs are set
// explicitly in Go because sqlite has no UUID default.
func setupDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := vgorm.NewDB(&vgorm.Config{
		Dialect:  vgorm.DialectSQLite3,
		Database: fmt.Sprintf("casbin-test-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	for _, ddl := range policyTableDDLs {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("exec ddl: %v", err)
		}
	}
	return db
}

var policyTableDDLs = []string{
	`CREATE TABLE apps (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		"key" TEXT NOT NULL,
		org_id TEXT,
		name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'web',
		description TEXT,
		logo_url TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE resources (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		parent_id TEXT,
		type TEXT NOT NULL,
		code TEXT NOT NULL,
		name TEXT NOT NULL,
		sort INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'active',
		visible BOOLEAN NOT NULL DEFAULT TRUE,
		icon TEXT,
		method TEXT,
		route_path TEXT,
		extra TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE roles (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		code TEXT NOT NULL,
		name TEXT NOT NULL,
		scope TEXT NOT NULL DEFAULT 'app',
		built_in BOOLEAN NOT NULL DEFAULT FALSE,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE role_resources (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		role_id TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		effect TEXT NOT NULL DEFAULT 'allow',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE users (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		username TEXT NOT NULL,
		email TEXT NOT NULL,
		email_verified BOOLEAN NOT NULL DEFAULT FALSE,
		password_hash TEXT,
		nickname TEXT,
		avatar_url TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
		last_login_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE accounts (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		identity_id TEXT NOT NULL,
		app_id TEXT NOT NULL,
		email TEXT NOT NULL,
		username TEXT,
		password_hash TEXT,
		display_name TEXT,
		status TEXT NOT NULL DEFAULT 'pending_activation',
		source TEXT NOT NULL DEFAULT 'invite',
		last_login_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE account_roles (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		account_id TEXT NOT NULL,
		role_id TEXT NOT NULL,
		granted_by TEXT,
		granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE account_grants (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		account_id TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		granted_by TEXT,
		granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		effect TEXT NOT NULL DEFAULT 'allow',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	// M4: service clients translated by the loader.
	`CREATE TABLE oauth_clients (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		name TEXT NOT NULL,
		client_type TEXT NOT NULL DEFAULT 'confidential',
		secret_hash TEXT,
		grant_types TEXT NOT NULL DEFAULT '[]',
		redirect_uris TEXT NOT NULL DEFAULT '[]',
		scopes TEXT NOT NULL DEFAULT '[]',
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
}
