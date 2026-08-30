package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/flametest/vita/vgorm"
	"gorm.io/gorm"
)

// setupRepoDB opens a sqlite in-memory DB with the minimal DDL for the
// account_roles round-trip check.
func setupRepoDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := vgorm.NewDB(&vgorm.Config{
		Dialect:  vgorm.DialectSQLite3,
		Database: fmt.Sprintf("repo-test-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	ddl := []string{
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
	}
	for _, d := range ddl {
		if err := db.Exec(d).Error; err != nil {
			t.Fatalf("exec ddl: %v", err)
		}
	}
	return db
}

// TestAccountRoleAddSetsGrantedAt verifies that Add records the grant time
// instead of the zero time (the column has DEFAULT CURRENT_TIMESTAMP but the
// gorm model would otherwise insert the Go zero value).
func TestAccountRoleAddSetsGrantedAt(t *testing.T) {
	db := setupRepoDB(t)
	repo := NewAccountRoleRepo(db)
	// ListByAccount joins roles: seed the referenced role row.
	if err := db.Exec(`INSERT INTO roles (id, app_id, code, name, scope) VALUES ('role-1', 'app-1', 'member', 'Member', 'app')`).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	before := time.Now().Add(-time.Minute)
	if err := repo.Add(context.Background(), "acc-1", "role-1", "", nil); err != nil {
		t.Fatalf("add: %v", err)
	}
	rows, err := repo.ListByAccount(context.Background(), "acc-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].GrantedAt.Before(before) {
		t.Errorf("granted_at = %v, want a timestamp at/after %v (got zero-value insertion)", rows[0].GrantedAt, before)
	}
}
