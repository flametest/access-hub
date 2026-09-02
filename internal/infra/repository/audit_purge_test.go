package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/vgorm"
	"gorm.io/gorm"
)

func setupAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := vgorm.NewDB(&vgorm.Config{
		Dialect:  vgorm.DialectSQLite3,
		Database: fmt.Sprintf("audit-test-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.Exec(`CREATE TABLE audit_logs (
		id TEXT PRIMARY KEY, version INTEGER NOT NULL DEFAULT 0,
		actor_type TEXT NOT NULL, actor_id TEXT, org_id TEXT,
		action TEXT NOT NULL, target_type TEXT, target_id TEXT,
		detail JSONB, ip TEXT, user_agent TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME)`).Error; err != nil {
		t.Fatalf("ddl: %v", err)
	}
	return db
}

// TestAuditPurgeBefore pins the retention contract: strictly-older rows are
// hard-deleted, newer ones stay, and the deleted count is returned.
func TestAuditPurgeBefore(t *testing.T) {
	db := setupAuditDB(t)
	repo := NewAuditLogRepo(db)
	ctx := context.Background()

	old := time.Now().AddDate(0, 0, -200)
	fresh := time.Now().AddDate(0, 0, -10)
	for i, ts := range []time.Time{old, old, fresh} {
		row := &model.AuditLog{
			BasePostgres: vgorm.BasePostgres{
				Id:        fmt.Sprintf("log-%d", i),
				CreatedAt: ts,
				UpdatedAt: ts,
			},
			ActorType: "system",
			Action:    "login_success",
		}
		if err := db.WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	cutoff := time.Now().AddDate(0, 0, -180)
	deleted, err := repo.PurgeBefore(ctx, cutoff)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	var remain int64
	db.Model(&model.AuditLog{}).Count(&remain)
	if remain != 1 {
		t.Fatalf("remaining rows = %d, want 1", remain)
	}
}
