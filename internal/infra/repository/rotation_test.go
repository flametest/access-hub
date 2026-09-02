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

// setupRotationDB opens a sqlite in-memory DB with the sessions and
// oauth_refresh_tokens DDL (the two CAS rotation tables).
func setupRotationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := vgorm.NewDB(&vgorm.Config{
		Dialect:  vgorm.DialectSQLite3,
		Database: fmt.Sprintf("rotation-test-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	for _, stmt := range []string{
		`CREATE TABLE sessions (
			id TEXT PRIMARY KEY, version INTEGER NOT NULL DEFAULT 0,
			user_id TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'identity',
			account_id TEXT, app_id TEXT, refresh_token_hash TEXT NOT NULL,
			device TEXT, ip TEXT, last_used_at DATETIME,
			rotation_count INTEGER NOT NULL DEFAULT 0,
			expires_at DATETIME NOT NULL, revoked_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME)`,
		`CREATE TABLE oauth_refresh_tokens (
			id TEXT PRIMARY KEY, version INTEGER NOT NULL DEFAULT 0,
			client_id TEXT NOT NULL, user_id TEXT, account_id TEXT,
			token_hash TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '',
			rotation_count INTEGER NOT NULL DEFAULT 0, last_used_at DATETIME,
			expires_at DATETIME NOT NULL, revoked_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("ddl: %v", err)
		}
	}
	return db
}

// TestSessionRotateTokenCAS pins the concurrency contract: only the
// presentation whose hash is still current wins; a concurrent/second
// presentation of the same old hash loses (false) without error.
func TestSessionRotateTokenCAS(t *testing.T) {
	db := setupRotationDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	s := &model.Session{
		BasePostgres:     vgorm.BasePostgres{Id: "sess-1"},
		UserID:           "u-1",
		Scope:            "identity",
		RefreshTokenHash: "hash-old",
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, s); err != nil {
		t.Fatalf("create: %v", err)
	}

	ok, err := repo.RotateToken(ctx, s.Id, "hash-old", "hash-new", time.Now())
	if err != nil || !ok {
		t.Fatalf("first rotation: ok=%v err=%v", ok, err)
	}
	// The loser of a concurrent double-presentation.
	ok, err = repo.RotateToken(ctx, s.Id, "hash-old", "hash-new-2", time.Now())
	if err != nil {
		t.Fatalf("second rotation error: %v", err)
	}
	if ok {
		t.Fatal("second CAS with the retired hash must lose")
	}
	// The winner's token is intact and the counter moved exactly once.
	row, err := repo.FindByTokenHash(ctx, "hash-new")
	if err != nil {
		t.Fatalf("find new hash: %v", err)
	}
	if row.RotationCount != 1 {
		t.Fatalf("rotation_count = %d, want 1", row.RotationCount)
	}
	// A revoked session refuses rotation even with the current hash.
	if err := repo.Revoke(ctx, s.Id, time.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	ok, err = repo.RotateToken(ctx, s.Id, "hash-new", "hash-3", time.Now())
	if err != nil {
		t.Fatalf("rotate revoked: %v", err)
	}
	if ok {
		t.Fatal("revoked session must not rotate")
	}
}

// TestOAuthRotateTokenCAS is the same contract for the OAuth2 path.
func TestOAuthRotateTokenCAS(t *testing.T) {
	db := setupRotationDB(t)
	repo := NewOAuthRefreshTokenRepo(db)
	ctx := context.Background()

	row := &model.OAuthRefreshToken{
		BasePostgres: vgorm.BasePostgres{Id: "rt-1"},
		ClientID:     "cli-1",
		UserID:       strPtr("u-1"),
		AccountID:    strPtr("a-1"),
		TokenHash:    "hash-old",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	if ok, err := repo.RotateToken(ctx, row.Id, "hash-old", "hash-new", time.Now()); err != nil || !ok {
		t.Fatalf("first rotation: ok=%v err=%v", ok, err)
	}
	if ok, err := repo.RotateToken(ctx, row.Id, "hash-old", "hash-new-2", time.Now()); err != nil {
		t.Fatalf("second rotation error: %v", err)
	} else if ok {
		t.Fatal("second CAS with the retired hash must lose")
	}
	got, err := repo.FindByTokenHash(ctx, "hash-new")
	if err != nil {
		t.Fatalf("find new hash: %v", err)
	}
	if got.RotationCount != 1 {
		t.Fatalf("rotation_count = %d, want 1", got.RotationCount)
	}
}

func strPtr(v string) *string { return &v }
