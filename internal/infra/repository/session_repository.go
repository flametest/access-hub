package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"gorm.io/gorm"
)

// SessionRepo persists refresh-token sessions with in-place rotation.
type SessionRepo interface {
	Create(ctx context.Context, session *model.Session) error
	FindByID(ctx context.Context, id string) (*model.Session, error)
	// FindByTokenHash resolves a sha256 refresh-token hash to its session
	// (rotation / reuse detection).
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
	// ListByUser returns every session owned by the identity, including
	// revoked ones (the "my sessions" UI shows them).
	ListByUser(ctx context.Context, userID string) ([]*model.Session, error)
	// Revoke sets revoked_at on an active (non-revoked) session. A missing or
	// already-revoked session yields ConflictError.
	Revoke(ctx context.Context, id string, at time.Time) error
	// RevokeAllForUser revokes every session owned by the identity across all
	// scopes (identity + account), e.g. "sign out everywhere".
	RevokeAllForUser(ctx context.Context, userID string, at time.Time) error
	// RevokeAllForUserByScope revokes the identity's sessions of one scope
	// only; design.md §7: password change revokes identity-scope sessions but
	// leaves workspace (account) sessions alone.
	RevokeAllForUserByScope(ctx context.Context, userID, scope string, at time.Time) error
	// RevokeAllForUserByScopeExcept revokes the identity's sessions of one
	// scope, keeping exceptSessionID active (e.g. "change password, stay
	// signed in on this device").
	RevokeAllForUserByScopeExcept(ctx context.Context, userID, scope, exceptSessionID string, at time.Time) error
	// RevokeAllForAccount revokes the workspace account's sessions (e.g. after
	// an account password reset).
	RevokeAllForAccount(ctx context.Context, accountID string, at time.Time) error
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
}

type sessionRepoImpl struct {
	db *gorm.DB
}

func NewSessionRepo(db *gorm.DB) SessionRepo {
	return &sessionRepoImpl{db: db}
}

func (r *sessionRepoImpl) Create(ctx context.Context, session *model.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *sessionRepoImpl) FindByID(ctx context.Context, id string) (*model.Session, error) {
	var session model.Session
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&session).Error; err != nil {
		return nil, translateFirst(err, "session %s not found", id)
	}
	return &session, nil
}

func (r *sessionRepoImpl) FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	var session model.Session
	if err := r.db.WithContext(ctx).Where("refresh_token_hash = ?", tokenHash).First(&session).Error; err != nil {
		return nil, translateFirst(err, "session for the given refresh token not found")
	}
	return &session, nil
}

func (r *sessionRepoImpl) ListByUser(ctx context.Context, userID string) ([]*model.Session, error) {
	var out []*model.Session
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&out).Error
	return out, err
}

// Revoke targets only active sessions; zero rows means "missing or already
// revoked" — reported as ConflictError so callers can detect token reuse or
// double logout.
func (r *sessionRepoImpl) Revoke(ctx context.Context, id string, at time.Time) error {
	res := r.db.WithContext(ctx).Exec(
		"UPDATE sessions SET revoked_at = ?, version = version + 1 WHERE id = ? AND revoked_at IS NULL AND deleted_at IS NULL",
		at, id,
	)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return verrors.ConflictError(fmt.Sprintf("session %s not active (missing or already revoked)", id))
	}
	return nil
}

// revokeWhere is the shared raw-update helper for bulk revocation. Raw Exec
// bypasses the optimistic-lock update callback, so revoking an empty set is a
// no-op rather than a spurious conflict error.
func (r *sessionRepoImpl) revokeWhere(ctx context.Context, where string, at time.Time, args ...any) error {
	res := r.db.WithContext(ctx).Exec(
		"UPDATE sessions SET revoked_at = ?, version = version + 1 WHERE revoked_at IS NULL AND deleted_at IS NULL AND "+where,
		append([]any{at}, args...)...,
	)
	return res.Error
}

func (r *sessionRepoImpl) RevokeAllForUser(ctx context.Context, userID string, at time.Time) error {
	return r.revokeWhere(ctx, "user_id = ?", at, userID)
}

func (r *sessionRepoImpl) RevokeAllForUserByScope(ctx context.Context, userID, scope string, at time.Time) error {
	return r.revokeWhere(ctx, "user_id = ? AND scope = ?", at, userID, scope)
}

func (r *sessionRepoImpl) RevokeAllForAccount(ctx context.Context, accountID string, at time.Time) error {
	return r.revokeWhere(ctx, "account_id = ?", at, accountID)
}

func (r *sessionRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Session{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("session %s not found", id))
}

// RevokeAllForUserByScopeExcept revokes the identity's sessions of one scope,
// keeping exceptSessionID active. An empty exceptSessionID revokes all.
func (r *sessionRepoImpl) RevokeAllForUserByScopeExcept(ctx context.Context, userID, scope, exceptSessionID string, at time.Time) error {
	where := "user_id = ? AND scope = ?"
	args := []any{userID, scope}
	if exceptSessionID != "" {
		where += " AND id <> ?"
		args = append(args, exceptSessionID)
	}
	return r.revokeWhere(ctx, where, at, args...)
}
