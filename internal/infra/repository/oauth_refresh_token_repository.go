package repository

import (
	"context"
	"fmt"
	"time"

	"errors"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"gorm.io/gorm"
)

// OAuthRefreshTokenRepo persists OAuth2 refresh tokens with in-place
// rotation. Reuse of a replaced hash revokes the whole token family.
type OAuthRefreshTokenRepo interface {
	Create(ctx context.Context, token *model.OAuthRefreshToken) error
	// FindByTokenHash resolves a sha256 refresh-token hash to its row
	// (including revoked ones — callers decide on reuse semantics).
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.OAuthRefreshToken, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	// RotateToken atomically replaces the hash of the row still holding
	// oldHash (compare-and-swap). false = no row matched: the token was
	// rotated or revoked concurrently; callers treat it as reuse.
	RotateToken(ctx context.Context, id, oldHash, newHash string, at time.Time) (bool, error)
	// Revoke targets only active tokens; zero rows yields ConflictError
	// (missing or already revoked).
	Revoke(ctx context.Context, id string, at time.Time) error
	// RevokeAllForClient revokes the client's whole token family (reuse
	// detection).
	RevokeAllForClient(ctx context.Context, clientID string, at time.Time) error
	RevokeAllForAccount(ctx context.Context, accountID string, at time.Time) error
	// Delete soft-deletes one row; zero rows yields NotFoundError.
	Delete(ctx context.Context, id string) error
}

type oauthRefreshTokenRepoImpl struct {
	db *gorm.DB
}

func NewOAuthRefreshTokenRepo(db *gorm.DB) OAuthRefreshTokenRepo {
	return &oauthRefreshTokenRepoImpl{db: db}
}

func (r *oauthRefreshTokenRepoImpl) Create(ctx context.Context, token *model.OAuthRefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *oauthRefreshTokenRepoImpl) FindByTokenHash(ctx context.Context, tokenHash string) (*model.OAuthRefreshToken, error) {
	var token model.OAuthRefreshToken
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&token).Error; err != nil {
		return nil, translateFirst(err, "refresh token not found")
	}
	return &token, nil
}

func (r *oauthRefreshTokenRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.OAuthRefreshToken{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("refresh token %s not found", id))
}

// Revoke targets only active tokens, mirroring SessionRepo.Revoke semantics.
// RotateToken is the CAS rotation; version is bumped manually because
// map-based Updates bypass the optimistic-lock plugin.
func (r *oauthRefreshTokenRepoImpl) RotateToken(ctx context.Context, id, oldHash, newHash string, at time.Time) (bool, error) {
	res := r.db.WithContext(ctx).
		Model(&model.OAuthRefreshToken{}).
		Where("id = ? AND token_hash = ? AND revoked_at IS NULL", id, oldHash).
		Updates(map[string]any{
			"token_hash":     newHash,
			"rotation_count": gorm.Expr("rotation_count + 1"),
			"last_used_at":   at,
			// no "version" key: the optimistic-lock plugin treats a map
			// update carrying it as armed and misreports a lost CAS race
			// (rows:0) as a lock conflict instead of a plain no-match.
		})
	if res.Error != nil {
		// The optimistic-lock plugin reports rows:0 on versioned models as a
		// lock conflict; for the CAS rotation a no-match IS the lost race
		// (hash already rotated or row revoked since the read).
		if errors.Is(res.Error, verrors.ErrOptimisticLock) {
			return false, nil
		}
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *oauthRefreshTokenRepoImpl) Revoke(ctx context.Context, id string, at time.Time) error {
	res := r.db.WithContext(ctx).Exec(
		"UPDATE oauth_refresh_tokens SET revoked_at = ?, version = version + 1 WHERE id = ? AND revoked_at IS NULL AND deleted_at IS NULL",
		at, id,
	)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return verrors.ConflictError(fmt.Sprintf("refresh token %s not active (missing or already revoked)", id))
	}
	return nil
}

func (r *oauthRefreshTokenRepoImpl) RevokeAllForClient(ctx context.Context, clientID string, at time.Time) error {
	return r.revokeWhere(ctx, "client_id = ?", at, clientID)
}

func (r *oauthRefreshTokenRepoImpl) RevokeAllForAccount(ctx context.Context, accountID string, at time.Time) error {
	return r.revokeWhere(ctx, "account_id = ?", at, accountID)
}

func (r *oauthRefreshTokenRepoImpl) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.OAuthRefreshToken{})
	return updateRowsAffected(res, fmt.Sprintf("refresh token %s not found", id))
}

// revokeWhere is the shared bulk-revocation helper (raw update bypasses the
// optimistic-lock callback; revoking an empty set is a no-op).
func (r *oauthRefreshTokenRepoImpl) revokeWhere(ctx context.Context, where string, at time.Time, args ...any) error {
	res := r.db.WithContext(ctx).Exec(
		"UPDATE oauth_refresh_tokens SET revoked_at = ?, version = version + 1 WHERE revoked_at IS NULL AND deleted_at IS NULL AND "+where,
		append([]any{at}, args...)...,
	)
	return res.Error
}
