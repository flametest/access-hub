package repository

import (
	"context"
	"fmt"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// TOTPSecretRepo persists per-identity TOTP enrollments (one row per user,
// partial unique index on user_id among live rows).
type TOTPSecretRepo interface {
	// UpsertDraft stores an unconfirmed draft secret, replacing any prior
	// unconfirmed draft of the user. A confirmed row must be rejected by the
	// service layer (enroll is refused when 2FA is already enabled).
	UpsertDraft(ctx context.Context, userID, secret string) (*model.TOTPSecret, error)
	FindByUserID(ctx context.Context, userID string) (*model.TOTPSecret, error)
	// Confirm flips confirmed=true (after a valid code check).
	Confirm(ctx context.Context, id string) error
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	// AdvanceStep atomically moves last_used_step forward (single-use TOTP
	// steps): false means the step was already consumed by a concurrent
	// verification.
	AdvanceStep(ctx context.Context, id string, step int64) (bool, error)
	// ConsumeBackupCodeCAS replaces the backup-code set only when it still
	// holds prevJSON (compare-and-swap on the whole array): false means a
	// concurrent verification consumed the code first.
	ConsumeBackupCodeCAS(ctx context.Context, id string, prevJSON, nextJSON []byte) (bool, error)
	// Delete soft-deletes the row (2FA disable).
	Delete(ctx context.Context, id string) error
}

type totpSecretRepoImpl struct {
	db *gorm.DB
}

func NewTOTPSecretRepo(db *gorm.DB) TOTPSecretRepo {
	return &totpSecretRepoImpl{db: db}
}

// UpsertDraft resolves the live row for the user and either resets it to a
// fresh draft or creates it. The service layer guards the "already
// confirmed" case.
func (r *totpSecretRepoImpl) UpsertDraft(ctx context.Context, userID, secret string) (*model.TOTPSecret, error) {
	existing, err := r.FindByUserID(ctx, userID)
	if err != nil && !IsNotFound(err) {
		return nil, err
	}
	if existing != nil {
		if existing.Confirmed {
			return nil, fmt.Errorf("totp secret for user %s already confirmed", userID)
		}
		fields := map[string]any{
			"secret":         secret,
			"confirmed":      false,
			"last_used_step": 0,
			"backup_codes":   []byte("[]"),
		}
		if err := r.UpdateFields(ctx, existing.Id, fields); err != nil {
			return nil, err
		}
		return r.FindByUserID(ctx, userID)
	}
	row := &model.TOTPSecret{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		UserID:       userID,
		Secret:       secret,
		Confirmed:    false,
		BackupCodes:  datatypes.JSON("[]"),
	}
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		return nil, err
	}
	return row, nil
}

func (r *totpSecretRepoImpl) FindByUserID(ctx context.Context, userID string) (*model.TOTPSecret, error) {
	var row model.TOTPSecret
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&row).Error; err != nil {
		return nil, translateFirst(err, "totp secret for user %s not found", userID)
	}
	return &row, nil
}

func (r *totpSecretRepoImpl) Confirm(ctx context.Context, id string) error {
	return r.UpdateFields(ctx, id, map[string]any{"confirmed": true})
}

func (r *totpSecretRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.TOTPSecret{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("totp secret %s not found", id))
}

// AdvanceStep conditionally moves last_used_step forward: the UPDATE only
// matches when the stored step is still older than the presented one, so
// two concurrent verifications of the same window cannot both succeed.
func (r *totpSecretRepoImpl) AdvanceStep(ctx context.Context, id string, step int64) (bool, error) {
	res := r.db.WithContext(ctx).Exec(
		"UPDATE totp_secrets SET last_used_step = ?, version = version + 1 WHERE id = ? AND last_used_step < ? AND deleted_at IS NULL",
		step, id, step,
	)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

// ConsumeBackupCodeCAS swaps the backup-code set only when the stored set is
// still byte-identical to what the caller read: two concurrent presentations
// of the same single-use code cannot both win the compare-and-swap.
func (r *totpSecretRepoImpl) ConsumeBackupCodeCAS(ctx context.Context, id string, prevJSON, nextJSON []byte) (bool, error) {
	res := r.db.WithContext(ctx).Exec(
		"UPDATE totp_secrets SET backup_codes = ?, version = version + 1 WHERE id = ? AND backup_codes = ? AND deleted_at IS NULL",
		nextJSON, id, prevJSON,
	)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *totpSecretRepoImpl) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.TOTPSecret{})
	return updateRowsAffected(res, fmt.Sprintf("totp secret %s not found", id))
}
