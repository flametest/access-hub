package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AccountGrantRepo manages direct (role-free) resource grants on accounts.
type AccountGrantRepo interface {
	// Add grants one resource directly to an account. grantedBy may be "" and
	// expiresAt nil (permanent). Re-granting is a no-op (idempotent).
	Add(ctx context.Context, accountID, resourceID, grantedBy string, expiresAt *time.Time) error
	// Remove soft-deletes the grant; zero rows yields NotFoundError.
	Remove(ctx context.Context, accountID, resourceID string) error
	ListByAccount(ctx context.Context, accountID string) ([]*model.AccountGrant, error)
	// ListPolicyRows returns the full account_grants join used by the Casbin
	// loader. Rows referencing soft-deleted/disabled accounts, resources or
	// apps are excluded by the query itself.
	ListPolicyRows(ctx context.Context) ([]PolicyAccountGrant, error)
}

type accountGrantRepoImpl struct {
	db *gorm.DB
}

func NewAccountGrantRepo(db *gorm.DB) AccountGrantRepo {
	return &accountGrantRepoImpl{db: db}
}

func (r *accountGrantRepoImpl) Add(ctx context.Context, accountID, resourceID, grantedBy string, expiresAt *time.Time) error {
	row := model.AccountGrant{
		AccountID:  accountID,
		ResourceID: resourceID,
		ExpiresAt:  expiresAt,
		Effect:     grantEffectAllow,
	}
	if grantedBy != "" {
		row.GrantedBy = &grantedBy
	}
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&row).Error
}

func (r *accountGrantRepoImpl) Remove(ctx context.Context, accountID, resourceID string) error {
	res := r.db.WithContext(ctx).
		Where("account_id = ? AND resource_id = ?", accountID, resourceID).
		Delete(&model.AccountGrant{})
	return updateRowsAffected(res, fmt.Sprintf("grant of resource %s to account %s not found", resourceID, accountID))
}

func (r *accountGrantRepoImpl) ListByAccount(ctx context.Context, accountID string) ([]*model.AccountGrant, error) {
	var out []*model.AccountGrant
	err := r.db.WithContext(ctx).
		Where("account_id = ?", accountID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

// ListPolicyRows joins account_grants -> resources -> apps -> accounts.
func (r *accountGrantRepoImpl) ListPolicyRows(ctx context.Context) ([]PolicyAccountGrant, error) {
	var out []PolicyAccountGrant
	err := r.db.WithContext(ctx).
		Table("account_grants").
		Select("account_grants.id, account_grants.account_id, resources.code AS resource_code, "+
			"apps.key AS resource_app_key, account_grants.expires_at").
		Joins("JOIN resources ON resources.id = account_grants.resource_id AND resources.deleted_at IS NULL AND resources.status = 'active'").
		Joins("JOIN apps ON apps.id = resources.app_id AND apps.deleted_at IS NULL AND apps.status = 'active'").
		Joins("JOIN accounts ON accounts.id = account_grants.account_id AND accounts.deleted_at IS NULL AND accounts.status <> 'disabled'").
		Where("account_grants.deleted_at IS NULL").
		Scan(&out).Error
	return out, err
}
