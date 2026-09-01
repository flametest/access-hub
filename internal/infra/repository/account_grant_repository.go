package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AccountGrantRepo manages direct (role-free) resource grants on accounts.
type AccountGrantRepo interface {
	// Add grants one resource directly to an account with the given effect
	// (allow|deny; M6). grantedBy may be "" and expiresAt nil (permanent).
	// Re-granting is a no-op (idempotent). Returns the grant row id ("" when
	// an identical active grant already existed).
	Add(ctx context.Context, accountID, resourceID, grantedBy, effect string, expiresAt *time.Time) (string, error)
	// Remove soft-deletes the grant; zero rows yields NotFoundError.
	Remove(ctx context.Context, accountID, resourceID string) error
	ListByAccount(ctx context.Context, accountID string) ([]*model.AccountGrant, error)
	// FindByID resolves one grant row.
	FindByID(ctx context.Context, id string) (*model.AccountGrant, error)
	// RemoveByID soft-deletes the grant by its own id; zero rows yields
	// NotFoundError.
	RemoveByID(ctx context.Context, id string) error
	// ListByAccountWithResource returns the account's grants joined with the
	// display fields of their resources.
	ListByAccountWithResource(ctx context.Context, accountID string) ([]AccountGrantWithResource, error)
	// ListByResource returns the grants attached to one resource (used to
	// clean up in-memory policies when a resource is deleted/disabled).
	ListByResource(ctx context.Context, resourceID string) ([]*model.AccountGrant, error)
	// ListPolicyRows returns the full account_grants join used by the Casbin
	// loader. Rows referencing soft-deleted/disabled accounts, resources or
	// apps are excluded by the query itself.
	ListPolicyRows(ctx context.Context) ([]PolicyAccountGrant, error)
}

// AccountGrantWithResource is an account_grants row joined with the display
// fields of its resource.
type AccountGrantWithResource struct {
	// embedded: the query selects account_grants.* flat, so GORM must scan
	// these columns inline instead of treating the struct as an association.
	Grant        model.AccountGrant `gorm:"embedded"`
	ResourceCode string             `gorm:"column:resource_code"`
	ResourceName string             `gorm:"column:resource_name"`
	ResourceType string             `gorm:"column:resource_type"`
}

type accountGrantRepoImpl struct {
	db *gorm.DB
}

func NewAccountGrantRepo(db *gorm.DB) AccountGrantRepo {
	return &accountGrantRepoImpl{db: db}
}

func (r *accountGrantRepoImpl) Add(ctx context.Context, accountID, resourceID, grantedBy, effect string, expiresAt *time.Time) (string, error) {
	if effect != "allow" && effect != "deny" {
		effect = grantEffectAllow
	}
	row := model.AccountGrant{
		// The id is generated in Go: sqlite has no gen_random_uuid() default
		// and the conflict path (DoNothing) would not backfill one.
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		AccountID:    accountID,
		ResourceID:   resourceID,
		GrantedAt:    time.Now(),
		ExpiresAt:    expiresAt,
		Effect:       effect,
	}
	if grantedBy != "" {
		row.GrantedBy = &grantedBy
	}
	if err := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&row).Error; err != nil {
		return "", err
	}
	// On conflict the row was not inserted (RowsAffected == 0): the caller can
	// resolve the existing grant via the list endpoint.
	if row.Id == "" {
		return "", nil
	}
	return row.Id, nil
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
		Select("account_grants.id, account_grants.account_id, resources.code AS resource_code, " +
			"apps.key AS resource_app_key, account_grants.effect, account_grants.expires_at").
		Joins("JOIN resources ON resources.id = account_grants.resource_id AND resources.deleted_at IS NULL AND resources.status = 'active'").
		Joins("JOIN apps ON apps.id = resources.app_id AND apps.deleted_at IS NULL AND apps.status = 'active'").
		Joins("JOIN accounts ON accounts.id = account_grants.account_id AND accounts.deleted_at IS NULL AND accounts.status <> 'disabled'").
		Where("account_grants.deleted_at IS NULL").
		Scan(&out).Error
	return out, err
}

func (r *accountGrantRepoImpl) FindByID(ctx context.Context, id string) (*model.AccountGrant, error) {
	var grant model.AccountGrant
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&grant).Error; err != nil {
		return nil, translateFirst(err, "grant %s not found", id)
	}
	return &grant, nil
}

func (r *accountGrantRepoImpl) RemoveByID(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.AccountGrant{})
	return updateRowsAffected(res, fmt.Sprintf("grant %s not found", id))
}

func (r *accountGrantRepoImpl) ListByAccountWithResource(ctx context.Context, accountID string) ([]AccountGrantWithResource, error) {
	var out []AccountGrantWithResource
	err := r.db.WithContext(ctx).
		Table("account_grants").
		Select("account_grants.*, resources.code AS resource_code, resources.name AS resource_name, resources.type AS resource_type").
		Joins("JOIN resources ON resources.id = account_grants.resource_id AND resources.deleted_at IS NULL").
		Where("account_grants.account_id = ? AND account_grants.deleted_at IS NULL", accountID).
		Order("account_grants.created_at ASC").
		Scan(&out).Error
	return out, err
}

func (r *accountGrantRepoImpl) ListByResource(ctx context.Context, resourceID string) ([]*model.AccountGrant, error) {
	var out []*model.AccountGrant
	err := r.db.WithContext(ctx).
		Where("resource_id = ?", resourceID).
		Find(&out).Error
	return out, err
}
