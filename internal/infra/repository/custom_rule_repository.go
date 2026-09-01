package repository

import (
	"context"
	"fmt"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// CustomRuleRepo manages per-app ABAC custom rules (M6).
type CustomRuleRepo interface {
	// Create inserts a rule (id assigned by the caller for sqlite parity).
	Create(ctx context.Context, row *model.CustomRule) error
	// FindByID resolves one rule (soft-deleted rows yield NotFoundError).
	FindByID(ctx context.Context, id string) (*model.CustomRule, error)
	// FindByAppAndName resolves one rule by its per-app unique name.
	FindByAppAndName(ctx context.Context, appID, name string) (*model.CustomRule, error)
	// ListByApp returns the app's rules ordered by priority, then name.
	ListByApp(ctx context.Context, appID string) ([]*model.CustomRule, error)
	// UpdateFields updates the given columns (optimistic-lock aware).
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	// Delete soft-deletes the rule; zero rows yields NotFoundError.
	Delete(ctx context.Context, id string) error
	// ListPolicyRows returns every ACTIVE rule joined with its app key, used
	// by the Casbin loader. Rules whose app is soft-deleted or disabled are
	// excluded by the query itself.
	ListPolicyRows(ctx context.Context) ([]PolicyCustomRule, error)
}

// PolicyCustomRule is a custom_rules row joined with its app key.
type PolicyCustomRule struct {
	AppKey   string `gorm:"column:app_key"`
	Expr     string `gorm:"column:expr"`
	Effect   string `gorm:"column:effect"`
	Priority int    `gorm:"column:priority"`
}

type customRuleRepoImpl struct {
	db *gorm.DB
}

func NewCustomRuleRepo(db *gorm.DB) CustomRuleRepo {
	return &customRuleRepoImpl{db: db}
}

func (r *customRuleRepoImpl) Create(ctx context.Context, row *model.CustomRule) error {
	return r.db.WithContext(ctx).Create(row).Error
}

func (r *customRuleRepoImpl) FindByID(ctx context.Context, id string) (*model.CustomRule, error) {
	var row model.CustomRule
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&row).Error; err != nil {
		return nil, translateFirst(err, "custom rule %s not found", id)
	}
	return &row, nil
}

func (r *customRuleRepoImpl) FindByAppAndName(ctx context.Context, appID, name string) (*model.CustomRule, error) {
	var row model.CustomRule
	if err := r.db.WithContext(ctx).
		Where("app_id = ? AND name = ?", appID, name).
		First(&row).Error; err != nil {
		return nil, translateFirst(err, "custom rule %q not found", name)
	}
	return &row, nil
}

func (r *customRuleRepoImpl) ListByApp(ctx context.Context, appID string) ([]*model.CustomRule, error) {
	var out []*model.CustomRule
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("priority ASC, name ASC").
		Find(&out).Error
	return out, err
}

func (r *customRuleRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	res := r.db.WithContext(ctx).Model(&model.CustomRule{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("custom rule %s not found", id))
}

func (r *customRuleRepoImpl) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Delete(&model.CustomRule{}, "id = ?", id)
	return updateRowsAffected(res, fmt.Sprintf("custom rule %s not found", id))
}

// ListPolicyRows joins custom_rules -> apps (active only).
func (r *customRuleRepoImpl) ListPolicyRows(ctx context.Context) ([]PolicyCustomRule, error) {
	var out []PolicyCustomRule
	err := r.db.WithContext(ctx).
		Table("custom_rules").
		Select("apps.key AS app_key, custom_rules.expr, custom_rules.effect, custom_rules.priority").
		Joins("JOIN apps ON apps.id = custom_rules.app_id AND apps.deleted_at IS NULL AND apps.status = 'active'").
		Where("custom_rules.deleted_at IS NULL AND custom_rules.status = 'active'").
		Order("custom_rules.priority ASC").
		Scan(&out).Error
	return out, err
}
