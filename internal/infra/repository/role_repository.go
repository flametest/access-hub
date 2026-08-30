package repository

import (
	"context"
	"fmt"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// RoleRepo persists roles (app-scope and global built-ins).
type RoleRepo interface {
	Create(ctx context.Context, role *model.Role) error
	FindByID(ctx context.Context, id string) (*model.Role, error)
	FindByAppAndCode(ctx context.Context, appID, code string) (*model.Role, error)
	ListByApp(ctx context.Context, appID string) ([]*model.Role, error)
	// FindGlobalByCode returns the built-in global role with the given code
	// (scope=global AND built_in=true), e.g. super_admin / org_admin.
	FindGlobalByCode(ctx context.Context, code string) (*model.Role, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
}

type roleRepoImpl struct {
	db *gorm.DB
}

func NewRoleRepo(db *gorm.DB) RoleRepo {
	return &roleRepoImpl{db: db}
}

func (r *roleRepoImpl) Create(ctx context.Context, role *model.Role) error {
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *roleRepoImpl) FindByID(ctx context.Context, id string) (*model.Role, error) {
	var role model.Role
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&role).Error; err != nil {
		return nil, translateFirst(err, "role %s not found", id)
	}
	return &role, nil
}

func (r *roleRepoImpl) FindByAppAndCode(ctx context.Context, appID, code string) (*model.Role, error) {
	var role model.Role
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND code = ?", appID, code).
		First(&role).Error
	if err != nil {
		return nil, translateFirst(err, "role %s not found in app %s", code, appID)
	}
	return &role, nil
}

func (r *roleRepoImpl) ListByApp(ctx context.Context, appID string) ([]*model.Role, error) {
	var out []*model.Role
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *roleRepoImpl) FindGlobalByCode(ctx context.Context, code string) (*model.Role, error) {
	var role model.Role
	err := r.db.WithContext(ctx).
		Where("code = ? AND scope = ? AND built_in = ?", code, "global", true).
		First(&role).Error
	if err != nil {
		return nil, translateFirst(err, "global role %s not found", code)
	}
	return &role, nil
}

func (r *roleRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Role{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("role %s not found", id))
}
