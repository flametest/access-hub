package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// ResourceRepo persists the unified permission resources (menu/api/button).
type ResourceRepo interface {
	Create(ctx context.Context, resource *model.Resource) error
	FindByID(ctx context.Context, id string) (*model.Resource, error)
	FindByAppAndCode(ctx context.Context, appID, code string) (*model.Resource, error)
	// FindByAppAndRoute resolves an API resource by method + route path
	// (authz/check reverse lookup). method is upper-normalized here.
	FindByAppAndRoute(ctx context.Context, appID, method, path string) (*model.Resource, error)
	ListByApp(ctx context.Context, appID string) ([]*model.Resource, error)
	ListByAppAndType(ctx context.Context, appID, typ string) ([]*model.Resource, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	// Delete soft-deletes the resource; zero rows yields NotFoundError.
	Delete(ctx context.Context, id string) error
}

type resourceRepoImpl struct {
	db *gorm.DB
}

func NewResourceRepo(db *gorm.DB) ResourceRepo {
	return &resourceRepoImpl{db: db}
}

func (r *resourceRepoImpl) Create(ctx context.Context, resource *model.Resource) error {
	return r.db.WithContext(ctx).Create(resource).Error
}

func (r *resourceRepoImpl) FindByID(ctx context.Context, id string) (*model.Resource, error) {
	var resource model.Resource
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&resource).Error; err != nil {
		return nil, translateFirst(err, "resource %s not found", id)
	}
	return &resource, nil
}

func (r *resourceRepoImpl) FindByAppAndCode(ctx context.Context, appID, code string) (*model.Resource, error) {
	var resource model.Resource
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND code = ?", appID, code).
		First(&resource).Error
	if err != nil {
		return nil, translateFirst(err, "resource %s not found in app %s", code, appID)
	}
	return &resource, nil
}

func (r *resourceRepoImpl) FindByAppAndRoute(ctx context.Context, appID, method, path string) (*model.Resource, error) {
	var resource model.Resource
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND method = ? AND route_path = ?", appID, strings.ToUpper(strings.TrimSpace(method)), path).
		First(&resource).Error
	if err != nil {
		return nil, translateFirst(err, "resource for %s %s not found in app %s", method, path, appID)
	}
	return &resource, nil
}

func (r *resourceRepoImpl) ListByApp(ctx context.Context, appID string) ([]*model.Resource, error) {
	var out []*model.Resource
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("sort ASC, created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *resourceRepoImpl) ListByAppAndType(ctx context.Context, appID, typ string) ([]*model.Resource, error) {
	var out []*model.Resource
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND type = ?", appID, typ).
		Order("sort ASC, created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *resourceRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Resource{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("resource %s not found", id))
}

func (r *resourceRepoImpl) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Resource{})
	return updateRowsAffected(res, fmt.Sprintf("resource %s not found", id))
}
