package repository

import (
	"context"
	"fmt"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// AppRepo persists registered applications.
type AppRepo interface {
	Create(ctx context.Context, app *model.App) error
	FindByID(ctx context.Context, id string) (*model.App, error)
	FindByKey(ctx context.Context, key string) (*model.App, error)
	// List returns apps of one org; orgID nil means ALL apps (including
	// platform apps whose org_id is NULL).
	List(ctx context.Context, orgID *string) ([]*model.App, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	// Delete soft-deletes the app; zero rows yields NotFoundError.
	Delete(ctx context.Context, id string) error
}

type appRepoImpl struct {
	db *gorm.DB
}

func NewAppRepo(db *gorm.DB) AppRepo {
	return &appRepoImpl{db: db}
}

func (r *appRepoImpl) Create(ctx context.Context, app *model.App) error {
	return r.db.WithContext(ctx).Create(app).Error
}

func (r *appRepoImpl) FindByID(ctx context.Context, id string) (*model.App, error) {
	var app model.App
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&app).Error; err != nil {
		return nil, translateFirst(err, "app %s not found", id)
	}
	return &app, nil
}

func (r *appRepoImpl) FindByKey(ctx context.Context, key string) (*model.App, error) {
	var app model.App
	if err := r.db.WithContext(ctx).Where("key = ?", key).First(&app).Error; err != nil {
		return nil, translateFirst(err, "app %s not found", key)
	}
	return &app, nil
}

func (r *appRepoImpl) List(ctx context.Context, orgID *string) ([]*model.App, error) {
	q := r.db.WithContext(ctx)
	if orgID != nil {
		q = q.Where("org_id = ?", *orgID)
	}
	var out []*model.App
	err := q.Order("created_at ASC").Find(&out).Error
	return out, err
}

func (r *appRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.App{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("app %s not found", id))
}

func (r *appRepoImpl) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.App{})
	return updateRowsAffected(res, fmt.Sprintf("app %s not found", id))
}
