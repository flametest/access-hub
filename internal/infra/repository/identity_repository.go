package repository

import (
	"context"
	"fmt"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// IdentityRepo persists social sign-in bindings (identities). The
// (provider, provider_user_id) pair is unique among live rows (partial unique
// index, see migration/0003_m5.sql).
type IdentityRepo interface {
	Create(ctx context.Context, identity *model.Identity) error
	FindByID(ctx context.Context, id string) (*model.Identity, error)
	FindByProviderAndUID(ctx context.Context, provider, providerUserID string) (*model.Identity, error)
	ListByUser(ctx context.Context, userID string) ([]*model.Identity, error)
	Delete(ctx context.Context, id string) error
	CountByUser(ctx context.Context, userID string) (int64, error)
}

type identityRepoImpl struct {
	db *gorm.DB
}

func NewIdentityRepo(db *gorm.DB) IdentityRepo {
	return &identityRepoImpl{db: db}
}

func (r *identityRepoImpl) Create(ctx context.Context, identity *model.Identity) error {
	return r.db.WithContext(ctx).Create(identity).Error
}

func (r *identityRepoImpl) FindByID(ctx context.Context, id string) (*model.Identity, error) {
	var identity model.Identity
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&identity).Error; err != nil {
		return nil, translateFirst(err, "identity %s not found", id)
	}
	return &identity, nil
}

func (r *identityRepoImpl) FindByProviderAndUID(ctx context.Context, provider, providerUserID string) (*model.Identity, error) {
	var identity model.Identity
	err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		First(&identity).Error
	if err != nil {
		return nil, translateFirst(err, "identity %s/%s not found", provider, providerUserID)
	}
	return &identity, nil
}

func (r *identityRepoImpl) ListByUser(ctx context.Context, userID string) ([]*model.Identity, error) {
	var out []*model.Identity
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *identityRepoImpl) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Identity{})
	return updateRowsAffected(res, fmt.Sprintf("identity %s not found", id))
}

func (r *identityRepoImpl) CountByUser(ctx context.Context, userID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.Identity{}).Where("user_id = ?", userID).Count(&count).Error
	return count, err
}
