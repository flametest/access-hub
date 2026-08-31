package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// UserRepo persists primary identities (users). Emails and usernames are
// stored and looked up lower-normalized (see migration/init.sql conventions).
type UserRepo interface {
	Create(ctx context.Context, user *model.User) error
	FindByID(ctx context.Context, id string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByUsername(ctx context.Context, username string) (*model.User, error)
	// FindByUsernameOrEmail resolves a portal login identifier: it tries the
	// username first, then the email (both lower-normalized).
	FindByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	TouchLastLogin(ctx context.Context, id string, at time.Time) error
	// Search lists identities for the admin console: q (optional) matches
	// username/email substring (lower-normalized), offset pagination with the
	// total count of the filtered set.
	Search(ctx context.Context, q string, limit, offset int) ([]*model.User, int64, error)
}

type userRepoImpl struct {
	db *gorm.DB
}

func NewUserRepo(db *gorm.DB) UserRepo {
	return &userRepoImpl{db: db}
}

func (r *userRepoImpl) Create(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepoImpl) FindByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return nil, translateFirst(err, "user %s not found", id)
	}
	return &user, nil
}

func (r *userRepoImpl) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Where("LOWER(email) = ?", strings.ToLower(strings.TrimSpace(email))).First(&user).Error; err != nil {
		return nil, translateFirst(err, "user with email %s not found", email)
	}
	return &user, nil
}

func (r *userRepoImpl) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Where("LOWER(username) = ?", strings.ToLower(strings.TrimSpace(username))).First(&user).Error; err != nil {
		return nil, translateFirst(err, "user %s not found", username)
	}
	return &user, nil
}

func (r *userRepoImpl) FindByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error) {
	ident := strings.ToLower(strings.TrimSpace(identifier))
	var user model.User
	err := r.db.WithContext(ctx).
		Where("LOWER(username) = ? OR LOWER(email) = ?", ident, ident).
		First(&user).Error
	if err != nil {
		return nil, translateFirst(err, "user %s not found", identifier)
	}
	return &user, nil
}

func (r *userRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("user %s not found", id))
}

func (r *userRepoImpl) TouchLastLogin(ctx context.Context, id string, at time.Time) error {
	return r.UpdateFields(ctx, id, map[string]any{"last_login_at": at})
}

func (r *userRepoImpl) Search(ctx context.Context, q string, limit, offset int) ([]*model.User, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	query := r.db.WithContext(ctx).Model(&model.User{})
	if trimmed := strings.TrimSpace(q); trimmed != "" {
		pattern := "%" + strings.ToLower(trimmed) + "%"
		query = query.Where("LOWER(username) LIKE ? OR LOWER(email) LIKE ?", pattern, pattern)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []*model.User
	err := query.Order("created_at ASC").Limit(limit).Offset(offset).Find(&out).Error
	return out, total, err
}
