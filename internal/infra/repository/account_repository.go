package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// AccountRepo persists workspace (per-app) accounts. Account emails are
// lower-normalized; uniqueness is (app_id, lower(email)).
type AccountRepo interface {
	Create(ctx context.Context, account *model.Account) error
	FindByID(ctx context.Context, id string) (*model.Account, error)
	FindByAppAndEmail(ctx context.Context, appID, email string) (*model.Account, error)
	FindByAppAndUsername(ctx context.Context, appID, username string) (*model.Account, error)
	// ListByIdentity returns all workspace accounts bound to the identity
	// (the portal workspace list data source).
	ListByIdentity(ctx context.Context, identityID string) ([]*model.Account, error)
	// ListByApp returns the app's accounts; statusFilter nil means all.
	ListByApp(ctx context.Context, appID string, statusFilter *string) ([]*model.Account, error)
	// ListByAppQuery is the admin console variant: q (optional) matches
	// email/username substring (lower-normalized); statusFilter nil means all.
	ListByAppQuery(ctx context.Context, appID string, q *string, statusFilter *string) ([]*model.Account, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	TouchLastLogin(ctx context.Context, id string, at time.Time) error
}

type accountRepoImpl struct {
	db *gorm.DB
}

func NewAccountRepo(db *gorm.DB) AccountRepo {
	return &accountRepoImpl{db: db}
}

func (r *accountRepoImpl) Create(ctx context.Context, account *model.Account) error {
	return r.db.WithContext(ctx).Create(account).Error
}

func (r *accountRepoImpl) FindByID(ctx context.Context, id string) (*model.Account, error) {
	var account model.Account
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&account).Error; err != nil {
		return nil, translateFirst(err, "account %s not found", id)
	}
	return &account, nil
}

func (r *accountRepoImpl) FindByAppAndEmail(ctx context.Context, appID, email string) (*model.Account, error) {
	var account model.Account
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND LOWER(email) = ?", appID, strings.ToLower(strings.TrimSpace(email))).
		First(&account).Error
	if err != nil {
		return nil, translateFirst(err, "account with email %s not found in app %s", email, appID)
	}
	return &account, nil
}

func (r *accountRepoImpl) FindByAppAndUsername(ctx context.Context, appID, username string) (*model.Account, error) {
	var account model.Account
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND LOWER(username) = ?", appID, strings.ToLower(strings.TrimSpace(username))).
		First(&account).Error
	if err != nil {
		return nil, translateFirst(err, "account %s not found in app %s", username, appID)
	}
	return &account, nil
}

func (r *accountRepoImpl) ListByIdentity(ctx context.Context, identityID string) ([]*model.Account, error) {
	var out []*model.Account
	err := r.db.WithContext(ctx).
		Where("identity_id = ?", identityID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *accountRepoImpl) ListByApp(ctx context.Context, appID string, statusFilter *string) ([]*model.Account, error) {
	q := r.db.WithContext(ctx).Where("app_id = ?", appID)
	if statusFilter != nil && *statusFilter != "" {
		q = q.Where("status = ?", *statusFilter)
	}
	var out []*model.Account
	err := q.Order("created_at ASC").Find(&out).Error
	return out, err
}

func (r *accountRepoImpl) ListByAppQuery(ctx context.Context, appID string, q *string, statusFilter *string) ([]*model.Account, error) {
	query := r.db.WithContext(ctx).Where("app_id = ?", appID)
	if q != nil && strings.TrimSpace(*q) != "" {
		pattern := "%" + strings.ToLower(strings.TrimSpace(*q)) + "%"
		query = query.Where("LOWER(email) LIKE ? OR LOWER(username) LIKE ?", pattern, pattern)
	}
	if statusFilter != nil && *statusFilter != "" {
		query = query.Where("status = ?", *statusFilter)
	}
	var out []*model.Account
	err := query.Order("created_at ASC").Find(&out).Error
	return out, err
}

func (r *accountRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Account{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("account %s not found", id))
}

func (r *accountRepoImpl) TouchLastLogin(ctx context.Context, id string, at time.Time) error {
	return r.UpdateFields(ctx, id, map[string]any{"last_login_at": at})
}
