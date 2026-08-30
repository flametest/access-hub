package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// OrgRepo persists tenants (orgs).
type OrgRepo interface {
	Create(ctx context.Context, org *model.Org) error
	FindByID(ctx context.Context, id string) (*model.Org, error)
	FindByKey(ctx context.Context, key string) (*model.Org, error)
	List(ctx context.Context) ([]*model.Org, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
}

type orgRepoImpl struct {
	db *gorm.DB
}

func NewOrgRepo(db *gorm.DB) OrgRepo {
	return &orgRepoImpl{db: db}
}

func (r *orgRepoImpl) Create(ctx context.Context, org *model.Org) error {
	return r.db.WithContext(ctx).Create(org).Error
}

func (r *orgRepoImpl) FindByID(ctx context.Context, id string) (*model.Org, error) {
	var org model.Org
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&org).Error; err != nil {
		return nil, translateFirst(err, "org %s not found", id)
	}
	return &org, nil
}

func (r *orgRepoImpl) FindByKey(ctx context.Context, key string) (*model.Org, error) {
	var org model.Org
	if err := r.db.WithContext(ctx).Where("key = ?", key).First(&org).Error; err != nil {
		return nil, translateFirst(err, "org %s not found", key)
	}
	return &org, nil
}

func (r *orgRepoImpl) List(ctx context.Context) ([]*model.Org, error) {
	var out []*model.Org
	err := r.db.WithContext(ctx).Order("created_at ASC").Find(&out).Error
	return out, err
}

func (r *orgRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Org{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("org %s not found", id))
}

// OrgMemberRepo persists the governance-only org membership rows.
type OrgMemberRepo interface {
	// Upsert inserts or updates an org membership. The conflict target is the
	// partial unique index (org_id, user_id) WHERE deleted_at IS NULL; a
	// previously soft-deleted row is revived with the new org_role.
	Upsert(ctx context.Context, orgID, userID, orgRole string) error
	FindByOrgAndUser(ctx context.Context, orgID, userID string) (*model.OrgMember, error)
	ListByOrg(ctx context.Context, orgID string) ([]*model.OrgMember, error)
	ListByUser(ctx context.Context, userID string) ([]*model.OrgMember, error)
	// Delete soft-deletes the membership; zero rows yields NotFoundError.
	Delete(ctx context.Context, orgID, userID string) error
}

type orgMemberRepoImpl struct {
	db *gorm.DB
}

func NewOrgMemberRepo(db *gorm.DB) OrgMemberRepo {
	return &orgMemberRepoImpl{db: db}
}

func (r *orgMemberRepoImpl) Upsert(ctx context.Context, orgID, userID, orgRole string) error {
	member := &model.OrgMember{OrgID: orgID, UserID: userID, OrgRole: orgRole}
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "org_id"}, {Name: "user_id"}},
			TargetWhere: clause.Where{Exprs: []clause.Expression{
				clause.Expr{SQL: "deleted_at IS NULL"},
			}},
			DoUpdates: clause.Assignments(map[string]any{
				"org_role":   orgRole,
				"deleted_at": nil,
				"updated_at": time.Now(),
			}),
		}).
		Create(member).Error
}

func (r *orgMemberRepoImpl) FindByOrgAndUser(ctx context.Context, orgID, userID string) (*model.OrgMember, error) {
	var member model.OrgMember
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND user_id = ?", orgID, userID).
		First(&member).Error
	if err != nil {
		return nil, translateFirst(err, "org membership for user %s in org %s not found", userID, orgID)
	}
	return &member, nil
}

func (r *orgMemberRepoImpl) ListByOrg(ctx context.Context, orgID string) ([]*model.OrgMember, error) {
	var out []*model.OrgMember
	err := r.db.WithContext(ctx).
		Where("org_id = ?", orgID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *orgMemberRepoImpl) ListByUser(ctx context.Context, userID string) ([]*model.OrgMember, error) {
	var out []*model.OrgMember
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *orgMemberRepoImpl) Delete(ctx context.Context, orgID, userID string) error {
	res := r.db.WithContext(ctx).
		Where("org_id = ? AND user_id = ?", orgID, userID).
		Delete(&model.OrgMember{})
	return updateRowsAffected(res, fmt.Sprintf("org membership for user %s in org %s not found", userID, orgID))
}
