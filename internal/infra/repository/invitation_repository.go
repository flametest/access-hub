package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
)

// InvitationRepo persists invitations. FindByCodeHash only returns pending,
// non-expired invitations — redemption candidates.
type InvitationRepo interface {
	Create(ctx context.Context, invitation *model.Invitation) error
	FindByID(ctx context.Context, id string) (*model.Invitation, error)
	// FindByCodeHash resolves a redeem code hash to its invitation. Only
	// status=pending and not-yet-expired invitations match; anything else
	// surfaces as NotFoundError.
	FindByCodeHash(ctx context.Context, codeHash string) (*model.Invitation, error)
	ListByApp(ctx context.Context, appID string) ([]*model.Invitation, error)
	// ListPendingByEmail returns pending, unexpired invitations for an email
	// (the social-login "found N workspaces" moment, design.md §12 M5).
	ListPendingByEmail(ctx context.Context, email string) ([]*model.Invitation, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
}

type invitationRepoImpl struct {
	db *gorm.DB
}

func NewInvitationRepo(db *gorm.DB) InvitationRepo {
	return &invitationRepoImpl{db: db}
}

func (r *invitationRepoImpl) Create(ctx context.Context, invitation *model.Invitation) error {
	return r.db.WithContext(ctx).Create(invitation).Error
}

func (r *invitationRepoImpl) FindByID(ctx context.Context, id string) (*model.Invitation, error) {
	var invitation model.Invitation
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&invitation).Error; err != nil {
		return nil, translateFirst(err, "invitation %s not found", id)
	}
	return &invitation, nil
}

func (r *invitationRepoImpl) FindByCodeHash(ctx context.Context, codeHash string) (*model.Invitation, error) {
	var invitation model.Invitation
	err := r.db.WithContext(ctx).
		Where("code_hash = ? AND status = ? AND expires_at > ?", codeHash, "pending", time.Now()).
		First(&invitation).Error
	if err != nil {
		return nil, translateFirst(err, "invitation for the given code not found or no longer redeemable")
	}
	return &invitation, nil
}

func (r *invitationRepoImpl) ListByApp(ctx context.Context, appID string) ([]*model.Invitation, error) {
	var out []*model.Invitation
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("created_at DESC").
		Find(&out).Error
	return out, err
}

func (r *invitationRepoImpl) ListPendingByEmail(ctx context.Context, email string) ([]*model.Invitation, error) {
	var out []*model.Invitation
	err := r.db.WithContext(ctx).
		Where("LOWER(email) = ? AND status = ? AND expires_at > ?", strings.ToLower(strings.TrimSpace(email)), "pending", time.Now()).
		Order("created_at ASC").
		Find(&out).Error
	return out, err
}

func (r *invitationRepoImpl) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&model.Invitation{}).Where("id = ?", id).Updates(fields)
	return updateRowsAffected(res, fmt.Sprintf("invitation %s not found", id))
}
