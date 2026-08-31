package service

import (
	"context"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/password"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
)

// AdminUserService manages identities (users) on the platform level.
type AdminUserService interface {
	List(ctx context.Context, q string, page, pageSize int) (*dto.AdminUserPage, error)
	UpdateStatus(ctx context.Context, actor *AdminActor, userID string, req *dto.UpdateUserReq) (*dto.AdminUserItem, error)
	ResetPassword(ctx context.Context, actor *AdminActor, userID string, req *dto.ResetPasswordReq) error
}

type adminUserServiceImpl struct {
	c container.Container
}

// NewAdminUserService builds the admin user service.
func NewAdminUserService(c container.Container) AdminUserService {
	return &adminUserServiceImpl{c: c}
}

func toAdminUserItem(u *model.User) dto.AdminUserItem {
	return dto.AdminUserItem{
		ID:            u.Id,
		Username:      u.Username,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Nickname:      deref(u.Nickname),
		Status:        u.Status,
		CreatedAt:     u.CreatedAt,
		LastLoginAt:   u.LastLoginAt,
	}
}

func (s *adminUserServiceImpl) List(ctx context.Context, q string, page, pageSize int) (*dto.AdminUserPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	users, total, err := s.c.UserRepo().Search(ctx, q, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, verrors.Wrap(err, "search users")
	}
	items := make([]dto.AdminUserItem, 0, len(users))
	for _, u := range users {
		items = append(items, toAdminUserItem(u))
	}
	return &dto.AdminUserPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *adminUserServiceImpl) UpdateStatus(ctx context.Context, actor *AdminActor, userID string, req *dto.UpdateUserReq) (*dto.AdminUserItem, error) {
	if err := actor.requirePlatform(); err != nil {
		return nil, err
	}
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return nil, verrors.NotFoundError("user not found")
	}
	if err := s.c.UserRepo().UpdateFields(ctx, user.Id, map[string]any{"status": req.Status}); err != nil {
		return nil, verrors.Wrap(err, "update user status")
	}
	// Disabling an identity cuts its portal sessions immediately.
	if req.Status == domain.UserStatusDisabled {
		if err := s.c.SessionRepo().RevokeAllForUserByScope(ctx, user.Id, domain.SessionScopeIdentity, nowUTC()); err != nil {
			return nil, verrors.Wrap(err, "revoke identity sessions")
		}
	}
	updated, err := s.c.UserRepo().FindByID(ctx, user.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload user")
	}
	item := toAdminUserItem(updated)
	return &item, nil
}

func (s *adminUserServiceImpl) ResetPassword(ctx context.Context, actor *AdminActor, userID string, req *dto.ResetPasswordReq) error {
	if err := actor.requirePlatform(); err != nil {
		return err
	}
	user, err := s.c.UserRepo().FindByID(ctx, userID)
	if err != nil {
		return verrors.NotFoundError("user not found")
	}
	if err := password.ValidatePolicy(req.NewPassword); err != nil {
		return err
	}
	hash, err := password.Hash(req.NewPassword, s.c.Cfg().Auth.BcryptCost)
	if err != nil {
		return err
	}
	if err := s.c.UserRepo().UpdateFields(ctx, user.Id, map[string]any{
		"password_hash":        hash,
		"must_change_password": true,
	}); err != nil {
		return verrors.Wrap(err, "reset password")
	}
	if err := s.c.SessionRepo().RevokeAllForUserByScope(ctx, user.Id, domain.SessionScopeIdentity, nowUTC()); err != nil {
		return verrors.Wrap(err, "revoke identity sessions")
	}
	writeAudit(ctx, s.c, ActorIdentity, actor.IdentityID, nil, AuditPasswordReset, "user", user.Id,
		map[string]any{"via": "admin"}, "", "")
	return nil
}
