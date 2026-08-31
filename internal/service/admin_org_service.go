package service

import (
	"context"
	"strings"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

// AdminOrgService manages orgs and their governance members.
type AdminOrgService interface {
	List(ctx context.Context, actor *AdminActor) ([]dto.OrgItem, error)
	Create(ctx context.Context, actor *AdminActor, req *dto.CreateOrgReq) (*dto.OrgItem, error)
	Update(ctx context.Context, actor *AdminActor, orgKey string, req *dto.UpdateOrgReq) (*dto.OrgItem, error)
	ListMembers(ctx context.Context, actor *AdminActor, orgKey string) ([]dto.OrgMemberItem, error)
	AddMember(ctx context.Context, actor *AdminActor, orgKey string, req *dto.AddOrgMemberReq) (*dto.OrgMemberItem, error)
	RemoveMember(ctx context.Context, actor *AdminActor, orgKey, userID string) error
}

type adminOrgServiceImpl struct {
	c container.Container
}

// NewAdminOrgService builds the admin org service.
func NewAdminOrgService(c container.Container) AdminOrgService {
	return &adminOrgServiceImpl{c: c}
}

func toOrgItem(org *model.Org) *dto.OrgItem {
	return &dto.OrgItem{ID: org.Id, Key: org.Key, Name: org.Name, Status: org.Status, CreatedAt: org.CreatedAt}
}

func (s *adminOrgServiceImpl) List(ctx context.Context, actor *AdminActor) ([]dto.OrgItem, error) {
	if err := actor.requirePlatform(); err != nil {
		return nil, err
	}
	orgs, err := s.c.OrgRepo().List(ctx)
	if err != nil {
		return nil, verrors.Wrap(err, "list orgs")
	}
	out := make([]dto.OrgItem, 0, len(orgs))
	for _, org := range orgs {
		out = append(out, *toOrgItem(org))
	}
	return out, nil
}

func (s *adminOrgServiceImpl) Create(ctx context.Context, actor *AdminActor, req *dto.CreateOrgReq) (*dto.OrgItem, error) {
	if err := actor.requirePlatform(); err != nil {
		return nil, err
	}
	key := strings.ToLower(strings.TrimSpace(req.Key))
	if _, err := s.c.OrgRepo().FindByKey(ctx, key); err == nil {
		return nil, verrors.ConflictError("org key already exists")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find org by key")
	}
	org := &model.Org{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		Key:          key,
		Name:         req.Name,
		Status:       domain.OrgStatusActive,
	}
	if err := s.c.OrgRepo().Create(ctx, org); err != nil {
		return nil, verrors.Wrap(err, "create org")
	}
	// Creator becomes owner automatically.
	if actor.IdentityID != "" {
		if err := s.c.OrgMemberRepo().Upsert(ctx, org.Id, actor.IdentityID, domain.OrgRoleOwner); err != nil {
			return nil, verrors.Wrap(err, "add creator as org owner")
		}
	}
	return toOrgItem(org), nil
}

func (s *adminOrgServiceImpl) resolveOrg(ctx context.Context, orgKey string) (*model.Org, error) {
	org, err := s.c.OrgRepo().FindByKey(ctx, strings.ToLower(strings.TrimSpace(orgKey)))
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("org not found")
		}
		return nil, verrors.Wrap(err, "find org")
	}
	return org, nil
}

func (s *adminOrgServiceImpl) Update(ctx context.Context, actor *AdminActor, orgKey string, req *dto.UpdateOrgReq) (*dto.OrgItem, error) {
	if err := actor.requirePlatform(); err != nil {
		return nil, err
	}
	org, err := s.resolveOrg(ctx, orgKey)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if req.Name != nil {
		fields["name"] = *req.Name
	}
	if req.Status != nil {
		fields["status"] = *req.Status
	}
	if len(fields) > 0 {
		if err := s.c.OrgRepo().UpdateFields(ctx, org.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update org")
		}
	}
	updated, err := s.c.OrgRepo().FindByID(ctx, org.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload org")
	}
	return toOrgItem(updated), nil
}

func (s *adminOrgServiceImpl) ListMembers(ctx context.Context, actor *AdminActor, orgKey string) ([]dto.OrgMemberItem, error) {
	if err := actor.requirePlatform(); err != nil {
		return nil, err
	}
	org, err := s.resolveOrg(ctx, orgKey)
	if err != nil {
		return nil, err
	}
	members, err := s.c.OrgMemberRepo().ListByOrg(ctx, org.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "list org members")
	}
	out := make([]dto.OrgMemberItem, 0, len(members))
	for _, m := range members {
		item := dto.OrgMemberItem{UserID: m.UserID, OrgRole: m.OrgRole}
		if user, err := s.c.UserRepo().FindByID(ctx, m.UserID); err == nil {
			item.Username = user.Username
			item.Email = user.Email
			item.Nickname = deref(user.Nickname)
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *adminOrgServiceImpl) AddMember(ctx context.Context, actor *AdminActor, orgKey string, req *dto.AddOrgMemberReq) (*dto.OrgMemberItem, error) {
	if err := actor.requirePlatform(); err != nil {
		return nil, err
	}
	org, err := s.resolveOrg(ctx, orgKey)
	if err != nil {
		return nil, err
	}
	var user *model.User
	switch {
	case req.UserID != "":
		user, err = s.c.UserRepo().FindByID(ctx, req.UserID)
		if err != nil {
			return nil, verrors.NotFoundError("user not found")
		}
	case req.Email != "":
		user, err = s.c.UserRepo().FindByEmail(ctx, normalizeEmail(req.Email))
		if err != nil {
			return nil, verrors.NotFoundError("user not found")
		}
	default:
		return nil, verrors.BadRequestError("email or user_id is required")
	}
	if err := s.c.OrgMemberRepo().Upsert(ctx, org.Id, user.Id, req.OrgRole); err != nil {
		return nil, verrors.Wrap(err, "add org member")
	}
	return &dto.OrgMemberItem{
		UserID:   user.Id,
		Username: user.Username,
		Email:    user.Email,
		Nickname: deref(user.Nickname),
		OrgRole:  req.OrgRole,
	}, nil
}

func (s *adminOrgServiceImpl) RemoveMember(ctx context.Context, actor *AdminActor, orgKey, userID string) error {
	if err := actor.requirePlatform(); err != nil {
		return err
	}
	org, err := s.resolveOrg(ctx, orgKey)
	if err != nil {
		return err
	}
	if err := s.c.OrgMemberRepo().Delete(ctx, org.Id, userID); err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("org member not found")
		}
		return verrors.Wrap(err, "remove org member")
	}
	return nil
}
