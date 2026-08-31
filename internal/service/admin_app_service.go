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

// AdminAppService manages app registrations.
type AdminAppService interface {
	List(ctx context.Context, actor *AdminActor, orgKey string) ([]dto.AppItem, error)
	Create(ctx context.Context, actor *AdminActor, req *dto.CreateAppReq) (*dto.AppItem, error)
	Update(ctx context.Context, actor *AdminActor, appKey string, req *dto.UpdateAppReq) (*dto.AppItem, error)
	Delete(ctx context.Context, actor *AdminActor, appKey string) error
}

type adminAppServiceImpl struct {
	c container.Container
}

// NewAdminAppService builds the admin app service.
func NewAdminAppService(c container.Container) AdminAppService {
	return &adminAppServiceImpl{c: c}
}

func (s *adminAppServiceImpl) toItem(ctx context.Context, app *model.App) *dto.AppItem {
	item := dto.AppItem{
		ID:          app.Id,
		Key:         app.Key,
		OrgID:       app.OrgID,
		Name:        app.Name,
		Type:        app.Type,
		Description: deref(app.Description),
		LogoURL:     deref(app.LogoURL),
		Status:      app.Status,
		CreatedAt:   app.CreatedAt,
	}
	if app.OrgID != nil {
		if org, err := s.c.OrgRepo().FindByID(ctx, *app.OrgID); err == nil {
			item.OrgKey = org.Key
		}
	}
	return &item
}

func (s *adminAppServiceImpl) List(ctx context.Context, actor *AdminActor, orgKey string) ([]dto.AppItem, error) {
	var apps []*model.App
	switch {
	case orgKey != "":
		org, err := s.c.OrgRepo().FindByKey(ctx, strings.ToLower(strings.TrimSpace(orgKey)))
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.NotFoundError("org not found")
			}
			return nil, verrors.Wrap(err, "find org")
		}
		if !actor.canAccessOrg(&org.Id) {
			return nil, verrors.ForbiddenError("org outside your scope")
		}
		list, err := s.c.AppRepo().List(ctx, &org.Id)
		if err != nil {
			return nil, verrors.Wrap(err, "list apps")
		}
		apps = list
	case !actor.Platform:
		// org_admin: auto-filtered to the orgs they administer.
		apps = nil
		for _, orgID := range actor.OrgIDs {
			list, err := s.c.AppRepo().List(ctx, &orgID)
			if err != nil {
				return nil, verrors.Wrap(err, "list apps")
			}
			apps = append(apps, list...)
		}
	default:
		list, err := s.c.AppRepo().List(ctx, nil)
		if err != nil {
			return nil, verrors.Wrap(err, "list apps")
		}
		apps = list
	}
	out := make([]dto.AppItem, 0, len(apps))
	for _, app := range apps {
		out = append(out, *s.toItem(ctx, app))
	}
	return out, nil
}

func (s *adminAppServiceImpl) Create(ctx context.Context, actor *AdminActor, req *dto.CreateAppReq) (*dto.AppItem, error) {
	key := strings.ToLower(strings.TrimSpace(req.Key))
	if _, err := s.c.AppRepo().FindByKey(ctx, key); err == nil {
		return nil, verrors.ConflictError("app key already exists")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find app by key")
	}
	var orgID *string
	if req.OrgKey != "" {
		org, err := s.c.OrgRepo().FindByKey(ctx, strings.ToLower(strings.TrimSpace(req.OrgKey)))
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.NotFoundError("org not found")
			}
			return nil, verrors.Wrap(err, "find org")
		}
		if !actor.canAccessOrg(&org.Id) {
			return nil, verrors.ForbiddenError("org outside your scope")
		}
		orgID = &org.Id
	} else if !actor.Platform {
		return nil, verrors.BadRequestError("org_key is required")
	}
	typ := req.Type
	if typ == "" {
		typ = domain.AppTypeWeb
	}
	app := &model.App{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		Key:          key,
		OrgID:        orgID,
		Name:         req.Name,
		Type:         typ,
		Status:       domain.AppStatusActive,
	}
	if req.Description != "" {
		d := req.Description
		app.Description = &d
	}
	if req.LogoURL != "" {
		l := req.LogoURL
		app.LogoURL = &l
	}
	if err := s.c.AppRepo().Create(ctx, app); err != nil {
		return nil, verrors.Wrap(err, "create app")
	}
	return s.toItem(ctx, app), nil
}

func (s *adminAppServiceImpl) Update(ctx context.Context, actor *AdminActor, appKey string, req *dto.UpdateAppReq) (*dto.AppItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if req.Name != nil {
		fields["name"] = *req.Name
	}
	if req.Description != nil {
		fields["description"] = *req.Description
	}
	if req.LogoURL != nil {
		fields["logo_url"] = *req.LogoURL
	}
	if req.Status != nil {
		fields["status"] = *req.Status
	}
	if len(fields) > 0 {
		if err := s.c.AppRepo().UpdateFields(ctx, app.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update app")
		}
	}
	updated, err := s.c.AppRepo().FindByID(ctx, app.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload app")
	}
	return s.toItem(ctx, updated), nil
}

func (s *adminAppServiceImpl) Delete(ctx context.Context, actor *AdminActor, appKey string) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	if app.Key == PlatformAdminAppKey {
		return verrors.ForbiddenError("the platform admin app cannot be deleted")
	}
	if err := s.c.AppRepo().Delete(ctx, app.Id); err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("app not found")
		}
		return verrors.Wrap(err, "delete app")
	}
	return nil
}
