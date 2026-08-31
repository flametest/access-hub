package service

import (
	"context"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

// AdminRoleService manages app roles and their resource bindings.
type AdminRoleService interface {
	List(ctx context.Context, actor *AdminActor, appKey string) ([]dto.AdminRoleItem, error)
	Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateRoleReq) (*dto.AdminRoleItem, error)
	Update(ctx context.Context, actor *AdminActor, appKey, roleID string, req *dto.UpdateRoleReq) (*dto.AdminRoleItem, error)
	Delete(ctx context.Context, actor *AdminActor, appKey, roleID string) error
	SetResources(ctx context.Context, actor *AdminActor, appKey, roleID string, req *dto.SetRoleResourcesReq) ([]string, error)
}

type adminRoleServiceImpl struct {
	c container.Container
}

// NewAdminRoleService builds the admin role service.
func NewAdminRoleService(c container.Container) AdminRoleService {
	return &adminRoleServiceImpl{c: c}
}

func (s *adminRoleServiceImpl) toItem(r *model.Role) dto.AdminRoleItem {
	return dto.AdminRoleItem{
		ID:        r.Id,
		AppID:     r.AppID,
		Code:      r.Code,
		Name:      r.Name,
		Scope:     r.Scope,
		BuiltIn:   r.BuiltIn,
		CreatedAt: r.CreatedAt,
	}
}

func (s *adminRoleServiceImpl) List(ctx context.Context, actor *AdminActor, appKey string) ([]dto.AdminRoleItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	roles, err := s.c.RoleRepo().ListByApp(ctx, app.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "list roles")
	}
	out := make([]dto.AdminRoleItem, 0, len(roles))
	for _, role := range roles {
		out = append(out, s.toItem(role))
	}
	return out, nil
}

func (s *adminRoleServiceImpl) Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateRoleReq) (*dto.AdminRoleItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	if _, err := s.c.RoleRepo().FindByAppAndCode(ctx, app.Id, req.Code); err == nil {
		return nil, verrors.ConflictError("role code already exists in the app")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find role by code")
	}
	scope := domain.RoleScopeApp
	if req.Scope != "" {
		scope = req.Scope
	}
	if scope == domain.RoleScopeGlobal && !actor.Platform {
		return nil, verrors.ForbiddenError("global roles are platform-managed")
	}
	role := &model.Role{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		AppID:        app.Id,
		Code:         req.Code,
		Name:         req.Name,
		Scope:        scope,
		BuiltIn:      false,
	}
	if err := s.c.RoleRepo().Create(ctx, role); err != nil {
		return nil, verrors.Wrap(err, "create role")
	}
	item := s.toItem(role)
	return &item, nil
}

// roleOfApp loads a role and asserts it belongs to the app.
func (s *adminRoleServiceImpl) roleOfApp(ctx context.Context, app *model.App, roleID string) (*model.Role, error) {
	role, err := s.c.RoleRepo().FindByID(ctx, roleID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("role not found")
		}
		return nil, verrors.Wrap(err, "find role")
	}
	if role.AppID != app.Id {
		return nil, verrors.NotFoundError("role not found")
	}
	return role, nil
}

func (s *adminRoleServiceImpl) Update(ctx context.Context, actor *AdminActor, appKey, roleID string, req *dto.UpdateRoleReq) (*dto.AdminRoleItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	role, err := s.roleOfApp(ctx, app, roleID)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if req.Name != nil {
		fields["name"] = *req.Name
	}
	if len(fields) > 0 {
		if err := s.c.RoleRepo().UpdateFields(ctx, role.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update role")
		}
	}
	updated, err := s.c.RoleRepo().FindByID(ctx, role.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload role")
	}
	item := s.toItem(updated)
	return &item, nil
}

func (s *adminRoleServiceImpl) Delete(ctx context.Context, actor *AdminActor, appKey, roleID string) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	role, err := s.roleOfApp(ctx, app, roleID)
	if err != nil {
		return err
	}
	if role.BuiltIn {
		return verrors.ForbiddenError("built-in roles cannot be deleted")
	}
	// Remove in-memory rules bound to this role before the DB delete.
	bindings, err := s.c.AccountRoleRepo().ListByRole(ctx, role.Id)
	if err == nil {
		for _, b := range bindings {
			account, err := s.c.AccountRepo().FindByID(ctx, b.AccountID)
			if err != nil {
				continue
			}
			appRow, err := s.c.AppRepo().FindByID(ctx, account.AppID)
			if err != nil {
				continue
			}
			_ = syncAccountRoleBinding(ctx, s.c, account.Id, appRow, role, false)
		}
	}
	attachments, err := s.c.RoleResourceRepo().ListByRole(ctx, role.Id)
	if err == nil {
		for _, a := range attachments {
			resource, err := s.c.ResourceRepo().FindByID(ctx, a.ResourceID)
			if err != nil {
				continue
			}
			resourceApp, err := s.c.AppRepo().FindByID(ctx, resource.AppID)
			if err != nil {
				continue
			}
			_ = syncRoleResourceRule(ctx, s.c, role, resourceApp.Key, resource.Code, false)
		}
	}
	if err := s.c.RoleRepo().UpdateFields(ctx, role.Id, map[string]any{"deleted_at": nowUTC()}); err != nil {
		return verrors.Wrap(err, "delete role")
	}
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	return nil
}

func (s *adminRoleServiceImpl) SetResources(ctx context.Context, actor *AdminActor, appKey, roleID string, req *dto.SetRoleResourcesReq) ([]string, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	role, err := s.roleOfApp(ctx, app, roleID)
	if err != nil {
		return nil, err
	}
	// Validate resources: all must belong to the role's app.
	resources := make([]*model.Resource, 0, len(req.ResourceIDs))
	seen := make(map[string]struct{}, len(req.ResourceIDs))
	for _, id := range req.ResourceIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		resource, err := s.c.ResourceRepo().FindByID(ctx, id)
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.BadRequestError("unknown resource " + id)
			}
			return nil, verrors.Wrap(err, "find resource")
		}
		if resource.AppID != app.Id {
			return nil, verrors.BadRequestError("resource does not belong to the app")
		}
		resources = append(resources, resource)
	}
	// Diff before/after for incremental policy sync.
	beforeRows, err := s.c.RoleResourceRepo().ListByRole(ctx, role.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "list current role resources")
	}
	before := make(map[string]struct{}, len(beforeRows))
	for _, row := range beforeRows {
		before[row.ResourceID] = struct{}{}
	}
	after := make(map[string]struct{}, len(resources))
	resourceIDs := make([]string, 0, len(resources))
	for _, r := range resources {
		after[r.Id] = struct{}{}
		resourceIDs = append(resourceIDs, r.Id)
	}
	if err := s.c.RoleResourceRepo().ReplaceForRole(ctx, role.Id, resourceIDs); err != nil {
		return nil, verrors.Wrap(err, "replace role resources")
	}
	for _, r := range resources {
		if _, had := before[r.Id]; had {
			continue
		}
		if role.Scope == domain.RoleScopeApp && role.AppID == r.AppID {
			_ = syncRoleResourceRule(ctx, s.c, role, app.Key, r.Code, true)
		}
	}
	removedIDs := make([]string, 0)
	for id := range before {
		if _, kept := after[id]; kept {
			continue
		}
		removedIDs = append(removedIDs, id)
		resource, err := s.c.ResourceRepo().FindByID(ctx, id)
		if err != nil {
			continue
		}
		if role.Scope == domain.RoleScopeApp && role.AppID == resource.AppID {
			_ = syncRoleResourceRule(ctx, s.c, role, app.Key, resource.Code, false)
		}
	}
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditRoleGranted, "role", role.Id,
		map[string]any{"added": countAdded(resources, before), "removed_ids": removedIDs}, "", "")
	return resourceCodes(resources), nil
}

func countAdded(resources []*model.Resource, before map[string]struct{}) int {
	n := 0
	for _, r := range resources {
		if _, ok := before[r.Id]; !ok {
			n++
		}
	}
	return n
}

// resourceCodes maps resources to their permission codes (the response of the
// role resource binding endpoint).
func resourceCodes(resources []*model.Resource) []string {
	out := make([]string, 0, len(resources))
	for _, r := range resources {
		out = append(out, r.Code)
	}
	return out
}
