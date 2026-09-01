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

// AdminResourceService manages the unified permission resources (menus, APIs,
// buttons) including the idempotent batch import.
type AdminResourceService interface {
	Tree(ctx context.Context, actor *AdminActor, appKey string) ([]*dto.AdminResourceItem, error)
	Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateResourceReq) (*dto.AdminResourceItem, error)
	Update(ctx context.Context, actor *AdminActor, appKey, resourceID string, req *dto.UpdateResourceReq) (*dto.AdminResourceItem, error)
	Delete(ctx context.Context, actor *AdminActor, appKey, resourceID string) error
	Batch(ctx context.Context, actor *AdminActor, appKey string, req *dto.BatchResourcesReq, mode string) (*dto.BatchResourcesResp, error)
}

type adminResourceServiceImpl struct {
	c container.Container
}

// NewAdminResourceService builds the admin resource service.
func NewAdminResourceService(c container.Container) AdminResourceService {
	return &adminResourceServiceImpl{c: c}
}

func (s *adminResourceServiceImpl) toItem(r *model.Resource) *dto.AdminResourceItem {
	item := &dto.AdminResourceItem{
		ID:        r.Id,
		ParentID:  r.ParentID,
		Type:      r.Type,
		Code:      r.Code,
		Name:      r.Name,
		Sort:      r.Sort,
		Status:    r.Status,
		Visible:   r.Visible,
		Icon:      deref(r.Icon),
		Method:    deref(r.Method),
		RoutePath: deref(r.RoutePath),
		Children:  []*dto.AdminResourceItem{},
	}
	if r.Type == domain.ResourceTypeMenu {
		item.Path = deref(r.RoutePath)
	} else {
		item.Path = deref(r.RoutePath)
	}
	return item
}

// tree assembles a full resource tree from a flat (sorted) list.
func (s *adminResourceServiceImpl) tree(ctx context.Context, appID string) ([]*dto.AdminResourceItem, error) {
	rows, err := s.c.ResourceRepo().ListByApp(ctx, appID)
	if err != nil {
		return nil, verrors.Wrap(err, "list resources")
	}
	byID := make(map[string]*model.Resource, len(rows))
	nodes := make(map[string]*dto.AdminResourceItem, len(rows))
	for _, r := range rows {
		byID[r.Id] = r
		nodes[r.Id] = s.toItem(r)
	}
	var roots []*dto.AdminResourceItem
	for _, r := range rows {
		node := nodes[r.Id]
		if r.ParentID != nil && nodes[*r.ParentID] != nil {
			nodes[*r.ParentID].Children = append(nodes[*r.ParentID].Children, node)
		} else {
			roots = append(roots, node)
		}
	}
	return roots, nil
}

func (s *adminResourceServiceImpl) Tree(ctx context.Context, actor *AdminActor, appKey string) ([]*dto.AdminResourceItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	return s.tree(ctx, app.Id)
}

// resolveParent validates a parent id (must exist within the app).
func (s *adminResourceServiceImpl) resolveParent(ctx context.Context, app *model.App, parentID string) (*string, error) {
	if parentID == "" {
		return nil, nil
	}
	parent, err := s.c.ResourceRepo().FindByID(ctx, parentID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.BadRequestError("parent resource not found")
		}
		return nil, verrors.Wrap(err, "find parent")
	}
	if parent.AppID != app.Id {
		return nil, verrors.BadRequestError("parent resource belongs to another app")
	}
	return &parent.Id, nil
}

// routeFor maps the request path fields onto the route_path column: menu
// resources carry their nav path there; api resources use method+route_path.
func routeFor(typ, path, method, routePath string) *string {
	switch typ {
	case domain.ResourceTypeMenu:
		if path != "" {
			return &path
		}
		return nil
	case domain.ResourceTypeAPI:
		if routePath != "" {
			return &routePath
		}
		return nil
	default:
		return nil
	}
}

func methodPtr(typ, method string) *string {
	if typ == domain.ResourceTypeAPI && method != "" {
		return &method
	}
	return nil
}

func (s *adminResourceServiceImpl) Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateResourceReq) (*dto.AdminResourceItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	if _, err := s.c.ResourceRepo().FindByAppAndCode(ctx, app.Id, req.Code); err == nil {
		return nil, verrors.ConflictError("resource code already exists in the app")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find resource by code")
	}
	parentID, err := s.resolveParent(ctx, app, req.ParentID)
	if err != nil {
		return nil, err
	}
	if req.Type == domain.ResourceTypeAPI && req.Method == "" {
		return nil, verrors.BadRequestError("method is required for api resources")
	}
	resource := &model.Resource{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		AppID:        app.Id,
		ParentID:     parentID,
		Type:         req.Type,
		Code:         req.Code,
		Name:         req.Name,
		Status:       domain.ResourceStatusActive,
		Visible:      true,
		RoutePath:    routeFor(req.Type, req.Path, req.Method, req.RoutePath),
		Method:       methodPtr(req.Type, req.Method),
	}
	if req.Sort != nil {
		resource.Sort = *req.Sort
	}
	if req.Visible != nil {
		resource.Visible = *req.Visible
	}
	if req.Status != "" {
		resource.Status = req.Status
	}
	if req.Icon != "" {
		i := req.Icon
		resource.Icon = &i
	}
	if err := s.c.ResourceRepo().Create(ctx, resource); err != nil {
		return nil, verrors.Wrap(err, "create resource")
	}
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	item := s.toItem(resource)
	return item, nil
}

// resourceOfApp loads a resource and asserts it belongs to the app.
func (s *adminResourceServiceImpl) resourceOfApp(ctx context.Context, app *model.App, resourceID string) (*model.Resource, error) {
	resource, err := s.c.ResourceRepo().FindByID(ctx, resourceID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("resource not found")
		}
		return nil, verrors.Wrap(err, "find resource")
	}
	if resource.AppID != app.Id {
		return nil, verrors.NotFoundError("resource not found")
	}
	return resource, nil
}

func (s *adminResourceServiceImpl) Update(ctx context.Context, actor *AdminActor, appKey, resourceID string, req *dto.UpdateResourceReq) (*dto.AdminResourceItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	resource, err := s.resourceOfApp(ctx, app, resourceID)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if req.Name != nil {
		fields["name"] = *req.Name
	}
	if req.ParentID != nil {
		parentID, err := s.resolveParent(ctx, app, *req.ParentID)
		if err != nil {
			return nil, err
		}
		fields["parent_id"] = parentID
	}
	if req.Path != nil && resource.Type == domain.ResourceTypeMenu {
		fields["route_path"] = *req.Path
	}
	if req.RoutePath != nil {
		fields["route_path"] = *req.RoutePath
	}
	if req.Method != nil && resource.Type == domain.ResourceTypeAPI {
		fields["method"] = *req.Method
	}
	if req.Icon != nil {
		fields["icon"] = *req.Icon
	}
	if req.Sort != nil {
		fields["sort"] = *req.Sort
	}
	if req.Visible != nil {
		fields["visible"] = *req.Visible
	}
	if req.Status != nil {
		fields["status"] = *req.Status
		// Disabling a resource removes its policies on the next reload; sync
		// the in-memory enforcer incrementally as well.
		if *req.Status == domain.ResourceStatusDisabled {
			_ = s.removeResourceRules(ctx, resource)
		}
	}
	if len(fields) > 0 {
		if err := s.c.ResourceRepo().UpdateFields(ctx, resource.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update resource")
		}
	}
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	updated, err := s.c.ResourceRepo().FindByID(ctx, resource.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "reload resource")
	}
	return s.toItem(updated), nil
}

// removeResourceRules drops every in-memory policy referencing the resource
// (role bindings + direct grants) — used on delete/disable.
func (s *adminResourceServiceImpl) removeResourceRules(ctx context.Context, resource *model.Resource) error {
	app, err := s.c.AppRepo().FindByID(ctx, resource.AppID)
	if err != nil {
		return err
	}
	bindings, err := s.c.RoleResourceRepo().ListByResource(ctx, resource.Id)
	if err == nil {
		for _, b := range bindings {
			role, err := s.c.RoleRepo().FindByID(ctx, b.RoleID)
			if err != nil {
				continue
			}
			if role.Scope == domain.RoleScopeApp && role.AppID != resource.AppID {
				continue
			}
			_ = syncRoleResourceRule(ctx, s.c, role, app.Key, resource.Code, b.Effect, false)
		}
	}
	grants, err := s.c.AccountGrantRepo().ListByResource(ctx, resource.Id)
	if err == nil {
		for _, g := range grants {
			_ = syncGrantRule(ctx, s.c, g.AccountID, app.Key, resource.Code, g.Effect, false)
		}
	}
	return nil
}

func (s *adminResourceServiceImpl) Delete(ctx context.Context, actor *AdminActor, appKey, resourceID string) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	resource, err := s.resourceOfApp(ctx, app, resourceID)
	if err != nil {
		return err
	}
	// Reject deletes with children (tree consistency).
	all, err := s.c.ResourceRepo().ListByApp(ctx, app.Id)
	if err != nil {
		return verrors.Wrap(err, "list resources")
	}
	for _, r := range all {
		if r.ParentID != nil && *r.ParentID == resource.Id {
			return verrors.ConflictError("resource has children, delete them first")
		}
	}
	if err := s.c.ResourceRepo().Delete(ctx, resource.Id); err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("resource not found")
		}
		return verrors.Wrap(err, "delete resource")
	}
	_ = s.removeResourceRules(ctx, resource)
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	return nil
}

// Batch upserts resources by code (two passes so parents may appear anywhere
// in the payload). With mode=replace, resources absent from the payload are
// disabled. Response counts created/updated/disabled rows.
func (s *adminResourceServiceImpl) Batch(ctx context.Context, actor *AdminActor, appKey string, req *dto.BatchResourcesReq, mode string) (*dto.BatchResourcesResp, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	resp := &dto.BatchResourcesResp{}

	// Pass 1: upsert each item without its parent.
	for _, item := range req.Items {
		existing, err := s.c.ResourceRepo().FindByAppAndCode(ctx, app.Id, item.Code)
		if err != nil && !repository.IsNotFound(err) {
			return nil, verrors.Wrap(err, "find resource by code")
		}
		status := domain.ResourceStatusActive
		if item.Status != "" {
			status = item.Status
		}
		visible := true
		if item.Visible != nil {
			visible = *item.Visible
		}
		sort := 0
		if item.Sort != nil {
			sort = *item.Sort
		}
		if repository.IsNotFound(err) {
			resource := &model.Resource{
				BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
				AppID:        app.Id,
				Type:         item.Type,
				Code:         item.Code,
				Name:         item.Name,
				Sort:         sort,
				Status:       status,
				Visible:      visible,
				RoutePath:    routeFor(item.Type, item.Path, item.Method, item.RoutePath),
				Method:       methodPtr(item.Type, item.Method),
			}
			if item.Icon != "" {
				i := item.Icon
				resource.Icon = &i
			}
			if err := s.c.ResourceRepo().Create(ctx, resource); err != nil {
				return nil, verrors.Wrap(err, "batch create resource")
			}
			resp.Created++
			continue
		}
		fields := map[string]any{
			"name":       item.Name,
			"type":       item.Type,
			"sort":       sort,
			"status":     status,
			"visible":    visible,
			"route_path": routeFor(item.Type, item.Path, item.Method, item.RoutePath),
			"method":     methodPtr(item.Type, item.Method),
		}
		if item.Icon != "" {
			fields["icon"] = item.Icon
		} else {
			fields["icon"] = nil
		}
		// Disabling an upserted resource syncs the enforcer incrementally.
		if status == domain.ResourceStatusDisabled && existing.Status != domain.ResourceStatusDisabled {
			_ = s.removeResourceRules(ctx, existing)
		}
		if err := s.c.ResourceRepo().UpdateFields(ctx, existing.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "batch update resource")
		}
		resp.Updated++
	}

	// Pass 2: resolve parent_code references against the (now up-to-date) set.
	for _, item := range req.Items {
		if item.ParentCode == "" {
			continue
		}
		parent, err := s.c.ResourceRepo().FindByAppAndCode(ctx, app.Id, item.ParentCode)
		if err != nil {
			if repository.IsNotFound(err) {
				return nil, verrors.BadRequestError("unknown parent_code " + item.ParentCode)
			}
			return nil, verrors.Wrap(err, "resolve parent")
		}
		child, err := s.c.ResourceRepo().FindByAppAndCode(ctx, app.Id, item.Code)
		if err != nil {
			return nil, verrors.Wrap(err, "reload child")
		}
		if child.ParentID == nil || *child.ParentID != parent.Id {
			if err := s.c.ResourceRepo().UpdateFields(ctx, child.Id, map[string]any{"parent_id": parent.Id}); err != nil {
				return nil, verrors.Wrap(err, "attach parent")
			}
		}
	}

	// Replace mode disables every resource absent from the payload.
	if mode == "replace" {
		present := make(map[string]struct{}, len(req.Items))
		for _, item := range req.Items {
			present[item.Code] = struct{}{}
		}
		all, err := s.c.ResourceRepo().ListByApp(ctx, app.Id)
		if err != nil {
			return nil, verrors.Wrap(err, "list resources")
		}
		for _, r := range all {
			if _, ok := present[r.Code]; ok {
				continue
			}
			if r.Status == domain.ResourceStatusDisabled {
				continue
			}
			_ = s.removeResourceRules(ctx, r)
			if err := s.c.ResourceRepo().UpdateFields(ctx, r.Id, map[string]any{"status": domain.ResourceStatusDisabled}); err != nil {
				return nil, verrors.Wrap(err, "disable missing resource")
			}
			resp.Disabled++
		}
	}

	_ = casbinNotify(ctx, s.c, []string{app.Key})
	return resp, nil
}
