// Admin management of per-app ABAC custom rules (design.md §12 M6). Rules
// are expr-lang expressions evaluated inside the Casbin matcher with the
// typed env {sub, dom, obj, act, roles, now}; they carry an effect
// (allow|deny) and a priority on the fixed ladder (default 40, between grant
// allow 30 and role deny 45). Every mutation validates the expression, syncs
// the in-memory enforcer incrementally and bumps the policy version.
package service

import (
	"context"
	"strings"

	"github.com/flametest/access-hub/internal/container"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

// AdminCustomRuleService manages the per-app ABAC custom rules.
type AdminCustomRuleService interface {
	List(ctx context.Context, actor *AdminActor, appKey string) ([]dto.CustomRuleItem, error)
	Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateCustomRuleReq) (*dto.CustomRuleItem, error)
	Update(ctx context.Context, actor *AdminActor, appKey, ruleID string, req *dto.UpdateCustomRuleReq) (*dto.CustomRuleItem, error)
	Delete(ctx context.Context, actor *AdminActor, appKey, ruleID string) error
	// Test evaluates an expression WITHOUT persisting anything: the env is
	// built from the caller's own admin-app account subject, the target app
	// dom and the request obj/act. Used by the admin console as a dry-run.
	Test(ctx context.Context, actor *AdminActor, appKey string, req *dto.TestCustomRuleReq) (*dto.CustomRuleTestResp, error)
}

type adminCustomRuleServiceImpl struct {
	c container.Container
}

// NewAdminCustomRuleService builds the admin custom-rule service.
func NewAdminCustomRuleService(c container.Container) AdminCustomRuleService {
	return &adminCustomRuleServiceImpl{c: c}
}

func (s *adminCustomRuleServiceImpl) toItem(row *model.CustomRule, appKey string) dto.CustomRuleItem {
	return dto.CustomRuleItem{
		ID:        row.Id,
		AppID:     row.AppID,
		AppKey:    appKey,
		Name:      row.Name,
		Expr:      row.Expr,
		Effect:    row.Effect,
		Priority:  row.Priority,
		Status:    row.Status,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

// validateExpr turns a compile error into a 400 carrying the compiler
// message; a valid expression compiles through the shared cache.
func validateExpr(source string) error {
	if err := casbinx.ValidateExpr(source); err != nil {
		return verrors.BadRequestError("invalid expression: " + err.Error())
	}
	return nil
}

func (s *adminCustomRuleServiceImpl) List(ctx context.Context, actor *AdminActor, appKey string) ([]dto.CustomRuleItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	rows, err := s.c.CustomRuleRepo().ListByApp(ctx, app.Id)
	if err != nil {
		return nil, verrors.Wrap(err, "list custom rules")
	}
	out := make([]dto.CustomRuleItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.toItem(row, app.Key))
	}
	return out, nil
}

// createDefaults fills effect/priority/status defaults shared by Create
// (effect/status are validated by the DTO tags; defaults are defense in
// depth).
func createDefaults(req *dto.CreateCustomRuleReq) (effect string, priority int, status string) {
	effect = req.Effect
	if effect != casbinx.EffectAllow && effect != casbinx.EffectDeny {
		effect = casbinx.EffectAllow
	}
	priority = casbinx.PriorityCustomRuleDefault
	if req.Priority != nil {
		priority = *req.Priority
	}
	status = model.CustomRuleStatusActive
	if req.Status != "" {
		status = req.Status
	}
	return effect, priority, status
}

func (s *adminCustomRuleServiceImpl) Create(ctx context.Context, actor *AdminActor, appKey string, req *dto.CreateCustomRuleReq) (*dto.CustomRuleItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if _, err := s.c.CustomRuleRepo().FindByAppAndName(ctx, app.Id, name); err == nil {
		return nil, verrors.ConflictError("a custom rule with this name already exists in the app")
	} else if !repository.IsNotFound(err) {
		return nil, verrors.Wrap(err, "find custom rule by name")
	}
	if err := validateExpr(req.Expr); err != nil {
		return nil, err
	}
	effect, priority, status := createDefaults(req)
	row := &model.CustomRule{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		AppID:        app.Id,
		Name:         name,
		Expr:         req.Expr,
		Effect:       effect,
		Priority:     priority,
		Status:       status,
	}
	if err := s.c.CustomRuleRepo().Create(ctx, row); err != nil {
		return nil, verrors.Wrap(err, "create custom rule")
	}
	// Active rules participate immediately: incremental enforcer add + reload
	// broadcast + version bump (invalidates authz caches).
	if status == model.CustomRuleStatusActive {
		_ = syncCustomRule(ctx, s.c, app.Key, priority, effect, req.Expr, true)
	}
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditCustomRuleCreated, "custom_rule", row.Id,
		map[string]any{"app_key": app.Key, "name": name, "effect": effect, "priority": priority, "status": status}, "", "")
	item := s.toItem(row, app.Key)
	return &item, nil
}

// ruleOfApp loads a custom rule and asserts it belongs to the app.
func (s *adminCustomRuleServiceImpl) ruleOfApp(ctx context.Context, app *model.App, ruleID string) (*model.CustomRule, error) {
	row, err := s.c.CustomRuleRepo().FindByID(ctx, ruleID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("custom rule not found")
		}
		return nil, verrors.Wrap(err, "find custom rule")
	}
	if row.AppID != app.Id {
		return nil, verrors.NotFoundError("custom rule not found")
	}
	return row, nil
}

func (s *adminCustomRuleServiceImpl) Update(ctx context.Context, actor *AdminActor, appKey, ruleID string, req *dto.UpdateCustomRuleReq) (*dto.CustomRuleItem, error) {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return nil, err
	}
	row, err := s.ruleOfApp(ctx, app, ruleID)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		newName := strings.TrimSpace(*req.Name)
		if newName != row.Name {
			if _, err := s.c.CustomRuleRepo().FindByAppAndName(ctx, app.Id, newName); err == nil {
				return nil, verrors.ConflictError("a custom rule with this name already exists in the app")
			} else if !repository.IsNotFound(err) {
				return nil, verrors.Wrap(err, "find custom rule by name")
			}
		}
	}
	if req.Expr != nil {
		if err := validateExpr(*req.Expr); err != nil {
			return nil, err
		}
	}
	fields := map[string]any{}
	if req.Name != nil {
		fields["name"] = strings.TrimSpace(*req.Name)
	}
	if req.Expr != nil {
		fields["expr"] = *req.Expr
	}
	if req.Effect != nil {
		fields["effect"] = *req.Effect
	}
	if req.Priority != nil {
		fields["priority"] = *req.Priority
	}
	if req.Status != nil {
		fields["status"] = *req.Status
	}
	if len(fields) > 0 {
		// DB is the source of truth: persist first. Only after a committed
		// write do we swap the in-memory rule out with its previous shape and
		// re-add the new one — a failed write must never leave the enforcer
		// missing an active (possibly deny) rule with no reload trigger.
		if err := s.c.CustomRuleRepo().UpdateFields(ctx, row.Id, fields); err != nil {
			return nil, verrors.Wrap(err, "update custom rule")
		}
		updated, err := s.c.CustomRuleRepo().FindByID(ctx, row.Id)
		if err != nil {
			// DB updated but the re-read failed: broadcast a reload so every
			// instance (including this one) converges from the business table.
			_ = casbinNotify(ctx, s.c, []string{app.Key})
			return nil, verrors.Wrap(err, "reload custom rule")
		}
		if row.Status == model.CustomRuleStatusActive {
			_ = syncCustomRule(ctx, s.c, app.Key, row.Priority, row.Effect, row.Expr, false)
		}
		if updated.Status == model.CustomRuleStatusActive {
			_ = syncCustomRule(ctx, s.c, app.Key, updated.Priority, updated.Effect, updated.Expr, true)
		}
		writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditCustomRuleUpdated, "custom_rule", row.Id,
			map[string]any{"app_key": app.Key, "fields": keysOfFields(fields)}, "", "")
		_ = casbinNotify(ctx, s.c, []string{app.Key})
		item := s.toItem(updated, app.Key)
		return &item, nil
	}
	item := s.toItem(row, app.Key)
	return &item, nil
}

func (s *adminCustomRuleServiceImpl) Delete(ctx context.Context, actor *AdminActor, appKey, ruleID string) error {
	app, err := actor.accessibleApp(ctx, s.c, appKey)
	if err != nil {
		return err
	}
	row, err := s.ruleOfApp(ctx, app, ruleID)
	if err != nil {
		return err
	}
	if err := s.c.CustomRuleRepo().Delete(ctx, row.Id); err != nil {
		if repository.IsNotFound(err) {
			return verrors.NotFoundError("custom rule not found")
		}
		return verrors.Wrap(err, "delete custom rule")
	}
	// Drop the in-memory rule (no-op when it was disabled).
	_ = syncCustomRule(ctx, s.c, app.Key, row.Priority, row.Effect, row.Expr, false)
	_ = casbinNotify(ctx, s.c, []string{app.Key})
	writeAudit(ctx, s.c, ActorAccount, actor.AccountID, app.OrgID, AuditCustomRuleDeleted, "custom_rule", row.Id,
		map[string]any{"app_key": app.Key, "name": row.Name}, "", "")
	return nil
}

func (s *adminCustomRuleServiceImpl) Test(ctx context.Context, actor *AdminActor, appKey string, req *dto.TestCustomRuleReq) (*dto.CustomRuleTestResp, error) {
	if _, err := actor.accessibleApp(ctx, s.c, appKey); err != nil {
		return nil, err
	}
	if err := validateExpr(req.Expr); err != nil {
		return nil, err
	}
	obj := strings.TrimSpace(req.Obj)
	if obj == "" {
		obj = "test:obj"
	}
	act := strings.TrimSpace(req.Act)
	if act == "" {
		act = "*"
	}
	// The dry-run evaluates against the CALLER's own admin-app account
	// subject in the target app dom; roles resolve from the enforcer for that
	// subject in that dom (plus the wildcard/global domain).
	sub := casbinSubjectAccount(actor.AccountID)
	roles := s.c.Enforcer().RolesOfSubjectInDomain(sub, appKey)
	env := casbinx.ExprEnv{
		Sub:   sub,
		Dom:   appKey,
		Obj:   obj,
		Act:   act,
		Roles: roles,
	}
	allowed, err := casbinx.TestExpr(req.Expr, env)
	resp := &dto.CustomRuleTestResp{Allowed: allowed}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

// keysOfFields lists the map keys (audit detail).
func keysOfFields(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
