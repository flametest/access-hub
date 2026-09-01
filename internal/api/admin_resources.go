// Admin dogfood resource codes (design.md §6.2): the admin console is a
// platform app whose API surface is declared here as code constants and
// synced into the resources table at startup. Platform-only codes are never
// bound to org_admin; app-scoped codes (prefix admin:app:) are.
package api

import (
	"context"
	"strings"

	"github.com/flametest/access-hub/internal/bootstrap"
	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
)

// AdminResourceDef is one admin API route: Code is the permission code
// enforced by RequireAdmin, Method+Path mirror the registered route (1:1),
// Name is the display name of the generated api resource.
type AdminResourceDef struct {
	Code   string
	Method string
	Path   string
	Name   string
}

// AdminResourceDefs is the constant admin resource table. A route checks
// exactly one code; list endpoints use :read, mutations :manage.
func AdminResourceDefs() []AdminResourceDef {
	return []AdminResourceDef{
		// orgs (platform-only)
		{Code: "admin:org:read", Method: "GET", Path: "/api/v1/admin/orgs", Name: "List orgs"},
		{Code: "admin:org:manage", Method: "POST", Path: "/api/v1/admin/orgs", Name: "Create org"},
		{Code: "admin:org:manage", Method: "PATCH", Path: "/api/v1/admin/orgs/{orgKey}", Name: "Update org"},
		{Code: "admin:org:read", Method: "GET", Path: "/api/v1/admin/orgs/{orgKey}/members", Name: "List org members"},
		{Code: "admin:org:member:manage", Method: "POST", Path: "/api/v1/admin/orgs/{orgKey}/members", Name: "Add org member"},
		{Code: "admin:org:member:manage", Method: "DELETE", Path: "/api/v1/admin/orgs/{orgKey}/members/{userId}", Name: "Remove org member"},
		// apps
		{Code: "admin:app:read", Method: "GET", Path: "/api/v1/admin/apps", Name: "List apps"},
		{Code: "admin:app:manage", Method: "POST", Path: "/api/v1/admin/apps", Name: "Create app"},
		{Code: "admin:app:manage", Method: "PATCH", Path: "/api/v1/admin/apps/{appKey}", Name: "Update app"},
		{Code: "admin:app:manage", Method: "DELETE", Path: "/api/v1/admin/apps/{appKey}", Name: "Delete app"},
		// users (identities, platform-only)
		{Code: "admin:user:read", Method: "GET", Path: "/api/v1/admin/users", Name: "List users"},
		{Code: "admin:user:manage", Method: "PATCH", Path: "/api/v1/admin/users/{userId}", Name: "Update user"},
		{Code: "admin:user:manage", Method: "POST", Path: "/api/v1/admin/users/{userId}/reset-password", Name: "Reset user password"},
		// accounts
		{Code: "admin:account:read", Method: "GET", Path: "/api/v1/admin/apps/{appKey}/accounts", Name: "List accounts"},
		{Code: "admin:account:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/accounts", Name: "Create account"},
		{Code: "admin:account:manage", Method: "PATCH", Path: "/api/v1/admin/apps/{appKey}/accounts/{accountId}", Name: "Update account"},
		{Code: "admin:account:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/accounts/{accountId}/reset-password", Name: "Reset account password"},
		{Code: "admin:account:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/accounts/{accountId}/transfer", Name: "Transfer account"},
		{Code: "admin:account:manage", Method: "PUT", Path: "/api/v1/admin/apps/{appKey}/accounts/{accountId}/roles", Name: "Set account roles"},
		{Code: "admin:grant:manage", Method: "GET", Path: "/api/v1/admin/apps/{appKey}/accounts/{accountId}/grants", Name: "List account grants"},
		{Code: "admin:grant:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/accounts/{accountId}/grants", Name: "Add account grant"},
		{Code: "admin:grant:manage", Method: "DELETE", Path: "/api/v1/admin/apps/{appKey}/accounts/{accountId}/grants/{grantId}", Name: "Remove account grant"},
		// invitations
		{Code: "admin:invitation:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/invitations", Name: "Create invitation"},
		{Code: "admin:invitation:manage", Method: "GET", Path: "/api/v1/admin/apps/{appKey}/invitations", Name: "List invitations"},
		{Code: "admin:invitation:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/invitations/{invitationId}/revoke", Name: "Revoke invitation"},
		// resources
		{Code: "admin:resource:manage", Method: "GET", Path: "/api/v1/admin/apps/{appKey}/resources", Name: "Resource tree"},
		{Code: "admin:resource:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/resources", Name: "Create resource"},
		{Code: "admin:resource:manage", Method: "PATCH", Path: "/api/v1/admin/apps/{appKey}/resources/{resourceId}", Name: "Update resource"},
		{Code: "admin:resource:manage", Method: "DELETE", Path: "/api/v1/admin/apps/{appKey}/resources/{resourceId}", Name: "Delete resource"},
		{Code: "admin:resource:manage", Method: "PUT", Path: "/api/v1/admin/apps/{appKey}/resources:batch", Name: "Batch import resources"},
		// roles
		{Code: "admin:role:manage", Method: "GET", Path: "/api/v1/admin/apps/{appKey}/roles", Name: "List roles"},
		{Code: "admin:role:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/roles", Name: "Create role"},
		{Code: "admin:role:manage", Method: "PATCH", Path: "/api/v1/admin/apps/{appKey}/roles/{roleId}", Name: "Update role"},
		{Code: "admin:role:manage", Method: "DELETE", Path: "/api/v1/admin/apps/{appKey}/roles/{roleId}", Name: "Delete role"},
		{Code: "admin:role:manage", Method: "PUT", Path: "/api/v1/admin/apps/{appKey}/roles/{roleId}/resources", Name: "Set role resources"},
		// oauth clients (M4; app-scoped -> org_admin auto-binds)
		{Code: "admin:oauthclient:read", Method: "GET", Path: "/api/v1/admin/apps/{appKey}/oauth-clients", Name: "List oauth clients"},
		{Code: "admin:oauthclient:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/oauth-clients", Name: "Create oauth client"},
		{Code: "admin:oauthclient:manage", Method: "PATCH", Path: "/api/v1/admin/apps/{appKey}/oauth-clients/{clientId}", Name: "Update oauth client"},
		{Code: "admin:oauthclient:manage", Method: "DELETE", Path: "/api/v1/admin/apps/{appKey}/oauth-clients/{clientId}", Name: "Delete oauth client"},
		// custom rules (M6; app-scoped -> org_admin auto-binds)
		{Code: "admin:customrule:read", Method: "GET", Path: "/api/v1/admin/apps/{appKey}/custom-rules", Name: "List custom rules"},
		{Code: "admin:customrule:manage", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/custom-rules", Name: "Create custom rule"},
		{Code: "admin:customrule:manage", Method: "PATCH", Path: "/api/v1/admin/apps/{appKey}/custom-rules/{ruleId}", Name: "Update custom rule"},
		{Code: "admin:customrule:manage", Method: "DELETE", Path: "/api/v1/admin/apps/{appKey}/custom-rules/{ruleId}", Name: "Delete custom rule"},
		{Code: "admin:customrule:read", Method: "POST", Path: "/api/v1/admin/apps/{appKey}/custom-rules/test", Name: "Test custom rule"},
		// audit logs
		{Code: "admin:audit:read", Method: "GET", Path: "/api/v1/admin/audit-logs", Name: "List audit logs"},
		{Code: "admin:audit:read", Method: "GET", Path: "/api/v1/admin/audit-logs/summary", Name: "Audit summary"},
	}
}

// adminPlatformCodePrefixes are the platform-only code families, never bound
// to org_admin. Every other admin code (admin:app:*, admin:account:*,
// admin:invitation:*, admin:resource:*, admin:role:*, admin:grant:*,
// admin:oauthclient:*, admin:customrule:*) is app-scoped and org_admin gets
// it (note: admin:audit:* stays platform-only, so admin:customrule:* is NOT
// swallowed by that family).
var adminPlatformCodePrefixes = []string{"admin:org:", "admin:user:", "admin:audit:"}

// adminResourceCodePlatform reports whether a code is platform-only (never
// bound to org_admin).
func adminResourceCodePlatform(code string) bool {
	for _, prefix := range adminPlatformCodePrefixes {
		if strings.HasPrefix(code, prefix) {
			return true
		}
	}
	return false
}

// SyncAdminResources upserts every constant into the admin app's resources
// (matched by (app, code)), disables stale admin-app api resources, ensures
// the org_admin built-in role is bound to exactly the app-scoped codes, then
// reloads the enforcer and audits the event. Idempotent.
func SyncAdminResources(ctx context.Context, c container.Container) error {
	app, err := c.AppRepo().FindByKey(ctx, bootstrap.PlatformAdminAppKey)
	if err != nil {
		return verrors.Wrap(err, "sync admin resources: find admin app (bootstrap.Run must run first)")
	}
	defs := AdminResourceDefs()
	defCodes := make(map[string]struct{}, len(defs))
	for _, def := range defs {
		defCodes[def.Code] = struct{}{}
	}

	existing, err := c.ResourceRepo().ListByApp(ctx, app.Id)
	if err != nil {
		return verrors.Wrap(err, "sync admin resources: list existing")
	}
	byCode := make(map[string]*model.Resource, len(existing))
	for _, row := range existing {
		byCode[row.Code] = row
	}

	// Upsert every constant (match by (app, code); update the display fields).
	// Resources are unique per (app, code): several admin routes may share
	// one code (e.g. admin:org:manage for create and update) — the first
	// definition owns the resource row, while every route still enforces the
	// same code 1:1 through RequireAdmin.
	resourcesByCode := make(map[string]*model.Resource, len(defs))
	for i, def := range defs {
		if _, dup := resourcesByCode[def.Code]; dup {
			continue
		}
		method := def.Method
		path := def.Path
		if row, ok := byCode[def.Code]; ok {
			fields := map[string]any{"name": def.Name, "method": method, "route_path": path, "type": domain.ResourceTypeAPI}
			if err := c.ResourceRepo().UpdateFields(ctx, row.Id, fields); err != nil {
				return verrors.Wrap(err, "sync admin resources: update "+def.Code)
			}
			row.Method = &method
			row.RoutePath = &path
			resourcesByCode[def.Code] = row
			continue
		}
		row := &model.Resource{
			BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
			AppID:        app.Id,
			Type:         domain.ResourceTypeAPI,
			Code:         def.Code,
			Name:         def.Name,
			Sort:         i,
			Status:       domain.ResourceStatusActive,
			Visible:      true,
			Method:       &method,
			RoutePath:    &path,
		}
		if err := c.ResourceRepo().Create(ctx, row); err != nil {
			return verrors.Wrap(err, "sync admin resources: create "+def.Code)
		}
		resourcesByCode[def.Code] = row
	}

	// Disable prior admin-app api resources not in the constant list.
	for _, row := range existing {
		if row.Type != domain.ResourceTypeAPI {
			continue
		}
		if _, current := defCodes[row.Code]; current {
			continue
		}
		if row.Status == domain.ResourceStatusDisabled {
			continue
		}
		if err := c.ResourceRepo().UpdateFields(ctx, row.Id, map[string]any{"status": domain.ResourceStatusDisabled}); err != nil {
			return verrors.Wrap(err, "sync admin resources: disable stale "+row.Code)
		}
	}

	// Ensure the org_admin built-in role is bound to exactly the app-scoped
	// codes (role_resources).
	orgAdmin, err := c.RoleRepo().FindGlobalByCode(ctx, domain.BuiltInRoleOrgAdmin)
	if err != nil {
		return verrors.Wrap(err, "sync admin resources: find org_admin role")
	}
	desired := make([]string, 0, len(defs))
	for _, def := range defs {
		if adminResourceCodePlatform(def.Code) {
			continue
		}
		desired = append(desired, resourcesByCode[def.Code].Id)
	}
	currentRows, err := c.RoleResourceRepo().ListByRole(ctx, orgAdmin.Id)
	if err != nil {
		return verrors.Wrap(err, "sync admin resources: list org_admin bindings")
	}
	current := make(map[string]struct{}, len(currentRows))
	for _, row := range currentRows {
		current[row.ResourceID] = struct{}{}
	}
	desiredSet := make(map[string]struct{}, len(desired))
	for _, id := range desired {
		desiredSet[id] = struct{}{}
	}
	changed := false
	for id := range current {
		if _, keep := desiredSet[id]; !keep {
			changed = true
			break
		}
	}
	for _, id := range desired {
		if _, has := current[id]; !has {
			changed = true
			break
		}
	}
	if changed {
		items := make([]repository.RoleResourceItem, 0, len(desired))
		for _, id := range desired {
			items = append(items, repository.RoleResourceItem{ResourceID: id, Effect: casbinx.EffectAllow})
		}
		if err := c.RoleResourceRepo().ReplaceForRole(ctx, orgAdmin.Id, items); err != nil {
			return verrors.Wrap(err, "sync admin resources: rebind org_admin")
		}
	}

	if err := c.Enforcer().Reload(); err != nil {
		return verrors.Wrap(err, "sync admin resources: reload enforcer")
	}
	if _, err := casbinx.IncrPolicyVersion(ctx, c.KV(), bootstrap.PlatformAdminAppKey); err != nil {
		// Non-fatal: periodic reconciliation converges.
		_ = err
	}
	_ = c.Enforcer().NotifyReload()
	service.WriteSystemAudit(ctx, c, service.AuditAdminResourceSynced, map[string]any{
		"app_key": bootstrap.PlatformAdminAppKey,
		"defs":    len(defs),
		"rebound": changed,
	})
	return nil
}
