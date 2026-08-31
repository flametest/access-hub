package service

import (
	"context"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/verrors"
)

// AdminResourceCodePlatformRead is the platform-only code. Possessing it
// implies platform-scope (the loader wildcard only reaches super_admin), so
// org row-level filtering is skipped for such callers.
const AdminResourceCodePlatformRead = "admin:org:read"

// AdminActor is the middleware-resolved admin caller: an admin-app account
// subject plus its row-level org scope.
type AdminActor struct {
	AccountID  string   // admin-app account subject (casbin sub)
	IdentityID string   // owning identity
	Platform   bool     // passes the platform-only admin:org:read code
	OrgIDs     []string // orgs the caller governs (org_role owner|admin)
}

// NewAdminActor resolves the caller's org scope and platform flag. Called
// once per request by the middleware.
func NewAdminActor(ctx context.Context, c container.Container, accountID, identityID string) *AdminActor {
	actor := &AdminActor{AccountID: accountID, IdentityID: identityID}
	ok, err := c.Enforcer().Enforce(casbinSubjectAccount(accountID), PlatformAdminAppKey, AdminResourceCodePlatformRead, "*")
	if err == nil && ok {
		actor.Platform = true
	}
	memberships, err := c.OrgMemberRepo().ListByUser(ctx, identityID)
	if err == nil {
		for _, m := range memberships {
			if m.OrgRole == domain.OrgRoleOwner || m.OrgRole == domain.OrgRoleAdmin {
				actor.OrgIDs = append(actor.OrgIDs, m.OrgID)
			}
		}
	}
	return actor
}

// PlatformAdminAppKey is the admin console app key (dogfood domain).
const PlatformAdminAppKey = "admin"

// requirePlatform rejects non-platform callers (defense in depth on top of
// the middleware's platform-only codes).
func (a *AdminActor) requirePlatform() error {
	if !a.Platform {
		return verrors.ForbiddenError("platform rights required")
	}
	return nil
}

// canAccessOrg reports whether the caller may act inside the org.
func (a *AdminActor) canAccessOrg(orgID *string) bool {
	if a.Platform {
		return true
	}
	if orgID == nil {
		return false
	}
	for _, id := range a.OrgIDs {
		if id == *orgID {
			return true
		}
	}
	return false
}

// accessibleApp loads the app by key and enforces the caller's org scope
// (org_admin callers only touch apps of orgs they administer).
func (a *AdminActor) accessibleApp(ctx context.Context, c container.Container, appKey string) (*model.App, error) {
	app, err := c.AppRepo().FindByKey(ctx, appKey)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, verrors.NotFoundError("app not found")
		}
		return nil, verrors.Wrap(err, "find app")
	}
	if !a.canAccessApp(app) {
		return nil, verrors.ForbiddenError("app outside your organization scope")
	}
	return app, nil
}

// canAccessApp applies the org row-level scope to an app.
func (a *AdminActor) canAccessApp(app *model.App) bool {
	if a.Platform {
		return true
	}
	return a.canAccessOrg(app.OrgID)
}

// containsID reports whether the id list contains id.
func containsID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
