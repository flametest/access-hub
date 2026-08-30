package domain

import (
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// Role scope values (roles.scope).
const (
	RoleScopeApp    = "app"
	RoleScopeGlobal = "global"
)

// Built-in global role codes (roles.code, scope=global, built_in=true). They
// are defined on the platform admin app.
const (
	BuiltInRoleSuperAdmin = "super_admin"
	BuiltInRoleOrgAdmin   = "org_admin"
)

type Role struct {
	id        string
	appID     string
	code      string
	name      string
	scope     string
	builtIn   bool
	createdAt time.Time
}

func NewRole(appID, code, name, scope string) *Role {
	return &Role{appID: appID, code: code, name: name, scope: scope}
}

func NewRoleFromDO(do *model.Role) *Role {
	return &Role{
		id:        do.Id,
		appID:     do.AppID,
		code:      do.Code,
		name:      do.Name,
		scope:     do.Scope,
		builtIn:   do.BuiltIn,
		createdAt: do.CreatedAt,
	}
}

func (r *Role) ToDO() *model.Role {
	return &model.Role{
		BasePostgres: vgorm.BasePostgres{Id: r.id},
		AppID:        r.appID,
		Code:         r.code,
		Name:         r.name,
		Scope:        r.scope,
		BuiltIn:      r.builtIn,
	}
}

// IsGlobal reports whether the role is a global-scope role.
func (r *Role) IsGlobal() bool { return r.scope == RoleScopeGlobal }

// IsSuperAdmin reports whether this is the wildcard super_admin role.
func (r *Role) IsSuperAdmin() bool {
	return r.builtIn && r.scope == RoleScopeGlobal && r.code == BuiltInRoleSuperAdmin
}

func (r *Role) ID() string           { return r.id }
func (r *Role) AppID() string        { return r.appID }
func (r *Role) Code() string         { return r.code }
func (r *Role) Name() string         { return r.name }
func (r *Role) Scope() string        { return r.scope }
func (r *Role) BuiltIn() bool        { return r.builtIn }
func (r *Role) CreatedAt() time.Time { return r.createdAt }

func (r *Role) SetAppID(v string) { r.appID = v }
func (r *Role) SetCode(v string)  { r.code = v }
func (r *Role) SetName(v string)  { r.name = v }
func (r *Role) SetScope(v string) error {
	if v != RoleScopeApp && v != RoleScopeGlobal {
		return verrors.BadRequestError(fmt.Sprintf("invalid role scope %q", v))
	}
	r.scope = v
	return nil
}
func (r *Role) SetBuiltIn(v bool) { r.builtIn = v }
