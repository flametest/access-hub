package domain

import (
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/vgorm"
)

// Resource type values (resources.type).
const (
	ResourceTypeMenu   = "menu"
	ResourceTypeAPI    = "api"
	ResourceTypeButton = "button"
)

// Resource status values (resources.status).
const (
	ResourceStatusActive   = "active"
	ResourceStatusDisabled = "disabled"
)

// Resource is the unified permission unit. code is the permission code used by
// Casbin (exact match, no wildcards).
type Resource struct {
	id        string
	appID     string
	parentID  *string
	typ       string
	code      string
	name      string
	sort      int
	status    string
	visible   bool
	icon      *string
	method    *string
	routePath *string
	extra     []byte
	createdAt time.Time
}

func NewResource(appID, typ, code, name string) *Resource {
	return &Resource{appID: appID, typ: typ, code: code, name: name, status: ResourceStatusActive, visible: true}
}

func NewResourceFromDO(do *model.Resource) *Resource {
	return &Resource{
		id:        do.Id,
		appID:     do.AppID,
		parentID:  do.ParentID,
		typ:       do.Type,
		code:      do.Code,
		name:      do.Name,
		sort:      do.Sort,
		status:    do.Status,
		visible:   do.Visible,
		icon:      do.Icon,
		method:    do.Method,
		routePath: do.RoutePath,
		extra:     do.Extra,
		createdAt: do.CreatedAt,
	}
}

func (r *Resource) ToDO() *model.Resource {
	return &model.Resource{
		BasePostgres: vgorm.BasePostgres{Id: r.id},
		AppID:        r.appID,
		ParentID:     r.parentID,
		Type:         r.typ,
		Code:         r.code,
		Name:         r.name,
		Sort:         r.sort,
		Status:       r.status,
		Visible:      r.visible,
		Icon:         r.icon,
		Method:       r.method,
		RoutePath:    r.routePath,
		Extra:        r.extra,
	}
}

// IsAPI reports whether the resource is an api-type resource (method+path set).
func (r *Resource) IsAPI() bool { return r.typ == ResourceTypeAPI }

func (r *Resource) ID() string           { return r.id }
func (r *Resource) AppID() string        { return r.appID }
func (r *Resource) ParentID() *string    { return r.parentID }
func (r *Resource) Type() string         { return r.typ }
func (r *Resource) Code() string         { return r.code }
func (r *Resource) Name() string         { return r.name }
func (r *Resource) Sort() int            { return r.sort }
func (r *Resource) Status() string       { return r.status }
func (r *Resource) Visible() bool        { return r.visible }
func (r *Resource) Icon() *string        { return r.icon }
func (r *Resource) Method() *string      { return r.method }
func (r *Resource) RoutePath() *string   { return r.routePath }
func (r *Resource) Extra() []byte        { return r.extra }
func (r *Resource) CreatedAt() time.Time { return r.createdAt }

func (r *Resource) SetAppID(v string)      { r.appID = v }
func (r *Resource) SetParentID(v *string)  { r.parentID = v }
func (r *Resource) SetType(v string)       { r.typ = v }
func (r *Resource) SetCode(v string)       { r.code = v }
func (r *Resource) SetName(v string)       { r.name = v }
func (r *Resource) SetSort(v int)          { r.sort = v }
func (r *Resource) SetStatus(v string)     { r.status = v }
func (r *Resource) SetVisible(v bool)      { r.visible = v }
func (r *Resource) SetIcon(v *string)      { r.icon = v }
func (r *Resource) SetMethod(v *string)    { r.method = v }
func (r *Resource) SetRoutePath(v *string) { r.routePath = v }
func (r *Resource) SetExtra(v []byte)      { r.extra = v }
