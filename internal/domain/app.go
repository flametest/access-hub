package domain

import (
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
)

// App type values (apps.type).
const (
	AppTypeWeb     = "web"
	AppTypeNative  = "native"
	AppTypeService = "service"
)

// App status values (apps.status).
const (
	AppStatusActive   = "active"
	AppStatusDisabled = "disabled"
)

type App struct {
	id          string
	key         string
	orgID       *string
	name        string
	typ         string
	description *string
	logoURL     *string
	status      string
	createdAt   time.Time
}

func NewApp(key, name string, orgID *string) *App {
	return &App{key: key, orgID: orgID, name: name, typ: AppTypeWeb, status: AppStatusActive}
}

func NewAppFromDO(do *model.App) *App {
	return &App{
		id:          do.Id,
		key:         do.Key,
		orgID:       do.OrgID,
		name:        do.Name,
		typ:         do.Type,
		description: do.Description,
		logoURL:     do.LogoURL,
		status:      do.Status,
		createdAt:   do.CreatedAt,
	}
}

func (a *App) ToDO() *model.App {
	return &model.App{
		BasePostgres: vgorm.BasePostgres{Id: a.id},
		Key:          a.key,
		OrgID:        a.orgID,
		Name:         a.name,
		Type:         a.typ,
		Description:  a.description,
		LogoURL:      a.logoURL,
		Status:       a.status,
	}
}

// IsPlatformApp reports whether the app is a platform app (org_id NULL).
func (a *App) IsPlatformApp() bool { return a.orgID == nil }

// Disable transitions active -> disabled.
func (a *App) Disable() error {
	if a.status != AppStatusActive {
		return verrors.ConflictError(fmt.Sprintf("app %s not active (current: %s)", a.id, a.status))
	}
	a.status = AppStatusDisabled
	return nil
}

// Enable transitions disabled -> active.
func (a *App) Enable() error {
	if a.status != AppStatusDisabled {
		return verrors.ConflictError(fmt.Sprintf("app %s not disabled (current: %s)", a.id, a.status))
	}
	a.status = AppStatusActive
	return nil
}

func (a *App) ID() string           { return a.id }
func (a *App) Key() string          { return a.key }
func (a *App) OrgID() *string       { return a.orgID }
func (a *App) Name() string         { return a.name }
func (a *App) Type() string         { return a.typ }
func (a *App) Description() *string { return a.description }
func (a *App) LogoURL() *string     { return a.logoURL }
func (a *App) Status() string       { return a.status }
func (a *App) CreatedAt() time.Time { return a.createdAt }

func (a *App) SetKey(v string)          { a.key = v }
func (a *App) SetOrgID(v *string)       { a.orgID = v }
func (a *App) SetName(v string)         { a.name = v }
func (a *App) SetType(v string)         { a.typ = v }
func (a *App) SetDescription(v *string) { a.description = v }
func (a *App) SetLogoURL(v *string)     { a.logoURL = v }
