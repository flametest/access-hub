package model

import (
	"github.com/flametest/vita/vgorm"
	"gorm.io/datatypes"
)

// Resource is the unified permission unit (menu/api/button). code is the
// permission code and matches exactly in Casbin (no wildcards); method +
// route_path are used by api-type resources for method+path reverse lookup.
type Resource struct {
	vgorm.BasePostgres
	AppID     string         `gorm:"column:app_id"`
	ParentID  *string        `gorm:"column:parent_id"`
	Type      string         `gorm:"column:type"`
	Code      string         `gorm:"column:code"`
	Name      string         `gorm:"column:name"`
	Sort      int            `gorm:"column:sort"`
	Status    string         `gorm:"column:status"`
	Visible   bool           `gorm:"column:visible"`
	Icon      *string        `gorm:"column:icon"`
	Method    *string        `gorm:"column:method"`
	RoutePath *string        `gorm:"column:route_path"`
	Extra     datatypes.JSON `gorm:"column:extra"`
}

func (Resource) TableName() string { return "resources" }
