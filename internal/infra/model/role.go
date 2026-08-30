package model

import (
	"github.com/flametest/vita/vgorm"
)

// Role groups resource permissions. scope=app roles are defined per app;
// scope=global roles (built-ins super_admin/org_admin) are bound with a
// wildcard domain in Casbin.
type Role struct {
	vgorm.BasePostgres
	AppID   string `gorm:"column:app_id"`
	Code    string `gorm:"column:code"`
	Name    string `gorm:"column:name"`
	Scope   string `gorm:"column:scope"`
	BuiltIn bool   `gorm:"column:built_in"`
}

func (Role) TableName() string { return "roles" }

// RoleResource attaches a resource to a role. effect is reserved for M6 deny.
type RoleResource struct {
	vgorm.BasePostgres
	RoleID     string `gorm:"column:role_id"`
	ResourceID string `gorm:"column:resource_id"`
	Effect     string `gorm:"column:effect"`
}

func (RoleResource) TableName() string { return "role_resources" }
