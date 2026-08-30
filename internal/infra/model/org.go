package model

import (
	"github.com/flametest/vita/vgorm"
)

// Org is the tenant container. Apps belong to orgs; org_id NULL on apps marks
// platform apps (e.g. the admin console).
type Org struct {
	vgorm.BasePostgres
	Key    string `gorm:"column:key"`
	Name   string `gorm:"column:name"`
	Status string `gorm:"column:status"`
}

func (Org) TableName() string { return "orgs" }

// OrgMember is governance-only: owner/admin manage the org itself. Business
// membership is derived from holding an account in an org-owned app.
type OrgMember struct {
	vgorm.BasePostgres
	OrgID   string `gorm:"column:org_id"`
	UserID  string `gorm:"column:user_id"`
	OrgRole string `gorm:"column:org_role"`
}

func (OrgMember) TableName() string { return "org_members" }
