package model

import (
	"github.com/flametest/vita/vgorm"
)

// Custom rule status values (custom_rules.status).
const (
	CustomRuleStatusActive   = "active"
	CustomRuleStatusDisabled = "disabled"
)

// CustomRule is a per-app ABAC expression rule evaluated inside the Casbin
// matcher (design.md §12 M6). The expression is written against the typed
// env {sub, dom, obj, act, roles, now} and decides allow/deny for the
// requests it matches; priority resolves against the fixed ladder
// (casbinx.Priority*), effect is allow|deny.
type CustomRule struct {
	vgorm.BasePostgres
	AppID    string `gorm:"column:app_id"`
	Name     string `gorm:"column:name"`
	Expr     string `gorm:"column:expr"`
	Effect   string `gorm:"column:effect"`
	Priority int    `gorm:"column:priority"`
	Status   string `gorm:"column:status"`
}

func (CustomRule) TableName() string { return "custom_rules" }
