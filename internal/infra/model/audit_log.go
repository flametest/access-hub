package model

import (
	"github.com/flametest/vita/vgorm"
	"gorm.io/datatypes"
)

// AuditLog records privileged actions performed by an identity (primary user)
// or an account; actor_type=system is used for automated actions.
type AuditLog struct {
	vgorm.BasePostgres
	ActorType  string         `gorm:"column:actor_type"`
	ActorID    *string        `gorm:"column:actor_id"`
	OrgID      *string        `gorm:"column:org_id"`
	Action     string         `gorm:"column:action"`
	TargetType *string        `gorm:"column:target_type"`
	TargetID   *string        `gorm:"column:target_id"`
	Detail     datatypes.JSON `gorm:"column:detail"`
	IP         *string        `gorm:"column:ip"`
	UserAgent  *string        `gorm:"column:user_agent"`
}

func (AuditLog) TableName() string { return "audit_logs" }
