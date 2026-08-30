package model

import (
	"time"

	"github.com/flametest/vita/vgorm"
	"gorm.io/datatypes"
)

// Invitation invites an email to join an app with a set of roles. Only the
// sha256 hash of the redeem code is stored (code_hash); redemption is one-shot.
type Invitation struct {
	vgorm.BasePostgres
	AppID             string         `gorm:"column:app_id"`
	Email             string         `gorm:"column:email"`
	RoleIDs           datatypes.JSON `gorm:"column:role_ids"`
	InvitedBy         string         `gorm:"column:invited_by"`
	CodeHash          string         `gorm:"column:code_hash"`
	ExpiresAt         time.Time      `gorm:"column:expires_at"`
	AcceptedAt        *time.Time     `gorm:"column:accepted_at"`
	AcceptedAccountID *string        `gorm:"column:accepted_account_id"`
	Status            string         `gorm:"column:status"`
}

func (Invitation) TableName() string { return "invitations" }
