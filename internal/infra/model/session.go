package model

import (
	"time"

	"github.com/flametest/vita/vgorm"
)

// Session is a refresh-token record; rotation is in-place (same row: new
// refresh_token_hash, rotation_count++). Reuse of a replaced hash revokes the
// whole session. app_id records the login entry app (NULL for portal login).
type Session struct {
	vgorm.BasePostgres
	UserID           string     `gorm:"column:user_id"`
	Scope            string     `gorm:"column:scope"`
	AccountID        *string    `gorm:"column:account_id"`
	AppID            *string    `gorm:"column:app_id"`
	RefreshTokenHash string     `gorm:"column:refresh_token_hash"`
	Device           *string    `gorm:"column:device"`
	IP               *string    `gorm:"column:ip"`
	LastUsedAt       *time.Time `gorm:"column:last_used_at"`
	RotationCount    int64      `gorm:"column:rotation_count"`
	ExpiresAt        time.Time  `gorm:"column:expires_at"`
	RevokedAt        *time.Time `gorm:"column:revoked_at"`
}

func (Session) TableName() string { return "sessions" }
