package model

import (
	"github.com/flametest/vita/vgorm"
)

// App is a registered application (workspace). org_id NULL = platform app.
type App struct {
	vgorm.BasePostgres
	Key         string  `gorm:"column:key"`
	OrgID       *string `gorm:"column:org_id"`
	Name        string  `gorm:"column:name"`
	Type        string  `gorm:"column:type"`
	Description *string `gorm:"column:description"`
	LogoURL     *string `gorm:"column:logo_url"`
	Status      string  `gorm:"column:status"`
	// SecretHash is the SHA-256 hex of the per-app internal-API secret
	// (X-App-Key); nil = no internal credential (platform apps). The
	// plaintext is shown once at create/rotate and never persisted.
	SecretHash *string `gorm:"column:secret_hash"`
}

func (App) TableName() string { return "apps" }
