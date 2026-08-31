package model

import (
	"github.com/flametest/vita/vgorm"
	"gorm.io/datatypes"
)

// TOTPSecret is the per-identity TOTP enrollment. secret is base32; confirmed
// flips true only after a valid code check. backup_codes holds sha256 hex
// hashes of the one-time recovery codes; last_used_step is the replay guard
// (only steps strictly greater are accepted).
type TOTPSecret struct {
	vgorm.BasePostgres
	UserID       string         `gorm:"column:user_id"`
	Secret       string         `gorm:"column:secret"`
	Confirmed    bool           `gorm:"column:confirmed"`
	LastUsedStep int64          `gorm:"column:last_used_step"`
	BackupCodes  datatypes.JSON `gorm:"column:backup_codes"`
}

func (TOTPSecret) TableName() string { return "totp_secrets" }
