package model

import (
	"github.com/flametest/vita/vgorm"
	"gorm.io/datatypes"
)

// Identity is a social sign-in credential (design.md §12 M5): one row per
// (provider, provider_user_id) binding to a primary identity (users row).
// email/display_name snapshot the provider profile at link time; raw_profile
// keeps the untouched provider payload for debugging.
type Identity struct {
	vgorm.BasePostgres
	UserID         string         `gorm:"column:user_id"`
	Provider       string         `gorm:"column:provider"` // google | microsoft | facebook | apple
	ProviderUserID string         `gorm:"column:provider_user_id"`
	Email          *string        `gorm:"column:email"`
	EmailVerified  bool           `gorm:"column:email_verified"`
	DisplayName    *string        `gorm:"column:display_name"`
	AvatarURL      *string        `gorm:"column:avatar_url"`
	RawProfile     datatypes.JSON `gorm:"column:raw_profile"`
}

func (Identity) TableName() string { return "identities" }
