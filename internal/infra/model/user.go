package model

import (
	"time"

	"github.com/flametest/vita/vgorm"
)

// User is the primary identity (Company ID): it holds portal credentials only
// and never owns business-app permissions directly. password_hash is NULL for
// auto-provisioned identities until the password is set via email.
type User struct {
	vgorm.BasePostgres
	Username           string     `gorm:"column:username"`
	Email              string     `gorm:"column:email"`
	EmailVerified      bool       `gorm:"column:email_verified"`
	PasswordHash       *string    `gorm:"column:password_hash"`
	Nickname           *string    `gorm:"column:nickname"`
	AvatarURL          *string    `gorm:"column:avatar_url"`
	Status             string     `gorm:"column:status"`
	MustChangePassword bool       `gorm:"column:must_change_password"`
	LastLoginAt        *time.Time `gorm:"column:last_login_at"`
}

func (User) TableName() string { return "users" }
