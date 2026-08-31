package model

import (
	"time"

	"github.com/flametest/vita/vgorm"
)

// Account is a workspace (per-app) account: an independent login credential
// bound to exactly one primary identity (identity_id is NOT NULL by design —
// v6 auto-creates the identity when missing). Roles and direct grants attach
// to accounts, making them the Casbin subject.
type Account struct {
	vgorm.BasePostgres
	IdentityID   string     `gorm:"column:identity_id"`
	AppID        string     `gorm:"column:app_id"`
	Email        string     `gorm:"column:email"`
	Username     *string    `gorm:"column:username"`
	PasswordHash *string    `gorm:"column:password_hash"` // NULL for OIDC auto-provisioned accounts (cannot direct-login until activated)
	DisplayName  *string    `gorm:"column:display_name"`
	Status       string     `gorm:"column:status"`
	Source       string     `gorm:"column:source"`
	LastLoginAt  *time.Time `gorm:"column:last_login_at"`
}

func (Account) TableName() string { return "accounts" }

// AccountRole grants a role to an account. expires_at NULL means permanent;
// granted_by is the admin account that performed the grant.
type AccountRole struct {
	vgorm.BasePostgres
	AccountID string     `gorm:"column:account_id"`
	RoleID    string     `gorm:"column:role_id"`
	GrantedBy *string    `gorm:"column:granted_by"`
	GrantedAt time.Time  `gorm:"column:granted_at"`
	ExpiresAt *time.Time `gorm:"column:expires_at"`
}

func (AccountRole) TableName() string { return "account_roles" }

// AccountGrant is a direct (role-free) permission grant of a single resource
// to an account. effect is reserved (M1-M3 always "allow").
type AccountGrant struct {
	vgorm.BasePostgres
	AccountID  string     `gorm:"column:account_id"`
	ResourceID string     `gorm:"column:resource_id"`
	GrantedBy  *string    `gorm:"column:granted_by"`
	GrantedAt  time.Time  `gorm:"column:granted_at"`
	ExpiresAt  *time.Time `gorm:"column:expires_at"`
	Effect     string     `gorm:"column:effect"`
}

func (AccountGrant) TableName() string { return "account_grants" }
