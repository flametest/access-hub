package repository

import "time"

// Denormalized join rows for the read-only Casbin policy loader. The loader
// translates these rows into p/g rules per design.md §6.1; the queries behind
// them already drop rows referencing soft-deleted or disabled entities, while
// same-app checks and expiry checks are enforced by the loader itself.

// PolicyRoleResource is a role_resources row joined with its role and the
// resource's app (for the dom translation).
type PolicyRoleResource struct {
	RoleID         string `gorm:"column:role_id"`
	RoleCode       string `gorm:"column:role_code"`
	RoleScope      string `gorm:"column:role_scope"`
	RoleBuiltIn    bool   `gorm:"column:role_built_in"`
	RoleAppID      string `gorm:"column:role_app_id"`
	ResourceCode   string `gorm:"column:resource_code"`
	ResourceAppID  string `gorm:"column:resource_app_id"`
	ResourceAppKey string `gorm:"column:resource_app_key"`
}

// PolicyAccountRole is an account_roles row joined with its role and the
// account's app (bindings are dom-scoped by the account's app).
type PolicyAccountRole struct {
	AccountID     string     `gorm:"column:account_id"`
	RoleCode      string     `gorm:"column:role_code"`
	RoleScope     string     `gorm:"column:role_scope"`
	RoleAppID     string     `gorm:"column:role_app_id"`
	AccountAppKey string     `gorm:"column:account_app_key"`
	ExpiresAt     *time.Time `gorm:"column:expires_at"`
}

// PolicyAccountGrant is an account_grants row joined with the resource's app.
type PolicyAccountGrant struct {
	AccountID      string     `gorm:"column:account_id"`
	ResourceCode   string     `gorm:"column:resource_code"`
	ResourceAppKey string     `gorm:"column:resource_app_key"`
	ExpiresAt      *time.Time `gorm:"column:expires_at"`
}
