package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// grantEffectAllow is the M1-M3 effect stored on role_resources and
// account_grants rows (deny is reserved for M6).
const grantEffectAllow = "allow"

// AccountRoleWithRole is an account_roles row joined with its role's
// code/scope metadata (the workspace "access & role" summary).
type AccountRoleWithRole struct {
	AccountRoleID string     `gorm:"column:account_role_id"`
	RoleID        string     `gorm:"column:role_id"`
	GrantedBy     *string    `gorm:"column:granted_by"`
	GrantedAt     time.Time  `gorm:"column:granted_at"`
	ExpiresAt     *time.Time `gorm:"column:expires_at"`
	RoleCode      string     `gorm:"column:role_code"`
	RoleName      string     `gorm:"column:role_name"`
	RoleScope     string     `gorm:"column:role_scope"`
	RoleAppID     string     `gorm:"column:role_app_id"`
	RoleBuiltIn   bool       `gorm:"column:role_built_in"`
}

// AccountRoleRepo manages role bindings on accounts.
type AccountRoleRepo interface {
	// Add grants one role to an account. grantedBy may be "" (no grantor).
	// Re-granting an existing active binding is a no-op (ON CONFLICT DO
	// NOTHING), keeping the call idempotent.
	Add(ctx context.Context, accountID, roleID, grantedBy string, expiresAt *time.Time) error
	// Remove soft-deletes the binding; zero rows yields NotFoundError.
	Remove(ctx context.Context, accountID, roleID string) error
	// ListByAccount returns the account's bindings joined with role
	// code/scope metadata.
	ListByAccount(ctx context.Context, accountID string) ([]AccountRoleWithRole, error)
	// SetForAccount atomically replaces the account's role set with roleIDs
	// (soft-delete all, then insert), attributed to grantedBy.
	SetForAccount(ctx context.Context, accountID string, roleIDs []string, grantedBy string) error
	// ListByRole returns the (account, role) bindings of one role (used to
	// clean up in-memory policies when a role is deleted).
	ListByRole(ctx context.Context, roleID string) ([]*model.AccountRole, error)
	// ListPolicyRows returns the full account_roles join used by the Casbin
	// loader. Rows referencing soft-deleted/disabled accounts, roles or apps
	// are excluded by the query itself.
	ListPolicyRows(ctx context.Context) ([]PolicyAccountRole, error)
}

type accountRoleRepoImpl struct {
	db *gorm.DB
}

func NewAccountRoleRepo(db *gorm.DB) AccountRoleRepo {
	return &accountRoleRepoImpl{db: db}
}

func (r *accountRoleRepoImpl) Add(ctx context.Context, accountID, roleID, grantedBy string, expiresAt *time.Time) error {
	row := model.AccountRole{
		AccountID: accountID,
		RoleID:    roleID,
		GrantedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	if grantedBy != "" {
		row.GrantedBy = &grantedBy
	}
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&row).Error
}

func (r *accountRoleRepoImpl) Remove(ctx context.Context, accountID, roleID string) error {
	res := r.db.WithContext(ctx).
		Where("account_id = ? AND role_id = ?", accountID, roleID).
		Delete(&model.AccountRole{})
	return updateRowsAffected(res, fmt.Sprintf("role %s not granted to account %s", roleID, accountID))
}

func (r *accountRoleRepoImpl) ListByAccount(ctx context.Context, accountID string) ([]AccountRoleWithRole, error) {
	var out []AccountRoleWithRole
	err := r.db.WithContext(ctx).
		Table("account_roles").
		Select("account_roles.id AS account_role_id, account_roles.role_id, account_roles.granted_by, "+
			"account_roles.granted_at, account_roles.expires_at, roles.code AS role_code, roles.name AS role_name, "+
			"roles.scope AS role_scope, roles.app_id AS role_app_id, roles.built_in AS role_built_in").
		Joins("JOIN roles ON roles.id = account_roles.role_id AND roles.deleted_at IS NULL").
		Where("account_roles.account_id = ? AND account_roles.deleted_at IS NULL", accountID).
		Order("account_roles.created_at ASC").
		Scan(&out).Error
	return out, err
}

// ListByRole returns the bindings of one role.
func (r *accountRoleRepoImpl) ListByRole(ctx context.Context, roleID string) ([]*model.AccountRole, error) {
	var out []*model.AccountRole
	err := r.db.WithContext(ctx).
		Where("role_id = ?", roleID).
		Find(&out).Error
	return out, err
}

// SetForAccount replaces the binding set in one transaction. Insert order is
// deduplicated and made deterministic.
func (r *accountRoleRepoImpl) SetForAccount(ctx context.Context, accountID string, roleIDs []string, grantedBy string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ?", accountID).Delete(&model.AccountRole{}).Error; err != nil {
			return err
		}
		if len(roleIDs) == 0 {
			return nil
		}
		seen := make(map[string]struct{}, len(roleIDs))
		rows := make([]model.AccountRole, 0, len(roleIDs))
		for _, roleID := range roleIDs {
			if _, dup := seen[roleID]; dup {
				continue
			}
			seen[roleID] = struct{}{}
			row := model.AccountRole{AccountID: accountID, RoleID: roleID}
			if grantedBy != "" {
				row.GrantedBy = &grantedBy
			}
			rows = append(rows, row)
		}
		return tx.Create(&rows).Error
	})
}

// ListPolicyRows joins account_roles -> roles -> accounts -> apps (the
// account's app provides the dom for app-scope roles). Soft-deleted rows and
// rows whose account, role or role-app is deleted/disabled are excluded.
func (r *accountRoleRepoImpl) ListPolicyRows(ctx context.Context) ([]PolicyAccountRole, error) {
	var out []PolicyAccountRole
	err := r.db.WithContext(ctx).
		Table("account_roles").
		Select("account_roles.id, account_roles.account_id, accounts.app_id AS account_app_id, " +
			"apps.key AS account_app_key, roles.code AS role_code, roles.scope AS role_scope, " +
			"roles.app_id AS role_app_id, account_roles.expires_at").
		Joins("JOIN roles ON roles.id = account_roles.role_id AND roles.deleted_at IS NULL").
		Joins("JOIN accounts ON accounts.id = account_roles.account_id AND accounts.deleted_at IS NULL AND accounts.status <> 'disabled'").
		Joins("JOIN apps ON apps.id = accounts.app_id AND apps.deleted_at IS NULL AND apps.status = 'active'").
		Joins("JOIN apps role_app ON role_app.id = roles.app_id AND role_app.deleted_at IS NULL AND role_app.status = 'active'").
		Where("account_roles.deleted_at IS NULL").
		Scan(&out).Error
	return out, err
}
