package casbinx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/repository"
)

// Subject/role prefixes used inside Casbin rules.
const (
	SubjectPrefixAccount = "account:"
	RolePrefix           = "role:"
	DomPrefixApp         = "app:"
	DomWildcard          = "*"
	ActWildcard          = "*"
)

// errReadOnly is returned by the mutation hooks — the business tables are the
// single source of truth and this adapter never writes.
var errReadOnly = errors.New("casbin loader adapter is read-only")

// Loader is the read-only Casbin adapter: it loads the full policy set by
// translating business-table rows (design.md §6.1). Policies are never
// persisted to a casbin_rule table.
type Loader struct {
	roleRepo         repository.RoleRepo
	roleResourceRepo repository.RoleResourceRepo
	accountRoleRepo  repository.AccountRoleRepo
	accountGrantRepo repository.AccountGrantRepo
}

var _ persist.Adapter = (*Loader)(nil)

// NewLoader builds the adapter from the policy-relevant repositories.
func NewLoader(
	roleRepo repository.RoleRepo,
	roleResourceRepo repository.RoleResourceRepo,
	accountRoleRepo repository.AccountRoleRepo,
	accountGrantRepo repository.AccountGrantRepo,
) *Loader {
	return &Loader{
		roleRepo:         roleRepo,
		roleResourceRepo: roleResourceRepo,
		accountRoleRepo:  accountRoleRepo,
		accountGrantRepo: accountGrantRepo,
	}
}

// LoadPolicy rebuilds the complete policy set in the given model. Casbin
// clears the model beforehand, so no explicit removal is needed.
func (l *Loader) LoadPolicy(m model.Model) error {
	ctx := context.Background()
	now := time.Now()

	// super_admin wildcard seed (independent of role_resources rows).
	superAdmin, err := l.roleRepo.FindGlobalByCode(ctx, domain.BuiltInRoleSuperAdmin)
	if err != nil && !repository.IsNotFound(err) {
		return fmt.Errorf("load super_admin role: %w", err)
	}
	if superAdmin != nil {
		if err := addRule(m, "p", "p", []string{RolePrefix + superAdmin.Code, DomWildcard, DomWildcard, ActWildcard}); err != nil {
			return err
		}
	}

	if err := l.loadRoleResourceRules(m); err != nil {
		return err
	}
	if err := l.loadAccountRoleRules(m, now); err != nil {
		return err
	}
	return l.loadAccountGrantRules(m, now)
}

// loadRoleResourceRules emits p rules from role_resources:
//
//	p, role:{code}, app:{resource app key}, {resource code}, *
//
// act is always "*" in M1-M3 (effect=deny is reserved for M6). The
// super_admin wildcard was already emitted above.
func (l *Loader) loadRoleResourceRules(m model.Model) error {
	rows, err := l.roleResourceRepo.ListPolicyRows(context.Background())
	if err != nil {
		return fmt.Errorf("load role_resources: %w", err)
	}
	for _, row := range rows {
		if row.RoleBuiltIn && row.RoleScope == domain.RoleScopeGlobal && row.RoleCode == domain.BuiltInRoleSuperAdmin {
			continue
		}
		// An app-scope role only applies to resources of its own app; global
		// roles follow the resource's app (org_admin must not gain business
		// app permissions by accident).
		if row.RoleScope == domain.RoleScopeApp && row.RoleAppID != row.ResourceAppID {
			continue
		}
		rule := []string{RolePrefix + row.RoleCode, DomPrefixApp + row.ResourceAppKey, row.ResourceCode, ActWildcard}
		if err := addRule(m, "p", "p", rule); err != nil {
			return err
		}
	}
	return nil
}

// loadAccountRoleRules emits g rules from account_roles:
//
//	g, account:{id}, role:{code}, app:{account app key}   (app-scope roles)
//	g, account:{id}, role:{code}, *                       (global roles)
//
// Expired bindings are skipped; an app-scope role is only bound when it
// belongs to the account's app.
func (l *Loader) loadAccountRoleRules(m model.Model, now time.Time) error {
	rows, err := l.accountRoleRepo.ListPolicyRows(context.Background())
	if err != nil {
		return fmt.Errorf("load account_roles: %w", err)
	}
	for _, row := range rows {
		if row.ExpiresAt != nil && row.ExpiresAt.Before(now) {
			continue
		}
		dom := DomWildcard
		if row.RoleScope == domain.RoleScopeApp {
			if row.RoleAppID != row.AccountAppID {
				continue
			}
			dom = DomPrefixApp + row.AccountAppKey
		}
		rule := []string{SubjectPrefixAccount + row.AccountID, RolePrefix + row.RoleCode, dom}
		if err := addRule(m, "g", "g", rule); err != nil {
			return err
		}
	}
	return nil
}

// loadAccountGrantRules emits p rules from account_grants:
//
//	p, account:{id}, app:{resource app key}, {resource code}, *
func (l *Loader) loadAccountGrantRules(m model.Model, now time.Time) error {
	rows, err := l.accountGrantRepo.ListPolicyRows(context.Background())
	if err != nil {
		return fmt.Errorf("load account_grants: %w", err)
	}
	for _, row := range rows {
		if row.ExpiresAt != nil && row.ExpiresAt.Before(now) {
			continue
		}
		rule := []string{SubjectPrefixAccount + row.AccountID, DomPrefixApp + row.ResourceAppKey, row.ResourceCode, ActWildcard}
		if err := addRule(m, "p", "p", rule); err != nil {
			return err
		}
	}
	return nil
}

func addRule(m model.Model, sec, ptype string, rule []string) error {
	if err := m.AddPolicy(sec, ptype, rule); err != nil {
		return fmt.Errorf("add %s rule %v: %w", ptype, rule, err)
	}
	return nil
}

// SavePolicy is unsupported (read-only adapter).
func (l *Loader) SavePolicy(model.Model) error { return errReadOnly }

// AddPolicy is unsupported (read-only adapter).
func (l *Loader) AddPolicy(string, string, []string) error { return errReadOnly }

// RemovePolicy is unsupported (read-only adapter).
func (l *Loader) RemovePolicy(string, string, []string) error { return errReadOnly }

// RemoveFilteredPolicy is unsupported (read-only adapter).
func (l *Loader) RemoveFilteredPolicy(string, string, int, ...string) error { return errReadOnly }
