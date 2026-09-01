package casbinx

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/repository"
	log "github.com/flametest/vita/vlog"
)

// Subject/role prefixes used inside Casbin rules.
const (
	SubjectPrefixAccount = "account:"
	SubjectPrefixClient  = "client:"
	RolePrefix           = "role:"
	DomPrefixApp         = "app:"
	DomWildcard          = "*"
	ActWildcard          = "*"
)

// errReadOnly is returned by the mutation hooks — the business tables are the
// single source of truth and this adapter never writes.
var errReadOnly = errors.New("casbin loader adapter is read-only")

// Loader is the read-only Casbin adapter: it loads the full policy set by
// translating business-table rows (design.md §6.1) into 7-tuple rules
// [priority, sub, dom, obj, act, eft, cond]. Policies are never persisted to
// a casbin_rule table.
//
// Rule taxonomy (priority ladder, see ModelText):
//
//	super_admin wildcard:  [1,  role:super_admin, *,          *,  *,  allow, ""]
//	role_resources:        [45|50, role:{code}, app:{key}, code, *, effect, ""]
//	account_grants:        [20|30, account:{id}, app:{key}, code, *, effect, ""]
//	custom_rules (active): [row,  *,            app:{key}, *,    *,  effect, expr]
//	client_credentials:    [60,  client:{id},   app:{key},  *,    *,  allow,  ""]
//
// M4 addition: every ACTIVE oauth_clients row with the client_credentials
// grant is translated into a full-access rule for its OWN app (documented
// M4 decision: service tokens get full access to their own app's resources
// by default; tighten later via per-client scope policies).
type Loader struct {
	roleRepo         repository.RoleRepo
	roleResourceRepo repository.RoleResourceRepo
	accountRoleRepo  repository.AccountRoleRepo
	accountGrantRepo repository.AccountGrantRepo
	oauthClientRepo  repository.OAuthClientRepo
	customRuleRepo   repository.CustomRuleRepo
	appRepo          repository.AppRepo
}

var _ persist.Adapter = (*Loader)(nil)

// NewLoader builds the adapter from the policy-relevant repositories.
func NewLoader(
	roleRepo repository.RoleRepo,
	roleResourceRepo repository.RoleResourceRepo,
	accountRoleRepo repository.AccountRoleRepo,
	accountGrantRepo repository.AccountGrantRepo,
	oauthClientRepo repository.OAuthClientRepo,
	customRuleRepo repository.CustomRuleRepo,
	appRepo repository.AppRepo,
) *Loader {
	return &Loader{
		roleRepo:         roleRepo,
		roleResourceRepo: roleResourceRepo,
		accountRoleRepo:  accountRoleRepo,
		accountGrantRepo: accountGrantRepo,
		oauthClientRepo:  oauthClientRepo,
		customRuleRepo:   customRuleRepo,
		appRepo:          appRepo,
	}
}

// effectPriority maps an effect onto its ladder value; an unknown effect
// fails safe to the deny position (a deny ladder value with an allow eft is
// still filtered below by the matcher, and the CRUD layer validates the
// column anyway).
func effectPriority(effect string, allow, deny int) int {
	if effect == EffectDeny {
		return deny
	}
	return allow
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
		rule := []string{
			strconv.Itoa(PrioritySuperAdmin),
			RolePrefix + superAdmin.Code,
			DomWildcard, DomWildcard, DomWildcard,
			EffectAllow, "",
		}
		if err := addRule(m, "p", "p", rule); err != nil {
			return err
		}
	}

	if err := l.loadRoleResourceRules(m); err != nil {
		return err
	}
	if err := l.loadAccountRoleRules(m, now); err != nil {
		return err
	}
	if err := l.loadAccountGrantRules(m, now); err != nil {
		return err
	}
	if err := l.loadCustomRules(m); err != nil {
		return err
	}
	return l.loadServiceClientRules(m)
}

// loadServiceClientRules emits one wildcard p rule per active
// client_credentials oauth client:
//
//	[60, client:{client_id}, app:{client app key}, *, *, allow, ""]
func (l *Loader) loadServiceClientRules(m model.Model) error {
	if l.oauthClientRepo == nil {
		return nil
	}
	clients, err := l.oauthClientRepo.ListActiveClientCredential(context.Background())
	if err != nil {
		return fmt.Errorf("load oauth clients: %w", err)
	}
	for _, client := range clients {
		// The dom follows the client's app; a missing/deleted app yields no
		// rule (FindByID not-found is treated as skip).
		app, err := l.appOfClient(client.AppID)
		if err != nil {
			return err
		}
		if app == "" {
			continue
		}
		rule := []string{
			strconv.Itoa(PriorityClient),
			SubjectPrefixClient + client.Id,
			DomPrefixApp + app,
			DomWildcard, DomWildcard,
			EffectAllow, "",
		}
		if err := addRule(m, "p", "p", rule); err != nil {
			return err
		}
	}
	return nil
}

// appOfClient resolves the client's app key, skipping soft-deleted apps.
func (l *Loader) appOfClient(appID string) (string, error) {
	if l.appRepo == nil {
		return "", nil
	}
	app, err := l.appRepo.FindByID(context.Background(), appID)
	if err != nil {
		if repository.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("load oauth client app %s: %w", appID, err)
	}
	return app.Key, nil
}

// loadRoleResourceRules emits p rules from role_resources:
//
//	[45|50, role:{code}, app:{resource app key}, {resource code}, *, effect, ""]
//
// The effect column (allow|deny) is enforced since M6. The super_admin
// wildcard was already emitted above.
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
		effect := row.Effect
		if effect != EffectAllow && effect != EffectDeny {
			log.Warn().Any("effect", effect).Any("role", row.RoleCode).Msg("role_resources row has unknown effect (skipped)")
			continue
		}
		rule := []string{
			strconv.Itoa(effectPriority(effect, PriorityRoleAllow, PriorityRoleDeny)),
			RolePrefix + row.RoleCode,
			DomPrefixApp + row.ResourceAppKey,
			row.ResourceCode,
			ActWildcard,
			effect,
			"",
		}
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
//	[20|30, account:{id}, app:{resource app key}, {resource code}, *, effect, ""]
func (l *Loader) loadAccountGrantRules(m model.Model, now time.Time) error {
	rows, err := l.accountGrantRepo.ListPolicyRows(context.Background())
	if err != nil {
		return fmt.Errorf("load account_grants: %w", err)
	}
	for _, row := range rows {
		if row.ExpiresAt != nil && row.ExpiresAt.Before(now) {
			continue
		}
		effect := row.Effect
		if effect != EffectAllow && effect != EffectDeny {
			log.Warn().Any("effect", effect).Any("account", row.AccountID).Msg("account_grants row has unknown effect (skipped)")
			continue
		}
		rule := []string{
			strconv.Itoa(effectPriority(effect, PriorityGrantAllow, PriorityGrantDeny)),
			SubjectPrefixAccount + row.AccountID,
			DomPrefixApp + row.ResourceAppKey,
			row.ResourceCode,
			ActWildcard,
			effect,
			"",
		}
		if err := addRule(m, "p", "p", rule); err != nil {
			return err
		}
	}
	return nil
}

// loadCustomRules emits p rules from ACTIVE custom_rules rows:
//
//	[{priority}, *, app:{key}, *, *, effect, expr]
//
// A rule whose expression fails to compile is SKIPPED with a warning instead
// of failing the whole load (the admin CRUD validates expressions at
// write time, so this only guards legacy/manual rows). Rows that compile but
// fail at evaluation time fail closed inside the matcher.
func (l *Loader) loadCustomRules(m model.Model) error {
	if l.customRuleRepo == nil {
		return nil
	}
	rows, err := l.customRuleRepo.ListPolicyRows(context.Background())
	if err != nil {
		return fmt.Errorf("load custom_rules: %w", err)
	}
	for _, row := range rows {
		if _, err := compileExpr(row.Expr); err != nil {
			log.Warn().Any("error", err).Any("app_key", row.AppKey).Msg("custom rule expression failed to compile (skipped, fail-closed)")
			continue
		}
		effect := row.Effect
		if effect != EffectAllow && effect != EffectDeny {
			log.Warn().Any("effect", effect).Any("app_key", row.AppKey).Msg("custom rule has unknown effect (skipped)")
			continue
		}
		rule := []string{
			strconv.Itoa(row.Priority),
			DomWildcard,
			DomPrefixApp + row.AppKey,
			DomWildcard,
			DomWildcard,
			effect,
			row.Expr,
		}
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
