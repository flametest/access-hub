package service

import (
	"context"
	"strconv"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/model"
	log "github.com/flametest/vita/vlog"
)

// Policy-consistency helpers: every RBAC mutation writes the business tables
// (source of truth) AND applies the equivalent incremental in-memory casbin
// update (7-tuple rules with the priority ladder + explicit effect), bumps
// `policy:ver:{appKey}` and broadcasts a reload.

// casbinSubjectAccount builds the casbin subject for an account.
func casbinSubjectAccount(accountID string) string { return "account:" + accountID }

// casbinSubjectClient builds the casbin subject for an OAuth2 service client.
func casbinSubjectClient(clientID string) string { return "client:" + clientID }

// casbinRole builds the casbin role subject for a role.
func casbinRole(roleCode string) string { return "role:" + roleCode }

// casbinDomApp builds the domain value for an app key.
func casbinDomApp(appKey string) string { return "app:" + appKey }

// casbinEffect normalizes an effect value, defaulting unknown values to
// allow (mirrors the repo layer's default).
func casbinEffect(effect string) string {
	if effect == casbinx.EffectDeny {
		return casbinx.EffectDeny
	}
	return casbinx.EffectAllow
}

// bumpPolicyVersions increments the policy version counters for the given app
// keys. Errors are logged and swallowed (periodic reconciliation converges).
func bumpPolicyVersions(ctx context.Context, c container.Container, appKeys []string) {
	for _, key := range appKeys {
		if _, err := casbinx.IncrPolicyVersion(ctx, c.KV(), key); err != nil {
			log.Warn().Any("error", err).Any("app_key", key).Msg("policy version bump failed (ignored)")
		}
	}
	// The global epoch drives the reconciler: every instance compares it with
	// the epoch at its last (re)load and self-heals a missed watcher event.
	if _, err := casbinx.BumpGlobalEpoch(ctx, c.KV()); err != nil {
		log.Warn().Any("error", err).Msg("global policy epoch bump failed (reconciler may lag one interval)")
	}
}

// casbinNotify broadcasts a full-policy reload to all instances. Errors are
// logged and swallowed (the local enforcer is already updated).
func casbinNotify(ctx context.Context, c container.Container, appKeys []string) error {
	bumpPolicyVersions(ctx, c, appKeys)
	if err := c.Enforcer().NotifyReload(); err != nil {
		log.Warn().Any("error", err).Msg("casbin reload broadcast failed (ignored)")
		return err
	}
	return nil
}

// roleBindingDom computes the g-rule domain for an account-role binding:
// app-scope roles bind within the account's app, global roles use "*".
func roleBindingDom(role *model.Role, accountAppKey string) string {
	if role.Scope == domain.RoleScopeApp {
		return casbinDomApp(accountAppKey)
	}
	return "*"
}

// syncAccountRoleBinding applies one account-role binding change to the
// in-memory enforcer and bumps the affected policy versions.
func syncAccountRoleBinding(ctx context.Context, c container.Container, accountID string, accountApp *model.App, role *model.Role, add bool) error {
	sub := casbinSubjectAccount(accountID)
	rule := casbinRole(role.Code)
	dom := roleBindingDom(role, accountApp.Key)
	var err error
	if add {
		_, err = c.Enforcer().AddGroupingPolicy(sub, rule, dom)
	} else {
		_, err = c.Enforcer().RemoveGroupingPolicy(sub, rule, dom)
	}
	if err != nil {
		log.Warn().Any("error", err).Msg("incremental role binding sync failed (reload will converge)")
	}
	versions := []string{accountApp.Key}
	if role.Scope == domain.RoleScopeGlobal {
		versions = append(versions, "admin")
	}
	_ = casbinNotify(ctx, c, versions)
	return err
}

// syncRoleResourceRule applies one role-resource rule change to the in-memory
// enforcer as a 7-tuple with the role priority ladder (deny=45, allow=50).
// The effect must mirror the persisted role_resources row; the loader's
// skip-cases (app-scope roles cross-app) must be mirrored by callers.
func syncRoleResourceRule(ctx context.Context, c container.Container, role *model.Role, resourceAppKey, resourceCode, effect string, add bool) error {
	effect = casbinEffect(effect)
	rule := roleResourceRule(role.Code, resourceAppKey, resourceCode, effect)
	var err error
	if add {
		_, err = c.Enforcer().AddPolicy(rule...)
	} else {
		_, err = c.Enforcer().RemovePolicy(rule...)
	}
	if err != nil {
		log.Warn().Any("error", err).Msg("incremental role resource sync failed (reload will converge)")
	}
	return err
}

// roleResourceRule assembles the 7-tuple for a role_resources row.
func roleResourceRule(roleCode, resourceAppKey, resourceCode, effect string) []string {
	priority := casbinx.PriorityRoleAllow
	if effect == casbinx.EffectDeny {
		priority = casbinx.PriorityRoleDeny
	}
	return []string{
		strconv.Itoa(priority),
		casbinRole(roleCode),
		casbinDomApp(resourceAppKey),
		resourceCode,
		"*",
		effect,
		"",
	}
}

// grantResourceRule assembles the 7-tuple for an account_grants row.
func grantResourceRule(accountID, resourceAppKey, resourceCode, effect string) []string {
	priority := casbinx.PriorityGrantAllow
	if effect == casbinx.EffectDeny {
		priority = casbinx.PriorityGrantDeny
	}
	return []string{
		strconv.Itoa(priority),
		casbinSubjectAccount(accountID),
		casbinDomApp(resourceAppKey),
		resourceCode,
		"*",
		effect,
		"",
	}
}

// syncGrantRule applies one direct grant rule change to the in-memory
// enforcer (grant ladder: deny=20, allow=30).
func syncGrantRule(ctx context.Context, c container.Container, accountID, resourceAppKey, resourceCode, effect string, add bool) error {
	effect = casbinEffect(effect)
	rule := grantResourceRule(accountID, resourceAppKey, resourceCode, effect)
	var err error
	if add {
		_, err = c.Enforcer().AddPolicy(rule...)
	} else {
		_, err = c.Enforcer().RemovePolicy(rule...)
	}
	if err != nil {
		log.Warn().Any("error", err).Msg("incremental grant sync failed (reload will converge)")
	}
	return err
}

// customRuleRule assembles the 7-tuple for a custom_rules row
// ([priority, *, app:{key}, *, *, effect, expr]).
func customRuleRule(appKey string, priority int, effect, expr string) []string {
	return []string{
		strconv.Itoa(priority),
		"*",
		casbinDomApp(appKey),
		"*",
		"*",
		casbinEffect(effect),
		expr,
	}
}

// syncCustomRule applies one custom-rule change to the in-memory enforcer
// (add on create/enable, remove on delete/disable/expr-effect-priority
// change). The optional previous rule is removed first so an updated rule
// cannot double-match under its old shape.
func syncCustomRule(ctx context.Context, c container.Container, appKey string, priority int, effect, expr string, add bool) error {
	rule := customRuleRule(appKey, priority, effect, expr)
	var err error
	if add {
		_, err = c.Enforcer().AddPolicy(rule...)
	} else {
		_, err = c.Enforcer().RemovePolicy(rule...)
	}
	if err != nil {
		log.Warn().Any("error", err).Msg("incremental custom rule sync failed (reload will converge)")
	}
	return err
}

// grantExpiryWithin reports whether a grant/binding row is expired now.
func grantExpiryWithin(at *time.Time, now time.Time) bool { return expired(at, now) }
