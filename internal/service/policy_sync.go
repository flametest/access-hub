package service

import (
	"context"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/model"
	log "github.com/flametest/vita/vlog"
)

// Policy-consistency helpers: every RBAC mutation writes the business tables
// (source of truth) AND applies the equivalent incremental in-memory casbin
// update, bumps `policy:ver:{appKey}` and broadcasts a reload.

// casbinSubjectAccount builds the casbin subject for an account.
func casbinSubjectAccount(accountID string) string { return "account:" + accountID }

// casbinSubjectClient builds the casbin subject for an OAuth2 service client.
func casbinSubjectClient(clientID string) string { return "client:" + clientID }

// casbinRole builds the casbin role subject for a role.
func casbinRole(roleCode string) string { return "role:" + roleCode }

// casbinDomApp builds the domain value for an app key.
func casbinDomApp(appKey string) string { return "app:" + appKey }

// bumpPolicyVersions increments the policy version counters for the given app
// keys. Errors are logged and swallowed (periodic reconciliation converges).
func bumpPolicyVersions(ctx context.Context, c container.Container, appKeys []string) {
	for _, key := range appKeys {
		if _, err := casbinx.IncrPolicyVersion(ctx, c.KV(), key); err != nil {
			log.Warn().Any("error", err).Any("app_key", key).Msg("policy version bump failed (ignored)")
		}
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
// enforcer (the loader skips cross-app bindings for app-scope roles; callers
// must mirror that skip before invoking this helper).
func syncRoleResourceRule(ctx context.Context, c container.Container, role *model.Role, resourceAppKey string, resourceCode string, add bool) error {
	var err error
	if add {
		_, err = c.Enforcer().AddPolicy(casbinRole(role.Code), casbinDomApp(resourceAppKey), resourceCode, "*")
	} else {
		_, err = c.Enforcer().RemovePolicy(casbinRole(role.Code), casbinDomApp(resourceAppKey), resourceCode, "*")
	}
	if err != nil {
		log.Warn().Any("error", err).Msg("incremental role resource sync failed (reload will converge)")
	}
	return err
}

// syncGrantRule applies one direct grant rule change to the in-memory enforcer.
func syncGrantRule(ctx context.Context, c container.Container, accountID, resourceAppKey, resourceCode string, add bool) error {
	var err error
	if add {
		_, err = c.Enforcer().AddPolicy(casbinSubjectAccount(accountID), casbinDomApp(resourceAppKey), resourceCode, "*")
	} else {
		_, err = c.Enforcer().RemovePolicy(casbinSubjectAccount(accountID), casbinDomApp(resourceAppKey), resourceCode, "*")
	}
	if err != nil {
		log.Warn().Any("error", err).Msg("incremental grant sync failed (reload will converge)")
	}
	return err
}

// grantExpiryWithin reports whether a grant/binding row is expired now.
func grantExpiryWithin(at *time.Time, now time.Time) bool { return expired(at, now) }
