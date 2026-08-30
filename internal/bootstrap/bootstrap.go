// Package bootstrap performs the idempotent startup seeding (design.md §7
// Bootstrap): the platform admin app, the built-in global roles
// (super_admin / org_admin) and the initial platform admin identity with its
// admin-app account. Every step is ensure-style: re-running is a no-op.
package bootstrap

import (
	"context"
	"os"
	"strings"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/password"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	log "github.com/flametest/vita/vlog"
	"github.com/google/uuid"
)

const (
	// PlatformAdminAppKey is the app key of the admin console (dogfood domain).
	PlatformAdminAppKey = "admin"
	// PlatformAdminAppID is the fixed UUID from migration/seed.sql so
	// cross-references stay stable; bootstrap only creates the app when the
	// seed is missing it.
	PlatformAdminAppID = "00000000-0000-0000-0000-0000000000a1"

	// AdminAccountDisplayName is the display name of the bootstrapped
	// admin-app account.
	AdminAccountDisplayName = "Platform Admin"

	// BootstrapAdminPasswordEnv overrides cfg.Bootstrap.adminPassword (the
	// bootstrap password is a runtime secret and must not live in the config
	// file).
	BootstrapAdminPasswordEnv = "ACCESS_HUB_BOOTSTRAP_ADMIN_PASSWORD"
)

// Run executes the idempotent bootstrap. After any mutation it reloads the
// Casbin enforcer and bumps the admin app's policy version. It never logs
// plaintext passwords.
func Run(ctx context.Context, c container.Container) error {
	mutated := false

	adminApp, appCreated, err := ensureAdminApp(ctx, c)
	if err != nil {
		return err
	}
	mutated = mutated || appCreated

	superAdmin, superAdminCreated, err := ensureBuiltInRole(ctx, c, adminApp, domain.BuiltInRoleSuperAdmin, "Platform Super Admin")
	if err != nil {
		return err
	}
	mutated = mutated || superAdminCreated

	_, orgAdminCreated, err := ensureBuiltInRole(ctx, c, adminApp, domain.BuiltInRoleOrgAdmin, "Organization Admin")
	if err != nil {
		return err
	}
	mutated = mutated || orgAdminCreated

	adminCreated, err := bootstrapAdmin(ctx, c, adminApp, superAdmin)
	if err != nil {
		return err
	}
	mutated = mutated || adminCreated

	if !mutated {
		return nil
	}

	// Reload the local enforcer from the (now updated) business tables and
	// publish the policy version bump for downstream caches. A version-bump
	// failure is non-fatal: the periodic version reconciliation covers it.
	if err := c.Enforcer().Reload(); err != nil {
		return verrors.Wrap(err, "reload casbin policies after bootstrap")
	}
	if _, err := casbinx.IncrPolicyVersion(ctx, c.KV(), PlatformAdminAppKey); err != nil {
		log.Warn().Any("error", err).Msg("bootstrap: failed to bump policy version (periodic reconciliation will converge)")
	}
	log.Info().Msg("bootstrap: casbin policies reloaded")
	return nil
}

// ensureAdminApp finds the platform admin app (key="admin"), creating it with
// the fixed seed UUID when the seed.sql row is missing. Returns (app, created).
func ensureAdminApp(ctx context.Context, c container.Container) (*model.App, bool, error) {
	app, err := c.AppRepo().FindByKey(ctx, PlatformAdminAppKey)
	if err != nil && !repository.IsNotFound(err) {
		return nil, false, verrors.Wrap(err, "find platform admin app")
	}
	if app != nil {
		return app, false, nil
	}

	description := "Platform admin console (dogfood domain)"
	app = &model.App{
		BasePostgres: vgorm.BasePostgres{Id: PlatformAdminAppID},
		Key:          PlatformAdminAppKey,
		Name:         "Access-Hub Console",
		Type:         domain.AppTypeWeb,
		Description:  &description,
		Status:       domain.AppStatusActive,
	}
	if err := c.AppRepo().Create(ctx, app); err != nil {
		return nil, false, verrors.Wrap(err, "create platform admin app")
	}
	log.Info().Any("app_id", app.Id).Msg("bootstrap: created platform admin app")
	return app, true, nil
}

// ensureBuiltInRole finds the built-in global role by code, creating it on the
// admin app when missing. Returns (role, created).
func ensureBuiltInRole(ctx context.Context, c container.Container, adminApp *model.App, code, name string) (*model.Role, bool, error) {
	role, err := c.RoleRepo().FindGlobalByCode(ctx, code)
	if err != nil && !repository.IsNotFound(err) {
		return nil, false, verrors.Wrapf(err, "find built-in role %s", code)
	}
	if role != nil {
		return role, false, nil
	}

	role = &model.Role{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		AppID:        adminApp.Id,
		Code:         code,
		Name:         name,
		Scope:        domain.RoleScopeGlobal,
		BuiltIn:      true,
	}
	if err := c.RoleRepo().Create(ctx, role); err != nil {
		return nil, false, verrors.Wrapf(err, "create built-in role %s", code)
	}
	log.Info().Any("role_id", role.Id).Any("code", code).Msg("bootstrap: created built-in global role")
	return role, true, nil
}

// bootstrapAdmin creates the platform admin identity and its admin-app
// account, granted the super_admin role. Idempotent: an existing identity
// with the configured username or email skips the whole step silently. With
// no password configured (env override wins over cfg) and a missing identity
// it logs a warning and continues without error. Returns (created, error).
func bootstrapAdmin(ctx context.Context, c container.Container, adminApp *model.App, superAdmin *model.Role) (bool, error) {
	cfg := c.Cfg()

	pw := os.Getenv(BootstrapAdminPasswordEnv)
	if pw == "" {
		pw = cfg.Bootstrap.AdminPassword
	}

	// Normalized like the repositories' LOWER() lookups and the DB unique
	// indexes.
	username := strings.ToLower(strings.TrimSpace(cfg.Bootstrap.AdminUsername))
	email := strings.ToLower(strings.TrimSpace(cfg.Bootstrap.AdminEmail))

	// Idempotency: any identity matching the configured username or email
	// means the platform admin is already bootstrapped — skip silently.
	userRepo := c.UserRepo()
	existing, err := userRepo.FindByEmail(ctx, email)
	if err != nil && !repository.IsNotFound(err) {
		return false, verrors.Wrap(err, "find bootstrap admin identity by email")
	}
	if existing == nil {
		existing, err = userRepo.FindByUsername(ctx, username)
		if err != nil && !repository.IsNotFound(err) {
			return false, verrors.Wrap(err, "find bootstrap admin identity by username")
		}
	}
	if existing != nil {
		return false, nil
	}

	if pw == "" {
		log.Warn().
			Any("username", username).
			Any("email", email).
			Any("env", BootstrapAdminPasswordEnv).
			Msg("bootstrap: admin identity missing and no password configured (set ACCESS_HUB_BOOTSTRAP_ADMIN_PASSWORD or bootstrap.adminPassword); skipping platform admin bootstrap")
		return false, nil
	}

	if err := password.ValidatePolicy(pw); err != nil {
		return false, verrors.Wrap(err, "bootstrap admin password rejected by the password policy")
	}
	hash, err := password.Hash(pw, cfg.Auth.BcryptCost)
	if err != nil {
		return false, err
	}

	user := &model.User{
		BasePostgres:       vgorm.BasePostgres{Id: uuid.NewString()},
		Username:           username,
		Email:              email,
		EmailVerified:      true,
		PasswordHash:       &hash,
		Status:             domain.UserStatusActive,
		MustChangePassword: true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		return false, verrors.Wrap(err, "create bootstrap admin identity")
	}

	displayName := AdminAccountDisplayName
	account := &model.Account{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		IdentityID:   user.Id,
		AppID:        adminApp.Id,
		Email:        email,
		PasswordHash: hash,
		DisplayName:  &displayName,
		Status:       domain.AccountStatusActive,
		Source:       domain.AccountSourceProvisioned,
	}
	if err := c.AccountRepo().Create(ctx, account); err != nil {
		return false, verrors.Wrap(err, "create bootstrap admin account")
	}

	// grantedBy "" (no acting admin yet) and a permanent binding.
	if err := c.AccountRoleRepo().Add(ctx, account.Id, superAdmin.Id, "", nil); err != nil {
		return false, verrors.Wrap(err, "grant super_admin to bootstrap admin account")
	}

	log.Info().
		Any("user_id", user.Id).
		Any("account_id", account.Id).
		Msg("bootstrap: platform admin identity and admin-app account created (must_change_password=true)")
	return true, nil
}
