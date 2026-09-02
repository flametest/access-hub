// Package container wires the application singletons: config, database,
// Redis-backed KV store, mailer, JWT manager, repositories and the Casbin
// enforcer with its Redis reload watcher (design.md §4).
package container

import (
	"time"

	"github.com/flametest/access-hub/internal/config"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/mailer"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/internal/infra/social"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	log "github.com/flametest/vita/vlog"
	"github.com/flametest/vita/vredis"
	"gorm.io/gorm"
)

// Container exposes the shared dependencies of every application layer.
// Repositories are plain getters over their existing constructors (all of
// them take a *gorm.DB; none supports the variadic tx re-wrap pattern).
type Container interface {
	Cfg() *config.Config
	// DB returns the underlying *gorm.DB, e.g. for readiness pings.
	DB() *gorm.DB
	KV() kv.Store
	// Redis exposes the underlying client (readiness ping, diagnostics).
	Redis() vredis.Client
	Mailer() mailer.Mailer
	JWT() *jwt.Manager
	Enforcer() *casbinx.Enforcer

	UserRepo() repository.UserRepo
	AccountRepo() repository.AccountRepo
	OrgRepo() repository.OrgRepo
	OrgMemberRepo() repository.OrgMemberRepo
	AppRepo() repository.AppRepo
	ResourceRepo() repository.ResourceRepo
	RoleRepo() repository.RoleRepo
	RoleResourceRepo() repository.RoleResourceRepo
	AccountRoleRepo() repository.AccountRoleRepo
	AccountGrantRepo() repository.AccountGrantRepo
	SessionRepo() repository.SessionRepo
	InvitationRepo() repository.InvitationRepo
	AuditLogRepo() repository.AuditLogRepo
	OAuthClientRepo() repository.OAuthClientRepo
	OAuthRefreshTokenRepo() repository.OAuthRefreshTokenRepo
	TOTPSecretRepo() repository.TOTPSecretRepo
	IdentityRepo() repository.IdentityRepo
	CustomRuleRepo() repository.CustomRuleRepo

	// SocialRegistry returns the configured social login providers keyed by
	// provider id (disabled providers report Enabled()==false, design.md §12 M5).
	SocialRegistry() map[string]social.Provider

	// Close releases the watcher, the Redis client and the database pool.
	Close()
}

type containerImpl struct {
	cfg        *config.Config
	db         *gorm.DB
	redis      vredis.Client
	store      kv.Store
	mailer     mailer.Mailer
	reconciler *casbinx.Reconciler
	jwt        *jwt.Manager
	watcher    *casbinx.RedisWatcher
	enf        *casbinx.Enforcer

	userRepo         repository.UserRepo
	accountRepo      repository.AccountRepo
	orgRepo          repository.OrgRepo
	orgMemberRepo    repository.OrgMemberRepo
	appRepo          repository.AppRepo
	resourceRepo     repository.ResourceRepo
	roleRepo         repository.RoleRepo
	roleResourceRepo repository.RoleResourceRepo
	accountRoleRepo  repository.AccountRoleRepo
	accountGrantRepo repository.AccountGrantRepo
	sessionRepo      repository.SessionRepo
	invitationRepo   repository.InvitationRepo
	auditLogRepo     repository.AuditLogRepo
	oauthClientRepo  repository.OAuthClientRepo
	oauthRefreshRepo repository.OAuthRefreshTokenRepo
	totpSecretRepo   repository.TOTPSecretRepo
	identityRepo     repository.IdentityRepo
	customRuleRepo   repository.CustomRuleRepo
	social           map[string]social.Provider
}

// NewContainer builds every dependency, failing fast on the first error
// (already-created resources are released before returning).
func NewContainer(cfg *config.Config) (Container, error) {
	db, err := vgorm.NewDB(cfg.Datasource)
	if err != nil {
		return nil, verrors.Wrap(err, "connect database")
	}

	redisClient := vredis.NewClient(*cfg.Redis)
	store := kv.NewRedisStore(redisClient)

	ml, err := mailer.NewMailer(&cfg.Mailer)
	if err != nil {
		release(db, redisClient, nil)
		return nil, err
	}

	mgr, err := jwt.NewManager(cfg.Auth.RSAPrivateKeyPath, cfg.Auth.RSAPublicKeyPath)
	if err != nil {
		release(db, redisClient, nil)
		return nil, err
	}

	// Repositories (plain *gorm.DB constructors).
	userRepo := repository.NewUserRepo(db)
	accountRepo := repository.NewAccountRepo(db)
	orgRepo := repository.NewOrgRepo(db)
	orgMemberRepo := repository.NewOrgMemberRepo(db)
	appRepo := repository.NewAppRepo(db)
	resourceRepo := repository.NewResourceRepo(db)
	roleRepo := repository.NewRoleRepo(db)
	roleResourceRepo := repository.NewRoleResourceRepo(db)
	accountRoleRepo := repository.NewAccountRoleRepo(db)
	accountGrantRepo := repository.NewAccountGrantRepo(db)
	sessionRepo := repository.NewSessionRepo(db)
	invitationRepo := repository.NewInvitationRepo(db)
	auditLogRepo := repository.NewAuditLogRepo(db)
	oauthClientRepo := repository.NewOAuthClientRepo(db)
	oauthRefreshRepo := repository.NewOAuthRefreshTokenRepo(db)
	totpSecretRepo := repository.NewTOTPSecretRepo(db)
	identityRepo := repository.NewIdentityRepo(db)
	customRuleRepo := repository.NewCustomRuleRepo(db)

	// Social login providers built from the global yaml credentials
	// (providers without credentials report Enabled()==false).
	socialProviders := social.NewRegistry(cfg.Social)

	// Casbin enforcer over the read-only policy loader.
	loader := casbinx.NewLoader(roleRepo, roleResourceRepo, accountRoleRepo, accountGrantRepo, oauthClientRepo, customRuleRepo, appRepo)
	enf, err := casbinx.NewEnforcer(loader)
	if err != nil {
		release(db, redisClient, nil)
		return nil, err
	}

	// Redis watcher: reload broadcasts on the casbin:reload channel trigger a
	// full policy re-load on this instance too. A failing reload (DB blip,
	// loader error) is retried with backoff and logged — a stale enforcer
	// must never be silent; the reconciler below is the last-resort net.
	watcher := casbinx.NewRedisWatcher(*cfg.Redis, func() {
		backoff := 250 * time.Millisecond
		for attempt := 1; attempt <= 4; attempt++ {
			if err := enf.Reload(); err == nil {
				return
			}
			log.Warn().Any("attempt", attempt).Any("error", err).Msg("policy reload after watcher event failed, retrying")
			time.Sleep(backoff)
			backoff *= 2
		}
		log.Error().Msg("policy reload failed after retries; the reconciler will converge within its interval")
	})
	reconciler := casbinx.NewReconciler(store, enf.Reload, casbinx.DefaultReconcileInterval)
	_ = reconciler.Start()
	if err := enf.SetWatcher(watcher); err != nil {
		watcher.Close()
		release(db, redisClient, nil)
		return nil, err
	}

	return &containerImpl{
		cfg:     cfg,
		db:      db,
		redis:   redisClient,
		store:   store,
		mailer:  ml,
		jwt:     mgr,
		watcher: watcher,
		enf:     enf,

		userRepo:         userRepo,
		accountRepo:      accountRepo,
		orgRepo:          orgRepo,
		orgMemberRepo:    orgMemberRepo,
		appRepo:          appRepo,
		resourceRepo:     resourceRepo,
		roleRepo:         roleRepo,
		roleResourceRepo: roleResourceRepo,
		accountRoleRepo:  accountRoleRepo,
		accountGrantRepo: accountGrantRepo,
		sessionRepo:      sessionRepo,
		invitationRepo:   invitationRepo,
		auditLogRepo:     auditLogRepo,
		oauthClientRepo:  oauthClientRepo,
		oauthRefreshRepo: oauthRefreshRepo,
		totpSecretRepo:   totpSecretRepo,
		identityRepo:     identityRepo,
		customRuleRepo:   customRuleRepo,
		social:           socialProviders,
	}, nil
}

func (c *containerImpl) Cfg() *config.Config         { return c.cfg }
func (c *containerImpl) DB() *gorm.DB                { return c.db }
func (c *containerImpl) KV() kv.Store                { return c.store }
func (c *containerImpl) Mailer() mailer.Mailer       { return c.mailer }
func (c *containerImpl) JWT() *jwt.Manager           { return c.jwt }
func (c *containerImpl) Enforcer() *casbinx.Enforcer { return c.enf }

func (c *containerImpl) UserRepo() repository.UserRepo                 { return c.userRepo }
func (c *containerImpl) AccountRepo() repository.AccountRepo           { return c.accountRepo }
func (c *containerImpl) OrgRepo() repository.OrgRepo                   { return c.orgRepo }
func (c *containerImpl) OrgMemberRepo() repository.OrgMemberRepo       { return c.orgMemberRepo }
func (c *containerImpl) AppRepo() repository.AppRepo                   { return c.appRepo }
func (c *containerImpl) ResourceRepo() repository.ResourceRepo         { return c.resourceRepo }
func (c *containerImpl) RoleRepo() repository.RoleRepo                 { return c.roleRepo }
func (c *containerImpl) RoleResourceRepo() repository.RoleResourceRepo { return c.roleResourceRepo }
func (c *containerImpl) AccountRoleRepo() repository.AccountRoleRepo   { return c.accountRoleRepo }
func (c *containerImpl) AccountGrantRepo() repository.AccountGrantRepo { return c.accountGrantRepo }
func (c *containerImpl) SessionRepo() repository.SessionRepo           { return c.sessionRepo }
func (c *containerImpl) InvitationRepo() repository.InvitationRepo     { return c.invitationRepo }
func (c *containerImpl) AuditLogRepo() repository.AuditLogRepo         { return c.auditLogRepo }
func (c *containerImpl) OAuthClientRepo() repository.OAuthClientRepo   { return c.oauthClientRepo }
func (c *containerImpl) OAuthRefreshTokenRepo() repository.OAuthRefreshTokenRepo {
	return c.oauthRefreshRepo
}
func (c *containerImpl) TOTPSecretRepo() repository.TOTPSecretRepo { return c.totpSecretRepo }

func (c *containerImpl) Redis() vredis.Client                      { return c.redis }
func (c *containerImpl) IdentityRepo() repository.IdentityRepo     { return c.identityRepo }
func (c *containerImpl) CustomRuleRepo() repository.CustomRuleRepo { return c.customRuleRepo }
func (c *containerImpl) SocialRegistry() map[string]social.Provider {
	return c.social
}

// Close releases the watcher (stops pub/sub), the Redis client and the
// database pool. Safe to call on a partially-initialized container.
func (c *containerImpl) Close() {
	if c.reconciler != nil {
		c.reconciler.Stop()
		c.reconciler = nil
	}
	if c.watcher != nil {
		c.watcher.Close()
		c.watcher = nil
	}
	if c.redis != nil {
		_ = c.redis.Close()
		c.redis = nil
	}
	if c.db != nil {
		closeDB(c.db)
		c.db = nil
	}
}

// release closes the resources acquired before a construction failure.
func release(db *gorm.DB, redisClient vredis.Client, watcher *casbinx.RedisWatcher) {
	if watcher != nil {
		watcher.Close()
	}
	if redisClient != nil {
		_ = redisClient.Close()
	}
	if db != nil {
		closeDB(db)
	}
}

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
