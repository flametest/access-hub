// Package container wires the application singletons: config, database,
// Redis-backed KV store, mailer, JWT manager, repositories and the Casbin
// enforcer with its Redis reload watcher (design.md §4).
package container

import (
	"github.com/flametest/access-hub/internal/config"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/mailer"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
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

	// Close releases the watcher, the Redis client and the database pool.
	Close()
}

type containerImpl struct {
	cfg     *config.Config
	db      *gorm.DB
	redis   vredis.Client
	store   kv.Store
	mailer  mailer.Mailer
	jwt     *jwt.Manager
	watcher *casbinx.RedisWatcher
	enf     *casbinx.Enforcer

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

	// Casbin enforcer over the read-only policy loader.
	loader := casbinx.NewLoader(roleRepo, roleResourceRepo, accountRoleRepo, accountGrantRepo)
	enf, err := casbinx.NewEnforcer(loader)
	if err != nil {
		release(db, redisClient, nil)
		return nil, err
	}

	// Redis watcher: reload broadcasts on the casbin:reload channel trigger a
	// full policy re-load on this instance too.
	watcher := casbinx.NewRedisWatcher(*cfg.Redis, func() { _ = enf.Reload() })
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

// Close releases the watcher (stops pub/sub), the Redis client and the
// database pool. Safe to call on a partially-initialized container.
func (c *containerImpl) Close() {
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
