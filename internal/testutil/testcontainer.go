// Package testutil provides the shared test double wiring (sqlite container,
// recording mailer, in-memory KV, generated RSA keys) used by the service
// unit tests and the HTTP integration test.
package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/config"
	"github.com/flametest/access-hub/internal/container"
	casbinx "github.com/flametest/access-hub/internal/infra/casbin"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/mailer"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/internal/infra/social"
	"github.com/flametest/vita/vgorm"
	log "github.com/flametest/vita/vlog"
	"github.com/flametest/vita/vredis"
	"github.com/flametest/vita/vserver"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// init once per process: the global zerolog logger must be initialized before
// any code path logs (bootstrap writes to the global logger).
var logOnce sync.Once

func initLogger() {
	logOnce.Do(func() {
		log.InitLogger(log.ZerologType, "access-hub-test", log.ErrorLevel)
	})
}

// Message is one recorded email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// RecordingMailer is a fake Mailer capturing every message for assertions
// (e.g. extracting emailed verification codes).
type RecordingMailer struct {
	mu       sync.Mutex
	Messages []Message
}

var _ mailer.Mailer = (*RecordingMailer)(nil)

// Send records the message.
func (m *RecordingMailer) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Messages = append(m.Messages, Message{To: to, Subject: subject, Body: body})
	return nil
}

// Last returns the most recent message ("" when none).
func (m *RecordingMailer) Last() Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Messages) == 0 {
		return Message{}
	}
	return m.Messages[len(m.Messages)-1]
}

// TestContainer is a container.Container wired to sqlite (in-memory),
// kv.MemoryStore, the RecordingMailer and a real JWT manager + casbin
// enforcer (no watcher).
type TestContainer struct {
	CfgVal *config.Config
	DBVal  *gorm.DB
	KVVal  *kv.MemoryStore
	Mail   *RecordingMailer
	JWTVal *jwt.Manager
	EnfVal *casbinx.Enforcer

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

	// SocialVal is the social provider registry the services see. Tests may
	// replace it (e.g. with injectable endpoints pointing at a local fake)
	// before exercising the flows.
	SocialVal map[string]social.Provider
}

var _ container.Container = (*TestContainer)(nil)

// New builds the test container. Tests drive cfg mutations through tc.CfgVal
// (e.g. LoginMaxAttempts) before exercising the flows.
func New(t *testing.T) *TestContainer {
	t.Helper()
	initLogger()

	dbName := fmt.Sprintf("access-hub-test-%d", time.Now().UnixNano())
	db, err := vgorm.NewDB(&vgorm.Config{
		Dialect:  vgorm.DialectSQLite3,
		Database: dbName,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	for _, ddl := range schemaDDL {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("exec ddl: %v", err)
		}
	}

	privatePath, publicPath := writeRSAKeys(t)

	cfg := &config.Config{
		AppConfig: vserver.EchoServerConfig{Name: "access-hub-test", Addr: ":0"},
		Auth: config.AuthConfig{
			AccessTokenTTL:       15 * time.Minute,
			RefreshTokenTTL:      24 * time.Hour,
			RSAPrivateKeyPath:    privatePath,
			RSAPublicKeyPath:     publicPath,
			EmailCodeTTL:         10 * time.Minute,
			EmailCodeMaxAttempts: 5,
			SendCodeInterval:     60 * time.Second,
			SendCodeIPLimit:      10,
			LoginMaxAttempts:     5,
			LoginLockDuration:    15 * time.Minute,
			AllowAutoRegister:    true,
			BcryptCost:           bcrypt.MinCost,
			IssuerURL:            "http://localhost:8080",
			PortalURL:            "http://localhost:3000",
			MFATokenTTL:          5 * time.Minute,
		},
		Bootstrap: config.BootstrapConfig{
			AdminUsername: "root",
			AdminEmail:    "root@access-hub.test",
			AdminPassword: "RootPassw0rd",
		},
	}

	mgr, err := jwt.NewManager(privatePath, publicPath)
	if err != nil {
		t.Fatalf("jwt manager: %v", err)
	}
	loader := casbinx.NewLoader(
		repository.NewRoleRepo(db),
		repository.NewRoleResourceRepo(db),
		repository.NewAccountRoleRepo(db),
		repository.NewAccountGrantRepo(db),
		repository.NewOAuthClientRepo(db),
		repository.NewCustomRuleRepo(db),
		repository.NewAppRepo(db),
	)
	enf, err := casbinx.NewEnforcer(loader)
	if err != nil {
		t.Fatalf("casbin enforcer: %v", err)
	}

	tc := &TestContainer{
		CfgVal:           cfg,
		DBVal:            db,
		KVVal:            kv.NewMemoryStore(),
		Mail:             &RecordingMailer{},
		JWTVal:           mgr,
		EnfVal:           enf,
		userRepo:         repository.NewUserRepo(db),
		accountRepo:      repository.NewAccountRepo(db),
		orgRepo:          repository.NewOrgRepo(db),
		orgMemberRepo:    repository.NewOrgMemberRepo(db),
		appRepo:          repository.NewAppRepo(db),
		resourceRepo:     repository.NewResourceRepo(db),
		roleRepo:         repository.NewRoleRepo(db),
		roleResourceRepo: repository.NewRoleResourceRepo(db),
		accountRoleRepo:  repository.NewAccountRoleRepo(db),
		accountGrantRepo: repository.NewAccountGrantRepo(db),
		sessionRepo:      repository.NewSessionRepo(db),
		invitationRepo:   repository.NewInvitationRepo(db),
		auditLogRepo:     repository.NewAuditLogRepo(db),
		oauthClientRepo:  repository.NewOAuthClientRepo(db),
		oauthRefreshRepo: repository.NewOAuthRefreshTokenRepo(db),
		totpSecretRepo:   repository.NewTOTPSecretRepo(db),
		identityRepo:     repository.NewIdentityRepo(db),
		customRuleRepo:   repository.NewCustomRuleRepo(db),
	}
	tc.SocialVal = social.NewRegistry(cfg.Social)
	return tc
}

func (tc *TestContainer) Cfg() *config.Config  { return tc.CfgVal }
func (tc *TestContainer) DB() *gorm.DB         { return tc.DBVal }
func (tc *TestContainer) Redis() vredis.Client { return nil }

func (tc *TestContainer) KV() kv.Store                { return tc.KVVal }
func (tc *TestContainer) Mailer() mailer.Mailer       { return tc.Mail }
func (tc *TestContainer) JWT() *jwt.Manager           { return tc.JWTVal }
func (tc *TestContainer) Enforcer() *casbinx.Enforcer { return tc.EnfVal }

func (tc *TestContainer) UserRepo() repository.UserRepo                 { return tc.userRepo }
func (tc *TestContainer) AccountRepo() repository.AccountRepo           { return tc.accountRepo }
func (tc *TestContainer) OrgRepo() repository.OrgRepo                   { return tc.orgRepo }
func (tc *TestContainer) OrgMemberRepo() repository.OrgMemberRepo       { return tc.orgMemberRepo }
func (tc *TestContainer) AppRepo() repository.AppRepo                   { return tc.appRepo }
func (tc *TestContainer) ResourceRepo() repository.ResourceRepo         { return tc.resourceRepo }
func (tc *TestContainer) RoleRepo() repository.RoleRepo                 { return tc.roleRepo }
func (tc *TestContainer) RoleResourceRepo() repository.RoleResourceRepo { return tc.roleResourceRepo }
func (tc *TestContainer) AccountRoleRepo() repository.AccountRoleRepo   { return tc.accountRoleRepo }
func (tc *TestContainer) AccountGrantRepo() repository.AccountGrantRepo { return tc.accountGrantRepo }
func (tc *TestContainer) SessionRepo() repository.SessionRepo           { return tc.sessionRepo }
func (tc *TestContainer) InvitationRepo() repository.InvitationRepo     { return tc.invitationRepo }
func (tc *TestContainer) AuditLogRepo() repository.AuditLogRepo         { return tc.auditLogRepo }
func (tc *TestContainer) OAuthClientRepo() repository.OAuthClientRepo   { return tc.oauthClientRepo }
func (tc *TestContainer) OAuthRefreshTokenRepo() repository.OAuthRefreshTokenRepo {
	return tc.oauthRefreshRepo
}
func (tc *TestContainer) TOTPSecretRepo() repository.TOTPSecretRepo { return tc.totpSecretRepo }
func (tc *TestContainer) IdentityRepo() repository.IdentityRepo     { return tc.identityRepo }
func (tc *TestContainer) CustomRuleRepo() repository.CustomRuleRepo { return tc.customRuleRepo }
func (tc *TestContainer) SocialRegistry() map[string]social.Provider {
	return tc.SocialVal
}

// Close is a no-op for tests (cleanup is registered per resource).
func (tc *TestContainer) Close() {}

// Seed inserts a row with an explicit UUID (sqlite has no gen_random_uuid()).
func Seed(t *testing.T, tc *TestContainer, row *model.User) {
	t.Helper()
	if err := tc.userRepo.Create(context.Background(), row); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// writeRSAKeys generates a fresh RSA key pair and writes PEM files (the
// production jwt.Manager reads keys from disk).
func writeRSAKeys(t *testing.T) (privatePath, publicPath string) {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privatePath = filepath.Join(dir, "private.pem")
	publicPath = filepath.Join(dir, "public.pem")
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := os.WriteFile(publicPath, publicPEM, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return privatePath, publicPath
}

// schemaDDL is the sqlite-adapted full schema (mirrors migration/init.sql:
// TEXT ids set explicitly in Go, DATETIME timestamps, TEXT jsonb columns).
var schemaDDL = []string{
	`CREATE TABLE orgs (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		"key" TEXT NOT NULL,
		name TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE org_members (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		org_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		org_role TEXT NOT NULL DEFAULT 'member',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE users (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		username TEXT NOT NULL,
		email TEXT NOT NULL,
		email_verified BOOLEAN NOT NULL DEFAULT FALSE,
		password_hash TEXT,
		nickname TEXT,
		avatar_url TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
		last_login_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE accounts (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		identity_id TEXT NOT NULL,
		app_id TEXT NOT NULL,
		email TEXT NOT NULL,
		username TEXT,
		password_hash TEXT,
		display_name TEXT,
		status TEXT NOT NULL DEFAULT 'pending_activation',
		source TEXT NOT NULL DEFAULT 'invite',
		last_login_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE invitations (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		email TEXT NOT NULL,
		role_ids TEXT NOT NULL DEFAULT '[]',
		invited_by TEXT NOT NULL,
		code_hash TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		accepted_at DATETIME,
		accepted_account_id TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE apps (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		"key" TEXT NOT NULL,
		org_id TEXT,
		name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'web',
		description TEXT,
		logo_url TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE resources (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		parent_id TEXT,
		type TEXT NOT NULL,
		code TEXT NOT NULL,
		name TEXT NOT NULL,
		sort INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'active',
		visible BOOLEAN NOT NULL DEFAULT TRUE,
		icon TEXT,
		method TEXT,
		route_path TEXT,
		extra TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE roles (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		code TEXT NOT NULL,
		name TEXT NOT NULL,
		scope TEXT NOT NULL DEFAULT 'app',
		built_in BOOLEAN NOT NULL DEFAULT FALSE,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE role_resources (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		role_id TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		effect TEXT NOT NULL DEFAULT 'allow',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE account_roles (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		account_id TEXT NOT NULL,
		role_id TEXT NOT NULL,
		granted_by TEXT,
		granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE account_grants (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		account_id TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		granted_by TEXT,
		granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		effect TEXT NOT NULL DEFAULT 'allow',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		user_id TEXT NOT NULL,
		scope TEXT NOT NULL DEFAULT 'identity',
		account_id TEXT,
		app_id TEXT,
		refresh_token_hash TEXT NOT NULL,
		device TEXT,
		ip TEXT,
		last_used_at DATETIME,
		rotation_count INTEGER NOT NULL DEFAULT 0,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	// Partial unique indexes mirroring migration/init.sql so ON CONFLICT
	// clauses and uniqueness behave like production Postgres.
	`CREATE UNIQUE INDEX uq_orgs_key ON orgs ("key") WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_org_members_org_user ON org_members (org_id, user_id) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_users_username ON users (LOWER(username)) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_users_email ON users (LOWER(email)) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_accounts_app_email ON accounts (app_id, LOWER(email)) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_apps_key ON apps ("key") WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_resources_app_code ON resources (app_id, code) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_roles_app_code ON roles (app_id, code) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_role_resources ON role_resources (role_id, resource_id) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_account_roles ON account_roles (account_id, role_id) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_account_grants ON account_grants (account_id, resource_id) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_sessions_token_hash ON sessions (refresh_token_hash) WHERE deleted_at IS NULL`,
	`CREATE TABLE audit_logs (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		actor_type TEXT NOT NULL,
		actor_id TEXT,
		org_id TEXT,
		action TEXT NOT NULL,
		target_type TEXT,
		target_id TEXT,
		detail TEXT,
		ip TEXT,
		user_agent TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	// M4 tables (mirror migration/0002_m4.sql).
	`CREATE TABLE oauth_clients (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		name TEXT NOT NULL,
		client_type TEXT NOT NULL DEFAULT 'confidential',
		secret_hash TEXT,
		grant_types TEXT NOT NULL DEFAULT '[]',
		redirect_uris TEXT NOT NULL DEFAULT '[]',
		scopes TEXT NOT NULL DEFAULT '[]',
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE oauth_refresh_tokens (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		client_id TEXT NOT NULL,
		user_id TEXT,
		account_id TEXT,
		token_hash TEXT NOT NULL,
		scope TEXT NOT NULL DEFAULT '',
		rotation_count INTEGER NOT NULL DEFAULT 0,
		last_used_at DATETIME,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE TABLE totp_secrets (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		user_id TEXT NOT NULL,
		secret TEXT NOT NULL,
		confirmed BOOLEAN NOT NULL DEFAULT FALSE,
		last_used_step INTEGER NOT NULL DEFAULT 0,
		backup_codes TEXT NOT NULL DEFAULT '[]',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE UNIQUE INDEX uq_oauth_refresh_hash ON oauth_refresh_tokens (token_hash) WHERE deleted_at IS NULL`,
	`CREATE UNIQUE INDEX uq_totp_user ON totp_secrets (user_id) WHERE deleted_at IS NULL`,
	// M5 tables (mirror migration/0003_m5.sql).
	`CREATE TABLE identities (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		user_id TEXT NOT NULL,
		provider TEXT NOT NULL,
		provider_user_id TEXT NOT NULL,
		email TEXT,
		email_verified BOOLEAN NOT NULL DEFAULT FALSE,
		display_name TEXT,
		avatar_url TEXT,
		raw_profile TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE UNIQUE INDEX uq_identities_provider_uid ON identities (provider, provider_user_id) WHERE deleted_at IS NULL`,
	`CREATE INDEX idx_identities_user ON identities (user_id) WHERE deleted_at IS NULL`,
	// M6 tables (mirror migration/0004_m6.sql).
	`CREATE TABLE custom_rules (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL DEFAULT 0,
		app_id TEXT NOT NULL,
		name TEXT NOT NULL,
		expr TEXT NOT NULL,
		effect TEXT NOT NULL DEFAULT 'allow',
		priority INTEGER NOT NULL DEFAULT 40,
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at DATETIME
	)`,
	`CREATE UNIQUE INDEX uq_custom_rules_app_name ON custom_rules (app_id, name) WHERE deleted_at IS NULL`,
	`CREATE INDEX idx_custom_rules_app ON custom_rules (app_id) WHERE deleted_at IS NULL`,
}
