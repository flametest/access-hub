package casbinx

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/vgorm"
	log "github.com/flametest/vita/vlog"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TestMain initializes the global logger: the watcher's panic-recovery path
// logs, and vlog's package-global logger is nil until initialized.
func TestMain(m *testing.M) {
	log.InitLogger(log.ZerologType, "access-hub-test", log.DebugLevel)
	os.Exit(m.Run())
}

// fixture is a fully seeded policy world on a private sqlite in-memory DB.
type fixture struct {
	db         *gorm.DB
	appA       *model.App // business app A
	appB       *model.App // business app B
	adminApp   *model.App // platform admin app (owns global roles)
	superAdmin *model.Role
	orgAdmin   *model.Role
	memberA    *model.Role // app-scope role on app A
	resReadA   *model.Resource
	resWriteA  *model.Resource
}

func mustCreate(t *testing.T, db *gorm.DB, v interface{}) {
	t.Helper()
	// sqlite has no gen_random_uuid() default: backfill empty ids.
	fillID(v)
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("seed %T: %v", v, err)
	}
}

// fillID assigns a fresh UUID when the model's primary key is empty
// (mirrors the gen_random_uuid() default on PostgreSQL).
func fillID(v interface{}) {
	switch m := v.(type) {
	case *model.App:
		m.Id = mustUUID(m.Id)
	case *model.Resource:
		m.Id = mustUUID(m.Id)
	case *model.Role:
		m.Id = mustUUID(m.Id)
	case *model.RoleResource:
		m.Id = mustUUID(m.Id)
	case *model.User:
		m.Id = mustUUID(m.Id)
	case *model.Account:
		m.Id = mustUUID(m.Id)
	case *model.AccountRole:
		m.Id = mustUUID(m.Id)
	case *model.AccountGrant:
		m.Id = mustUUID(m.Id)
	case *model.CustomRule:
		m.Id = mustUUID(m.Id)
	}
}

func mustUUID(id string) string {
	if id != "" {
		return id
	}
	return uuid.NewString()
}

// newFixture seeds two business apps, the admin app with the built-in global
// roles, one app-scope role with resources, and disabled variants for the
// skip-cases. Rows reference each other via generated ids.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := setupDB(t)
	ctx := context.Background()

	f := &fixture{
		db:       db,
		appA:     &model.App{Key: "app-a", Name: "App A", Type: "web", Status: "active"},
		appB:     &model.App{Key: "app-b", Name: "App B", Type: "web", Status: "active"},
		adminApp: &model.App{Key: "admin", Name: "Console", Type: "web", Status: "active"},
	}
	for _, app := range []*model.App{f.appA, f.appB, f.adminApp} {
		mustCreate(t, db, app)
	}

	f.resReadA = &model.Resource{AppID: f.appA.Id, Type: "api", Code: "order:read", Name: "Read orders", Status: "active"}
	f.resWriteA = &model.Resource{AppID: f.appA.Id, Type: "api", Code: "order:write", Name: "Write orders", Status: "active"}
	mustCreate(t, db, f.resReadA)
	mustCreate(t, db, f.resWriteA)

	f.superAdmin = &model.Role{AppID: f.adminApp.Id, Code: "super_admin", Name: "Super Admin", Scope: "global", BuiltIn: true}
	f.orgAdmin = &model.Role{AppID: f.adminApp.Id, Code: "org_admin", Name: "Org Admin", Scope: "global", BuiltIn: true}
	f.memberA = &model.Role{AppID: f.appA.Id, Code: "member", Name: "Member", Scope: "app", BuiltIn: false}
	for _, role := range []*model.Role{f.superAdmin, f.orgAdmin, f.memberA} {
		mustCreate(t, db, role)
	}

	// member role of app A grants order:read.
	mustCreate(t, db, &model.RoleResource{RoleID: f.memberA.Id, ResourceID: f.resReadA.Id, Effect: "allow"})
	// org_admin (global) grants order:read on app A too (dom follows resource).
	mustCreate(t, db, &model.RoleResource{RoleID: f.orgAdmin.Id, ResourceID: f.resReadA.Id, Effect: "allow"})

	_ = ctx
	return f
}

// seedAccount inserts an active user + account pair for the app.
func (f *fixture) seedAccount(t *testing.T, app *model.App, status string, username string) *model.Account {
	t.Helper()
	hashX := "x"
	user := &model.User{
		BasePostgres:  vgorm.BasePostgres{Id: uuid.NewString()},
		Username:      username,
		Email:         username + "@example.com",
		Status:        "active",
		EmailVerified: true,
	}
	mustCreate(t, f.db, user)
	account := &model.Account{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		IdentityID:   user.Id,
		AppID:        app.Id,
		Email:        username + "@example.com",
		PasswordHash: &hashX,
		Status:       status,
		Source:       "invite",
	}
	mustCreate(t, f.db, account)
	return account
}

// newEnforcer builds the enforcer from the fixture's repositories.
func (f *fixture) newEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	loader := NewLoader(
		repository.NewRoleRepo(f.db),
		repository.NewRoleResourceRepo(f.db),
		repository.NewAccountRoleRepo(f.db),
		repository.NewAccountGrantRepo(f.db),
		repository.NewOAuthClientRepo(f.db),
		repository.NewCustomRuleRepo(f.db),
		repository.NewAppRepo(f.db),
	)
	en, err := NewEnforcer(loader)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	return en
}

// check is one enforce expectation.
type check struct {
	name string
	sub  string
	dom  string
	obj  string
	act  string
	want bool
}

func runChecks(t *testing.T, en *Enforcer, checks []check) {
	t.Helper()
	for _, c := range checks {
		got, err := en.Enforce(c.sub, c.dom, c.obj, c.act)
		if err != nil {
			t.Fatalf("%s: enforce: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: Enforce(%s, %s, %s, %s) = %v, want %v", c.name, c.sub, c.dom, c.obj, c.act, got, c.want)
		}
	}
}

func TestEnforceSuperAdminWildcard(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appB, "active", "super")
	mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.superAdmin.Id})

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"super admin any domain", "account:" + account.Id, "app:app-a", "order:read", "GET", true},
		{"super admin any object", "account:" + account.Id, "app:app-b", "whatever:code", "POST", true},
		{"super admin admin domain", "account:" + account.Id, "app:admin", "admin:users", "DELETE", true},
	})
}

func TestEnforceRoleBinding(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "member1")
	mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id})

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"role grants order:read", "account:" + account.Id, "app:app-a", "order:read", "GET", true},
		{"act wildcard on policy", "account:" + account.Id, "app:app-a", "order:read", "POST", true},
		{"ungranted object denied", "account:" + account.Id, "app:app-a", "order:write", "GET", false},
		{"other app denied", "account:" + account.Id, "app:app-b", "order:read", "GET", false},
	})
}

func TestEnforceDirectGrant(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "direct")
	mustCreate(t, f.db, &model.AccountGrant{AccountID: account.Id, ResourceID: f.resWriteA.Id, Effect: "allow"})

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"direct grant allowed", "account:" + account.Id, "app:app-a", "order:write", "GET", true},
		{"non-granted denied", "account:" + account.Id, "app:app-a", "order:read", "GET", false},
	})
}

func TestEnforceGlobalRoleCrossApp(t *testing.T) {
	f := newFixture(t)
	// Account lives on app B but holds the global org_admin role; the role's
	// resource (order:read on app A) must be enforceable in app A's domain.
	account := f.seedAccount(t, f.appB, "active", "orgadmin")
	mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.orgAdmin.Id})

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"global role reaches app A", "account:" + account.Id, "app:app-a", "order:read", "GET", true},
		{"global role only grants bound resources", "account:" + account.Id, "app:app-a", "order:write", "GET", false},
	})
}

func TestEnforceExpiredGrantSkipped(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "temporal")

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	mustCreate(t, f.db, &model.AccountGrant{AccountID: account.Id, ResourceID: f.resReadA.Id, Effect: "allow", ExpiresAt: &past})
	mustCreate(t, f.db, &model.AccountGrant{AccountID: account.Id, ResourceID: f.resWriteA.Id, Effect: "allow", ExpiresAt: &future})

	// Expired role binding too.
	mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id, ExpiresAt: &past})

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"expired grant skipped", "account:" + account.Id, "app:app-a", "order:read", "GET", false},
		{"future grant still active", "account:" + account.Id, "app:app-a", "order:write", "GET", true},
	})
}

func TestEnforceDenyByDefault(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "plain")

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"no policies -> deny", "account:" + account.Id, "app:app-a", "order:read", "GET", false},
		{"unknown subject -> deny", "account:nope", "app:app-a", "order:read", "GET", false},
	})
}

func TestEnforceSkipsDisabledAndDeletedEntities(t *testing.T) {
	f := newFixture(t)

	// Disabled account: its role binding must not be loaded.
	disabled := f.seedAccount(t, f.appA, "disabled", "disabled1")
	mustCreate(t, f.db, &model.AccountRole{AccountID: disabled.Id, RoleID: f.memberA.Id})

	// Active account bound to a soft-deleted role.
	account := f.seedAccount(t, f.appA, "active", "ghost")
	ghostRole := &model.Role{AppID: f.appA.Id, Code: "ghost", Name: "Ghost", Scope: "app"}
	mustCreate(t, f.db, ghostRole)
	mustCreate(t, f.db, &model.RoleResource{RoleID: ghostRole.Id, ResourceID: f.resReadA.Id, Effect: "allow"})
	if err := f.db.Delete(ghostRole).Error; err != nil {
		t.Fatalf("soft delete role: %v", err)
	}

	// Active account whose app is disabled.
	coldApp := &model.App{Key: "cold-app", Name: "Cold", Type: "web", Status: "disabled"}
	mustCreate(t, f.db, coldApp)
	coldAccount := f.seedAccount(t, coldApp, "active", "cold")
	mustCreate(t, f.db, &model.AccountRole{AccountID: coldAccount.Id, RoleID: f.memberA.Id})

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"disabled account skipped", "account:" + disabled.Id, "app:app-a", "order:read", "GET", false},
		{"soft-deleted role skipped", "account:" + account.Id, "app:app-a", "order:read", "GET", false},
		{"disabled app skipped", "account:" + coldAccount.Id, "app:cold-app", "order:read", "GET", false},
	})
}

func TestReloadPicksUpNewPolicies(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "late")

	en := f.newEnforcer(t)
	got, err := en.Enforce("account:"+account.Id, "app:app-a", "order:read", "GET")
	if err != nil || got {
		t.Fatalf("before grant: got=%v err=%v, want false", got, err)
	}

	mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id})
	if err := en.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	runChecks(t, en, []check{
		{"after reload binding active", "account:" + account.Id, "app:app-a", "order:read", "GET", true},
	})
}

func TestIncrementalUpdatesAndReload(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "incr")

	en := f.newEnforcer(t)
	ok, err := en.AddGroupingPolicy("account:"+account.Id, "role:member", "app:app-a")
	if err != nil || !ok {
		t.Fatalf("incremental add: ok=%v err=%v", ok, err)
	}
	runChecks(t, en, []check{
		{"incremental g rule active", "account:" + account.Id, "app:app-a", "order:read", "GET", true},
	})

	ok, err = en.RemoveGroupingPolicy("account:"+account.Id, "role:member", "app:app-a")
	if err != nil || !ok {
		t.Fatalf("incremental remove: ok=%v err=%v", ok, err)
	}
	runChecks(t, en, []check{
		{"incremental removal active", "account:" + account.Id, "app:app-a", "order:read", "GET", false},
	})
}

func TestLoaderRejectsWrites(t *testing.T) {
	f := newFixture(t)
	loader := NewLoader(
		repository.NewRoleRepo(f.db),
		repository.NewRoleResourceRepo(f.db),
		repository.NewAccountRoleRepo(f.db),
		repository.NewAccountGrantRepo(f.db),
		repository.NewOAuthClientRepo(f.db),
		repository.NewCustomRuleRepo(f.db),
		repository.NewAppRepo(f.db),
	)
	if err := loader.SavePolicy(nil); err == nil {
		t.Fatal("SavePolicy must be rejected")
	}
	if err := loader.AddPolicy("p", "p", []string{"a", "b", "c", "d"}); err == nil {
		t.Fatal("AddPolicy must be rejected")
	}
	if err := loader.RemovePolicy("p", "p", []string{"a", "b", "c", "d"}); err == nil {
		t.Fatal("RemovePolicy must be rejected")
	}
	if err := loader.RemoveFilteredPolicy("p", "p", 0); err == nil {
		t.Fatal("RemoveFilteredPolicy must be rejected")
	}
}

func TestWatcherSetUpdateCallbackAndDispatch(t *testing.T) {
	w := &RedisWatcher{closed: make(chan struct{})}
	var calls int32
	_ = w.SetUpdateCallback(func(string) { atomic.AddInt32(&calls, 1) })
	w.dispatch("reload")
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if w.UpdateCallback() == nil {
		t.Fatal("UpdateCallback should return the set callback")
	}
	// A panicking callback must not take down the watcher goroutine.
	_ = w.SetUpdateCallback(func(string) { panic("boom") })
	w.dispatch("reload")
	_ = w.SetUpdateCallback(func(string) { atomic.AddInt32(&calls, 1) })
	w.dispatch("reload")
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("calls after panic recovery = %d, want 2", calls)
	}
	w.Close()
	w.Close() // idempotent
}

func TestPolicyVersion(t *testing.T) {
	ctx := context.Background()
	store := kv.NewMemoryStore()

	v, err := GetPolicyVersion(ctx, store, "app-a")
	if err != nil || v != 0 {
		t.Fatalf("initial version = %d err = %v, want 0", v, err)
	}
	for i := int64(1); i <= 3; i++ {
		v, err = IncrPolicyVersion(ctx, store, "app-a")
		if err != nil || v != i {
			t.Fatalf("incr %d: v=%d err=%v", i, v, err)
		}
	}
	if got := PolicyVersionKey("app-a"); got != "policy:ver:app-a" {
		t.Fatalf("key = %q", got)
	}
}
