// M6 tests: the priority ladder + explicit eft/cond semantics of the
// 7-tuple model, the abacEval expression sandbox and the loader's handling
// of custom-rule rows.
package casbinx

import (
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/infra/model"
)

// grantDeny seeds a deny direct grant for the account on the resource.
func grantDeny(t *testing.T, f *fixture, accountID string, resource *model.Resource) {
	t.Helper()
	mustCreate(t, f.db, &model.AccountGrant{AccountID: accountID, ResourceID: resource.Id, Effect: EffectDeny})
}

// seedCustomRule inserts a custom rule row on the app.
func seedCustomRule(t *testing.T, f *fixture, appID, name, expr, effect string, priority int, status string) *model.CustomRule {
	t.Helper()
	row := &model.CustomRule{
		AppID:    appID,
		Name:     name,
		Expr:     expr,
		Effect:   effect,
		Priority: priority,
		Status:   status,
	}
	mustCreate(t, f.db, row)
	return row
}

// TestPriorityLadder drives the ladder table: the first matching rule in
// priority-ascending order decides allow/deny.
func TestPriorityLadder(t *testing.T) {
	cases := []struct {
		name  string
		seed  func(t *testing.T, f *fixture, account *model.Account)
		check check
	}{
		{
			name: "grant deny(20) beats role allow(50)",
			seed: func(t *testing.T, f *fixture, account *model.Account) {
				mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id})
				grantDeny(t, f, account.Id, f.resReadA)
			},
			check: check{"deny grant wins", "account:ID", "app:app-a", "order:read", "GET", false},
		},
		{
			name: "grant allow(30) beats role deny(45)",
			seed: func(t *testing.T, f *fixture, account *model.Account) {
				mustCreate(t, f.db, &model.RoleResource{RoleID: f.memberA.Id, ResourceID: f.resReadA.Id, Effect: EffectDeny})
				mustCreate(t, f.db, &model.AccountGrant{AccountID: account.Id, ResourceID: f.resReadA.Id, Effect: EffectAllow})
			},
			check: check{"grant allow wins", "account:ID", "app:app-a", "order:read", "GET", true},
		},
		{
			name: "super_admin(1) overrides a deny grant",
			seed: func(t *testing.T, f *fixture, account *model.Account) {
				mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.superAdmin.Id})
				grantDeny(t, f, account.Id, f.resReadA)
			},
			check: check{"super admin wins", "account:ID", "app:app-a", "order:read", "GET", true},
		},
		{
			name: "custom allow(40) beats role deny(45)",
			seed: func(t *testing.T, f *fixture, account *model.Account) {
				mustCreate(t, f.db, &model.RoleResource{RoleID: f.memberA.Id, ResourceID: f.resReadA.Id, Effect: EffectDeny})
				mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id})
				seedCustomRule(t, f, f.appA.Id, "read-ok", `obj == "order:read"`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)
			},
			check: check{"custom rule wins", "account:ID", "app:app-a", "order:read", "GET", true},
		},
		{
			name: "custom deny(40) beats role allow(50)",
			seed: func(t *testing.T, f *fixture, account *model.Account) {
				mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id})
				seedCustomRule(t, f, f.appA.Id, "no-read", `obj == "order:read"`, EffectDeny, PriorityCustomRuleDefault, model.CustomRuleStatusActive)
			},
			check: check{"custom deny wins", "account:ID", "app:app-a", "order:read", "GET", false},
		},
		{
			name: "role deny(45) beats custom allow at priority 50",
			seed: func(t *testing.T, f *fixture, account *model.Account) {
				mustCreate(t, f.db, &model.RoleResource{RoleID: f.memberA.Id, ResourceID: f.resReadA.Id, Effect: EffectDeny})
				mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id})
				seedCustomRule(t, f, f.appA.Id, "late-allow", `obj == "order:read"`, EffectAllow, 50, model.CustomRuleStatusActive)
			},
			check: check{"role deny wins", "account:ID", "app:app-a", "order:read", "GET", false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			account := f.seedAccount(t, f.appA, "active", "ladder")
			tc.seed(t, f, account)
			en := f.newEnforcer(t)
			c := tc.check
			c.sub = "account:" + account.Id
			runChecks(t, en, []check{c})
		})
	}
}

// TestEnforceNoMatchDenies re-checks the default-deny posture in the
// 7-tuple world.
func TestEnforceNoMatchDenies(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "nobody")
	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"no rules", "account:" + account.Id, "app:app-a", "order:read", "GET", false},
		{"unknown subject", "account:ghost", "app:app-a", "order:read", "GET", false},
	})
}

// TestCustomRuleExpressions covers the expression environment: obj/act/roles
// references and the now timestamp.
func TestCustomRuleExpressions(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "abac")
	mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.memberA.Id})
	// member role grants order:read (allow, 50). The custom rules below sit
	// at 40 and therefore refine/override the role grant.
	seedCustomRule(t, f, f.appA.Id, "read-act", `obj == "order:read" && act == "GET"`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)
	seedCustomRule(t, f, f.appA.Id, "member-role", `'member' in roles && obj == "order:write"`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)
	seedCustomRule(t, f, f.appA.Id, "time-gate", `obj == "time:check" && now.Year() > 2000`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)
	seedCustomRule(t, f, f.appA.Id, "ancient", `obj == "time:ancient" && now.Year() < 2000`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"obj+act condition matches", "account:" + account.Id, "app:app-a", "order:read", "GET", true},
		{"act mismatch falls back to role grant", "account:" + account.Id, "app:app-a", "order:read", "POST", true},
		{"roles grant write", "account:" + account.Id, "app:app-a", "order:write", "GET", true},
		{"roles missing for other subject", "account:ghost", "app:app-a", "order:write", "GET", false},
		{"time-gated rule passes", "account:" + account.Id, "app:app-a", "time:check", "GET", true},
		{"always-false time rule only", "account:" + account.Id, "app:app-a", "time:ancient", "GET", false},
		{"unmatched code denied", "account:" + account.Id, "app:app-a", "whatever:code", "GET", false},
	})
}

// TestCustomRuleRolesEnv verifies the roles env contains both domain-bound
// and wildcard-domain (global) role codes, prefix-stripped.
func TestCustomRuleRolesEnv(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "roleenv")
	mustCreate(t, f.db, &model.AccountRole{AccountID: account.Id, RoleID: f.orgAdmin.Id}) // global -> dom *
	seedCustomRule(t, f, f.appA.Id, "global-role", `'org_admin' in roles`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)
	seedCustomRule(t, f, f.appA.Id, "wrong-role", `'super_admin' in roles`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"global role visible in env", "account:" + account.Id, "app:app-a", "order:read", "GET", true},
	})
	// A negative assertion with a second account that has no roles at all.
	outsider := f.seedAccount(t, f.appA, "active", "outsider")
	runChecks(t, en, []check{
		{"wrong global role denied", "account:" + outsider.Id, "app:app-a", "order:read", "GET", false},
	})
}

// TestCustomRuleScopedToApp: a custom rule for app A must not leak into app B.
func TestCustomRuleScopedToApp(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appB, "active", "cross")
	seedCustomRule(t, f, f.appA.Id, "app-a-only", `obj != ""`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"rule does not cross apps", "account:" + account.Id, "app:app-b", "order:read", "GET", false},
	})
}

// TestCustomRuleDisabledAndInvalidSkipped: disabled rows and rows whose
// expression fails to compile are skipped at load (fail-closed) without
// failing the whole load.
func TestCustomRuleDisabledAndInvalidSkipped(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "skipme")
	seedCustomRule(t, f, f.appA.Id, "disabled", `obj != ""`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusDisabled)
	seedCustomRule(t, f, f.appA.Id, "broken", `this is not === valid expr`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)
	seedCustomRule(t, f, f.appA.Id, "unknown-ident", `definitely_not_in_env == 1`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)

	en := f.newEnforcer(t)
	runChecks(t, en, []check{
		{"broken rules fail closed", "account:" + account.Id, "app:app-a", "order:read", "GET", false},
	})
}

// TestEnforceRuntimeErrorFailsClose: a matching custom rule that fails at
// EVALUATION time surfaces (false, err) from Enforce — never an allow.
func TestEnforceRuntimeErrorFailsClose(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "runtime")
	seedCustomRule(t, f, f.appA.Id, "boom", `roles[99] == "member"`, EffectAllow, PriorityCustomRuleDefault, model.CustomRuleStatusActive)

	en := f.newEnforcer(t)
	allowed, err := en.Enforce("account:"+account.Id, "app:app-a", "order:read", "GET")
	if err == nil {
		t.Fatal("runtime evaluation failure must surface an error (fail-close)")
	}
	if allowed {
		t.Fatal("runtime evaluation failure must not allow")
	}
}

// TestIncrementalSevenTupleSync exercises AddPolicy/RemovePolicy with the
// 7-tuple shape (dom at rule[2]).
func TestIncrementalSevenTupleSync(t *testing.T) {
	f := newFixture(t)
	account := f.seedAccount(t, f.appA, "active", "incr7")
	en := f.newEnforcer(t)

	rule := []string{"30", "account:" + account.Id, "app:app-a", "order:write", "*", "allow", ""}
	ok, err := en.AddPolicy(rule...)
	if err != nil || !ok {
		t.Fatalf("incremental 7-tuple add: ok=%v err=%v", ok, err)
	}
	runChecks(t, en, []check{
		{"incremental grant allow", "account:" + account.Id, "app:app-a", "order:write", "GET", true},
	})

	denyRule := []string{"20", "account:" + account.Id, "app:app-a", "order:write", "*", "deny", ""}
	if _, err := en.AddPolicy(denyRule...); err != nil {
		t.Fatalf("add deny: %v", err)
	}
	runChecks(t, en, []check{
		{"deny (20) beats allow (30)", "account:" + account.Id, "app:app-a", "order:write", "GET", false},
	})

	if _, err := en.RemovePolicy(denyRule...); err != nil {
		t.Fatalf("remove deny: %v", err)
	}
	runChecks(t, en, []check{
		{"removal restores allow", "account:" + account.Id, "app:app-a", "order:write", "GET", true},
	})
}

// TestValidateExpr checks the sandbox: unknown identifiers and arbitrary
// function calls are rejected at compile time.
func TestValidateExpr(t *testing.T) {
	valid := []string{
		`obj == "order:read"`,
		`'manager' in roles`,
		`now.Hour() < 23`,
		`dom == "crm" && sub != ""`,
		`len(roles) > 0 && act == "GET"`,
		``,
	}
	for _, source := range valid {
		if err := ValidateExpr(source); err != nil {
			t.Errorf("ValidateExpr(%q) = %v, want nil", source, err)
		}
	}
	invalid := []string{
		`this is === not valid`,
		`definitely_not_in_env == 1`,
		`getenv("HOME") == ""`,
		`roles.len()`, // unknown method on []string
		`1 + 1`,       // non-boolean result
	}
	for _, source := range invalid {
		if err := ValidateExpr(source); err == nil {
			t.Errorf("ValidateExpr(%q) = nil, want error", source)
		}
	}
}

// TestTestExpr exercises the dry-run evaluation helper.
func TestTestExpr(t *testing.T) {
	env := ExprEnv{
		Sub:   "account:test-sub",
		Dom:   "crm",
		Obj:   "order:read",
		Act:   "GET",
		Roles: []string{"manager"},
		Now:   time.Now(),
	}
	allowed, err := TestExpr(`obj == "order:read" && 'manager' in roles`, env)
	if err != nil || !allowed {
		t.Fatalf("TestExpr = %v, %v; want true, nil", allowed, err)
	}
	allowed, err = TestExpr(`act == "POST"`, env)
	if err != nil || allowed {
		t.Fatalf("TestExpr = %v, %v; want false, nil", allowed, err)
	}
	if _, err := TestExpr(`roles[99] == "x"`, env); err == nil {
		t.Fatal("runtime failure must return an error")
	}
}
