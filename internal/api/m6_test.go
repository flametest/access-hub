// M6 integration tests over HTTP: deny enablement (role deny bindings, deny
// grants), custom ABAC rule CRUD + dry-run + matcher participation, enforcer
// driven menus, org_admin scoping of the custom-rule codes and the audit
// summary shape.
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/api"
	"github.com/flametest/access-hub/internal/bootstrap"
	"github.com/flametest/access-hub/internal/testutil"
	"github.com/flametest/vita/vserver"
)

func TestM6CustomRulesAndDeny(t *testing.T) {
	tc := testutil.New(t)
	ctx := context.Background()

	if err := bootstrap.Run(ctx, tc); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := api.SyncAdminResources(ctx, tc); err != nil {
		t.Fatalf("sync admin resources: %v", err)
	}

	srv, err := vserver.NewEchoServer(ctx, &vserver.EchoServerConfig{Name: "access-hub-m6", Addr: ":0"})
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	srv = api.NewApp(tc).Router(srv)
	ts := httptest.NewServer(srv.(*vserver.EchoServer).GetEchoServer())
	t.Cleanup(ts.Close)

	doJSON := func(method, path, token string, body any) (int, any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, ts.URL+path, reader)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if len(raw) == 0 {
			return resp.StatusCode, nil
		}
		var out any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
		return resp.StatusCode, out
	}
	asMap := func(v any) map[string]any {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("expected object, got %T: %v", v, v)
		}
		return m
	}
	asList := func(v any) []any {
		l, ok := v.([]any)
		if !ok {
			t.Fatalf("expected array, got %T: %v", v, v)
		}
		return l
	}
	expectCode := func(status, want int, body any) {
		t.Helper()
		if status != want {
			t.Fatalf("status = %d, want %d (body: %v)", status, want, body)
		}
	}
	num := func(m map[string]any, key string) float64 {
		v, ok := m[key].(float64)
		if !ok {
			t.Fatalf("field %q missing or not a number: %v", key, m)
		}
		return v
	}
	str := func(m map[string]any, key string) string {
		v, ok := m[key].(string)
		if !ok {
			t.Fatalf("field %q missing or not a string: %v", key, m)
		}
		return v
	}

	// ---------- world setup: root, org, app, resources, role, account ----------
	status, body := doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "root@access-hub.test", "password": "RootPassw0rd",
	})
	expectCode(status, 200, body)
	rootToken := str(asMap(body), "access_token")

	status, body = doJSON("POST", "/api/v1/auth/register", "", map[string]any{
		"username": "alice", "email": "alice@test.dev", "password": "AlicePassw0rd",
	})
	expectCode(status, 201, body)
	aliceToken := str(asMap(body), "access_token")

	status, body = doJSON("POST", "/api/v1/admin/orgs", rootToken, map[string]any{"key": "acme", "name": "Acme Inc"})
	expectCode(status, 201, body)
	status, body = doJSON("POST", "/api/v1/admin/apps", rootToken, map[string]any{
		"key": "crm", "org_key": "acme", "name": "CRM", "type": "web",
	})
	expectCode(status, 201, body)
	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/resources:batch", rootToken, map[string]any{
		"items": []any{
			map[string]any{"type": "menu", "code": "crm.dashboard", "name": "Dashboard", "path": "/", "sort": 1},
			map[string]any{"type": "api", "code": "order:read", "name": "Read orders", "method": "GET", "route_path": "/api/orders"},
			map[string]any{"type": "api", "code": "order:create", "name": "Create orders", "method": "POST", "route_path": "/api/orders"},
		},
	})
	expectCode(status, 200, body)
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/roles", rootToken, map[string]any{"code": "manager", "name": "Manager"})
	expectCode(status, 201, body)
	managerRoleID := str(asMap(body), "id")

	status, body = doJSON("GET", "/api/v1/admin/apps/crm/resources", rootToken, nil)
	expectCode(status, 200, body)
	resourceIDs := map[string]string{}
	var walk func(nodes []any)
	walk = func(nodes []any) {
		for _, n := range nodes {
			node := asMap(n)
			resourceIDs[node["code"].(string)] = node["id"].(string)
			if children, ok := node["children"].([]any); ok {
				walk(children)
			}
		}
	}
	walk(asList(body))

	// ---------- 1. role deny binding flips authz/check and hides the menu ----
	// Legacy all-allow shape binds dashboard + order:read.
	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/roles/"+managerRoleID+"/resources", rootToken, map[string]any{
		"resource_ids": []string{resourceIDs["crm.dashboard"], resourceIDs["order:read"]},
	})
	expectCode(status, 200, body)

	status, body = doJSON("POST", "/api/v1/admin/apps/crm/accounts", rootToken, map[string]any{
		"email": "alice@test.dev", "role_ids": []string{managerRoleID}, "password": "AliceCrmPass1",
	})
	expectCode(status, 201, body)
	aliceAccountID := str(asMap(body), "account_id")

	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:read",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != true {
		t.Fatalf("role allow must permit order:read: %v", body)
	}

	// Flip the binding to deny with the M6 items shape.
	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/roles/"+managerRoleID+"/resources", rootToken, map[string]any{
		"items": []any{
			map[string]any{"resource_id": resourceIDs["crm.dashboard"], "effect": "allow"},
			map[string]any{"resource_id": resourceIDs["order:read"], "effect": "deny"},
		},
	})
	expectCode(status, 200, body)

	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:read",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("role deny must block order:read: %v", body)
	}

	// Menus are enforcer-driven: the denied code disappears, the allowed
	// dashboard stays.
	status, body = doJSON("GET", "/api/v1/me/menus?app=crm", aliceToken, nil)
	expectCode(status, 200, body)
	menuCodes := map[string]bool{}
	var walkMenus func(nodes []any)
	walkMenus = func(nodes []any) {
		for _, n := range nodes {
			node := asMap(n)
			menuCodes[node["code"].(string)] = true
			if children, ok := node["children"].([]any); ok {
				walkMenus(children)
			}
		}
	}
	walkMenus(asList(body))
	if menuCodes["order:read"] {
		t.Fatalf("denied code must be hidden from authz (sanity): %v", body)
	}
	if !menuCodes["crm.dashboard"] {
		t.Fatalf("allowed menu must be visible: %v", body)
	}

	// Restore the allow binding for the rest of the flow.
	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/roles/"+managerRoleID+"/resources", rootToken, map[string]any{
		"resource_ids": []string{resourceIDs["crm.dashboard"], resourceIDs["order:read"]},
	})
	expectCode(status, 200, body)

	// ---------- 2. deny grant beats the role allow ----------
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/accounts/"+aliceAccountID+"/grants", rootToken, map[string]any{
		"resource_id": resourceIDs["order:read"], "effect": "deny",
	})
	expectCode(status, 201, body)
	grant := asMap(body)
	if grant["effect"] != "deny" {
		t.Fatalf("grant effect = %v", grant)
	}
	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:read",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("deny grant must beat the role allow: %v", body)
	}
	// Remove the deny grant: role allow applies again.
	status, body = doJSON("GET", "/api/v1/admin/apps/crm/accounts/"+aliceAccountID+"/grants", rootToken, nil)
	expectCode(status, 200, body)
	grantID := str(asMap(asList(body)[0]), "id")
	status, body = doJSON("DELETE", "/api/v1/admin/apps/crm/accounts/"+aliceAccountID+"/grants/"+grantID, rootToken, nil)
	expectCode(status, 204, body)
	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:read",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != true {
		t.Fatalf("role allow must apply after removing the deny grant: %v", body)
	}

	// ---------- 3. custom rules: CRUD + validation + matcher ----------
	// Invalid expressions are rejected at create/update time (400).
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules", rootToken, map[string]any{
		"name": "bad", "expr": "this is === not valid", "effect": "allow",
	})
	expectCode(status, 400, body)
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules", rootToken, map[string]any{
		"name": "bad", "expr": "secret_env_var == 1", "effect": "allow",
	})
	expectCode(status, 400, body)

	// A time-gated rule that grants order:create only to matching requests.
	// now is deterministic enough: the year is fixed, the hour comparison is
	// evaluated against the wall clock, so the expectation mirrors it.
	hourGate := time.Now().Hour() < 23
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules", rootToken, map[string]any{
		"name": "create-window", "expr": `obj == "order:create" && now.Year() > 2000 && now.Hour() < 23`, "effect": "allow",
	})
	expectCode(status, 201, body)
	rule := asMap(body)
	ruleID := str(rule, "id")
	if num(rule, "priority") != 40 {
		t.Fatalf("default priority = %v", rule)
	}
	if rule["effect"] != "allow" || rule["status"] != "active" {
		t.Fatalf("rule = %v", rule)
	}

	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:create",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != hourGate {
		t.Fatalf("custom rule grant = %v, want %v (body: %v)", asMap(body)["allowed"], hourGate, body)
	}
	// Non-matching objects stay denied (no role grants order:create... the
	// manager role does not carry it).
	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:export",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("non-matching object must stay denied: %v", body)
	}

	// Duplicate names conflict.
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules", rootToken, map[string]any{
		"name": "create-window", "expr": `obj == "x"`, "effect": "deny",
	})
	expectCode(status, 409, body)

	// List + update (disable) + delete.
	status, body = doJSON("GET", "/api/v1/admin/apps/crm/custom-rules", rootToken, nil)
	expectCode(status, 200, body)
	if len(asList(body)) != 1 {
		t.Fatalf("custom rule list = %v", body)
	}
	status, body = doJSON("PATCH", "/api/v1/admin/apps/crm/custom-rules/"+ruleID, rootToken, map[string]any{
		"status": "disabled",
	})
	expectCode(status, 200, body)
	if asMap(body)["status"] != "disabled" {
		t.Fatalf("disabled rule = %v", body)
	}
	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:create",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("disabled custom rule must not grant: %v", body)
	}

	// Re-enable with a deny effect at a high priority: deny must win over the
	// role allow on order:read.
	status, body = doJSON("PATCH", "/api/v1/admin/apps/crm/custom-rules/"+ruleID, rootToken, map[string]any{
		"status": "active", "expr": `obj == "order:read"`, "effect": "deny", "priority": 40,
	})
	expectCode(status, 200, body)
	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:read",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("custom deny must beat role allow: %v", body)
	}

	status, body = doJSON("DELETE", "/api/v1/admin/apps/crm/custom-rules/"+ruleID, rootToken, nil)
	expectCode(status, 204, body)
	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:read",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != true {
		t.Fatalf("role allow must apply after deleting the custom deny: %v", body)
	}

	// ---------- 4. custom rule test endpoint (dry-run) ----------
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules/test", rootToken, map[string]any{
		"expr": `obj == "test:obj" && dom == "crm"`,
	})
	expectCode(status, 200, body)
	testResp := asMap(body)
	if testResp["allowed"] != true || testResp["error"] != nil {
		t.Fatalf("dry-run = %v", testResp)
	}
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules/test", rootToken, map[string]any{
		"expr": `act == "POST"`, "obj": "order:read", "act": "GET",
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("dry-run act mismatch = %v", body)
	}
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules/test", rootToken, map[string]any{
		"expr": "roles[99] == \"x\"",
	})
	expectCode(status, 200, body)
	testResp = asMap(body)
	if testResp["allowed"] != false || testResp["error"] == "" {
		t.Fatalf("failing dry-run must report error: %v", testResp)
	}
	// Invalid expressions are rejected outright.
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules/test", rootToken, map[string]any{
		"expr": "definitely_not_in_env == 1",
	})
	expectCode(status, 400, body)

	// ---------- 5. org_admin manages custom rules of its own org ----------
	status, body = doJSON("POST", "/api/v1/auth/register", "", map[string]any{
		"username": "carol", "email": "carol@test.dev", "password": "CarolPassw0rd",
	})
	expectCode(status, 201, body)
	carolToken := str(asMap(body), "access_token")
	orgAdminRole, err := tc.RoleRepo().FindGlobalByCode(ctx, "org_admin")
	if err != nil {
		t.Fatalf("org_admin role: %v", err)
	}
	status, body = doJSON("POST", "/api/v1/admin/apps/admin/accounts", rootToken, map[string]any{
		"email": "carol@test.dev", "role_ids": []string{orgAdminRole.Id}, "password": "CarolAdminPass1",
	})
	expectCode(status, 201, body)
	status, body = doJSON("POST", "/api/v1/admin/orgs/acme/members", rootToken, map[string]any{
		"email": "carol@test.dev", "org_role": "admin",
	})
	expectCode(status, 201, body)

	// org_admin holds the app-scoped customrule codes: read + manage + test.
	status, body = doJSON("GET", "/api/v1/admin/apps/crm/custom-rules", carolToken, nil)
	expectCode(status, 200, body)
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules", carolToken, map[string]any{
		"name": "org-managed", "expr": `obj == "order:export"`, "effect": "allow", "priority": 42,
	})
	expectCode(status, 201, body)
	orgRuleID := str(asMap(body), "id")
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/custom-rules/test", carolToken, map[string]any{
		"expr": `'org_admin' in roles`,
	})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != true {
		t.Fatalf("org_admin dry-run must see its own roles: %v", body)
	}
	status, body = doJSON("PATCH", "/api/v1/admin/apps/crm/custom-rules/"+orgRuleID, carolToken, map[string]any{
		"priority": 44,
	})
	expectCode(status, 200, body)
	status, body = doJSON("DELETE", "/api/v1/admin/apps/crm/custom-rules/"+orgRuleID, carolToken, nil)
	expectCode(status, 204, body)
	// The customrule codes are app-scoped but platform audit stays platform-only.
	status, body = doJSON("GET", "/api/v1/admin/audit-logs/summary", carolToken, nil)
	expectCode(status, 403, body)

	// ---------- 6. audit summary shape ----------
	status, body = doJSON("GET", "/api/v1/admin/audit-logs/summary?days=7", rootToken, nil)
	expectCode(status, 200, body)
	summary := asMap(body)
	if num(summary, "days") != 7 {
		t.Fatalf("summary days = %v", summary)
	}
	byAction := map[string]float64{}
	for _, entry := range asList(summary["by_action"]) {
		item := asMap(entry)
		byAction[item["action"].(string)] = num(item, "count")
	}
	if byAction["login_success"] < 1 || byAction["customrule_created"] < 1 {
		t.Fatalf("summary by_action = %v", summary["by_action"])
	}
	var dailyTotal float64
	for _, entry := range asList(summary["daily"]) {
		item := asMap(entry)
		if len(item["date"].(string)) != 10 {
			t.Fatalf("daily date = %v", item)
		}
		dailyTotal += num(item, "count")
	}
	if dailyTotal < 1 {
		t.Fatalf("daily buckets missing: %v", summary["daily"])
	}
	foundActor := false
	for _, entry := range asList(summary["top_actors"]) {
		item := asMap(entry)
		if item["actor_type"] != "" && item["actor_id"] != "" {
			foundActor = true
		}
	}
	if !foundActor {
		t.Fatalf("top_actors missing: %v", summary["top_actors"])
	}

	// days is clamped to 1..90.
	status, body = doJSON("GET", "/api/v1/admin/audit-logs/summary?days=500", rootToken, nil)
	expectCode(status, 200, body)
	if num(asMap(body), "days") != 90 {
		t.Fatalf("days clamp = %v", body)
	}
}
