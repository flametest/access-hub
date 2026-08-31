package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/flametest/access-hub/internal/api"
	"github.com/flametest/access-hub/internal/bootstrap"
	"github.com/flametest/access-hub/internal/testutil"
	"github.com/flametest/vita/vserver"
)

// TestFullChain is the end-to-end integration test: bootstrap + admin
// resource sync -> register -> login -> org/app -> batch resources -> role ->
// provision account -> roles -> authz check (allow) -> revoke (deny) ->
// menus reflect grants -> workspaces + app token exchange -> admin guard
// (org_admin gets app-scoped codes but not platform ones) -> invitations ->
// refresh rotation -> logout -> jwks -> audit trail.
func TestFullChain(t *testing.T) {
	tc := testutil.New(t)
	ctx := context.Background()

	if err := bootstrap.Run(ctx, tc); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := api.SyncAdminResources(ctx, tc); err != nil {
		t.Fatalf("sync admin resources: %v", err)
	}

	srv, err := vserver.NewEchoServer(ctx, &vserver.EchoServerConfig{Name: "access-hub-it", Addr: ":0"})
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	srv = api.NewApp(tc).Router(srv)
	ts := httptest.NewServer(srv.(*vserver.EchoServer).GetEchoServer())
	t.Cleanup(ts.Close)

	// doJSON performs one HTTP round-trip and decodes the JSON body as `any`
	// (endpoints return either bare arrays or objects).
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

	// ---------- 1. bootstrap admin login (must_change_password still logs in)
	status, body := doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "root@access-hub.test",
		"password":   "RootPassw0rd",
	})
	expectCode(status, 200, body)
	rootToken := str(asMap(body), "access_token")
	rootSession := asMap(asMap(body)["session"])
	if rootSession["id"] == "" {
		t.Fatal("login must return session info")
	}
	if asMap(body)["token_type"] != "Bearer" {
		t.Fatal("token_type must be Bearer")
	}

	// ---------- 2. register alice
	status, body = doJSON("POST", "/api/v1/auth/register", "", map[string]any{
		"username": "Alice",
		"email":    "Alice@Test.Dev",
		"password": "AlicePassw0rd",
	})
	expectCode(status, 201, body)
	aliceToken := str(asMap(body), "access_token")
	aliceRefresh := str(asMap(body), "refresh_token")
	me := asMap(asMap(body)["me"])
	if me["username"] != "alice" {
		t.Fatalf("register response me = %v (username must be lower-normalized)", me)
	}

	// duplicate username conflicts (1409).
	status, body = doJSON("POST", "/api/v1/auth/register", "", map[string]any{
		"username": "alice", "email": "other@test.dev", "password": "AlicePassw0rd",
	})
	expectCode(status, 409, body)

	// ---------- 3. GET /me
	status, body = doJSON("GET", "/api/v1/me", aliceToken, nil)
	expectCode(status, 200, body)
	meBody := asMap(body)
	if meBody["must_change_password"] != false || meBody["email"] != "alice@test.dev" {
		t.Fatalf("me = %v", meBody)
	}

	// unauthenticated /me is 401.
	status, _ = doJSON("GET", "/api/v1/me", "", nil)
	expectCode(status, 401, nil)

	// ---------- 4. org + app (root = super_admin)
	status, body = doJSON("POST", "/api/v1/admin/orgs", rootToken, map[string]any{"key": "acme", "name": "Acme Inc"})
	expectCode(status, 201, body)
	org := asMap(body)
	if org["key"] != "acme" {
		t.Fatalf("org = %v", org)
	}

	status, body = doJSON("GET", "/api/v1/admin/orgs", rootToken, nil)
	expectCode(status, 200, body)
	if len(asList(body)) != 1 {
		t.Fatalf("org list = %v", body)
	}

	status, body = doJSON("POST", "/api/v1/admin/apps", rootToken, map[string]any{
		"key": "crm", "org_key": "acme", "name": "CRM", "type": "web",
	})
	expectCode(status, 201, body)
	if asMap(body)["org_key"] != "acme" {
		t.Fatalf("app org_key = %v", body)
	}

	// ---------- 5. batch import resources
	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/resources:batch", rootToken, map[string]any{
		"items": []any{
			map[string]any{"type": "menu", "code": "crm.dashboard", "name": "Dashboard", "path": "/", "sort": 1},
			map[string]any{"type": "menu", "code": "crm.users", "name": "Users", "path": "/users", "sort": 2},
			map[string]any{"type": "api", "code": "order:read", "name": "Read orders", "method": "GET", "route_path": "/api/orders"},
			map[string]any{"type": "api", "code": "order:create", "name": "Create orders", "method": "POST", "route_path": "/api/orders"},
			map[string]any{"type": "button", "code": "order:export", "name": "Export orders"},
		},
	})
	expectCode(status, 200, body)
	batchResult := asMap(body)
	if num(batchResult, "created") != 5 || num(batchResult, "updated") != 0 || num(batchResult, "disabled") != 0 {
		t.Fatalf("batch result = %v", batchResult)
	}

	// ---------- 6. role + resource binding
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
	for _, code := range []string{"crm.dashboard", "crm.users", "order:read", "order:create"} {
		if resourceIDs[code] == "" {
			t.Fatalf("resource %s missing from tree: %v", code, body)
		}
	}

	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/roles/"+managerRoleID+"/resources", rootToken, map[string]any{
		"resource_ids": []string{resourceIDs["crm.dashboard"], resourceIDs["order:read"], resourceIDs["order:create"]},
	})
	expectCode(status, 200, body)

	// ---------- 7. provision alice's CRM account (with password)
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/accounts", rootToken, map[string]any{
		"email":        "alice@test.dev",
		"display_name": "Alice in CRM",
		"role_ids":     []string{managerRoleID},
		"password":     "AliceCrmPass1",
	})
	expectCode(status, 201, body)
	createAccount := asMap(body)
	aliceAccountID := str(createAccount, "account_id")
	if createAccount["activation_sent"] != false {
		t.Fatalf("password-provisioned account must not need activation: %v", createAccount)
	}

	// ---------- 8. workspaces + app token exchange
	status, body = doJSON("GET", "/api/v1/me/workspaces", aliceToken, nil)
	expectCode(status, 200, body)
	wsItems := asList(body)
	if len(wsItems) != 1 {
		t.Fatalf("alice workspaces = %v", body)
	}
	ws := asMap(wsItems[0])
	if ws["app_key"] != "crm" || ws["account_id"] != aliceAccountID {
		t.Fatalf("workspace item = %v", ws)
	}
	if ws["org_key"] != "acme" || ws["org_name"] != "Acme Inc" {
		t.Fatalf("workspace org fields = %v", ws)
	}
	rolesSummary := asList(ws["roles"])
	if len(rolesSummary) != 1 || asMap(rolesSummary[0])["code"] != "manager" {
		t.Fatalf("workspace roles = %v", rolesSummary)
	}

	status, body = doJSON("POST", "/api/v1/me/workspaces/"+aliceAccountID+"/token", aliceToken, nil)
	expectCode(status, 200, body)
	workspaceToken := asMap(body)
	crmToken := str(workspaceToken, "access_token")
	if workspaceToken["app_key"] != "crm" || workspaceToken["account_id"] != aliceAccountID {
		t.Fatalf("workspace token = %v", workspaceToken)
	}

	// ---------- 9. authz check: allow -> revoke -> deny -> re-grant -> allow
	status, body = doJSON("POST", "/api/v1/authz/check", aliceToken, map[string]any{
		"app": "crm", "account_id": aliceAccountID, "obj": "order:read",
	})
	expectCode(status, 200, body)
	check := asMap(body)
	if check["allowed"] != true {
		t.Fatalf("authz check must allow order:read: %v", check)
	}
	if _, ok := check["version"]; !ok {
		t.Fatalf("authz response missing version: %v", check)
	}

	// Account token checks its own audience; ungranted codes are denied.
	status, body = doJSON("POST", "/api/v1/authz/check", crmToken, map[string]any{"obj": "order:read"})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != true {
		t.Fatalf("account token authz must allow order:read: %v", body)
	}
	status, body = doJSON("POST", "/api/v1/authz/check", crmToken, map[string]any{"obj": "crm.users"})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("crm.users must be denied: %v", body)
	}

	// Revoke all roles -> deny.
	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/accounts/"+aliceAccountID+"/roles", rootToken, map[string]any{"role_ids": []string{}})
	expectCode(status, 200, body)
	status, body = doJSON("POST", "/api/v1/authz/check", crmToken, map[string]any{"obj": "order:read"})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != false {
		t.Fatalf("authz must deny after revoke: %v", body)
	}

	// Re-grant -> allow again.
	status, body = doJSON("PUT", "/api/v1/admin/apps/crm/accounts/"+aliceAccountID+"/roles", rootToken, map[string]any{"role_ids": []string{managerRoleID}})
	expectCode(status, 200, body)
	status, body = doJSON("POST", "/api/v1/authz/check", crmToken, map[string]any{"obj": "order:read"})
	expectCode(status, 200, body)
	if asMap(body)["allowed"] != true {
		t.Fatalf("authz must allow after re-grant: %v", body)
	}

	// ---------- 10. menus reflect the grants
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
	if !menuCodes["crm.dashboard"] {
		t.Fatalf("menus must include crm.dashboard: %v", body)
	}
	if menuCodes["crm.users"] {
		t.Fatalf("menus must exclude ungranted crm.users: %v", body)
	}

	// ---------- 11. permissions snapshot
	status, body = doJSON("GET", "/api/v1/me/permissions?app=crm", aliceToken, nil)
	expectCode(status, 200, body)
	permsBody := asMap(body)
	if permsBody["app"] != "crm" {
		t.Fatalf("permissions app = %v", permsBody)
	}
	found := false
	for _, p := range asList(permsBody["permissions"]) {
		if p == "order:read" {
			found = true
		}
	}
	if !found {
		t.Fatalf("permissions must include order:read: %v", permsBody)
	}

	// ---------- 12. org_admin admin guard
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
		"email":    "carol@test.dev",
		"role_ids": []string{orgAdminRole.Id},
		"password": "CarolAdminPass1",
	})
	expectCode(status, 201, body)

	status, body = doJSON("POST", "/api/v1/admin/orgs/acme/members", rootToken, map[string]any{
		"email": "carol@test.dev", "org_role": "admin",
	})
	expectCode(status, 201, body)

	// org_admin: app-scoped codes pass, platform codes are 403.
	status, body = doJSON("GET", "/api/v1/admin/apps?org=acme", carolToken, nil)
	expectCode(status, 200, body)
	status, body = doJSON("GET", "/api/v1/admin/apps/crm/accounts", carolToken, nil)
	expectCode(status, 200, body)
	status, body = doJSON("POST", "/api/v1/admin/orgs", carolToken, map[string]any{"key": "evil", "name": "Evil"})
	expectCode(status, 403, body)
	status, body = doJSON("GET", "/api/v1/admin/users", carolToken, nil)
	expectCode(status, 403, body)

	// ---------- 13. invitation flow (anonymous auto-provision)
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/invitations", rootToken, map[string]any{
		"email": "dave@test.dev", "role_ids": []string{managerRoleID},
	})
	expectCode(status, 201, body)
	if len(tc.Mail.Messages) == 0 {
		t.Fatal("invitation email must be sent")
	}
	var invitationCode string
	reHex := regexp.MustCompile(`\b[0-9a-f]{64}\b`)
	for i := len(tc.Mail.Messages) - 1; i >= 0; i-- {
		if m := reHex.FindString(tc.Mail.Messages[i].Body); m != "" {
			invitationCode = m
			break
		}
	}
	if invitationCode == "" {
		t.Fatalf("invitation code not found in emails: %+v", tc.Mail.Messages)
	}

	status, body = doJSON("POST", "/api/v1/invitations/redeem", "", map[string]any{"code": invitationCode})
	expectCode(status, 200, body)
	preview := asMap(body)
	if preview["auto_provision"] != true || preview["app_key"] != "crm" || preview["email"] != "dave@test.dev" {
		t.Fatalf("redeem preview = %v", preview)
	}

	status, body = doJSON("POST", "/api/v1/invitations/accept", "", map[string]any{
		"code": invitationCode, "new_password": "DavePassw0rd",
	})
	expectCode(status, 200, body)
	accepted := asMap(body)
	if accepted["app_key"] != "crm" || accepted["access_token"] == "" {
		t.Fatalf("accept must auto-login the new identity: %v", accepted)
	}

	// The new identity can direct-login the workspace account.
	status, body = doJSON("POST", "/api/v1/auth/account-login", "", map[string]any{
		"app": "crm", "identifier": "dave@test.dev", "password": "DavePassw0rd",
	})
	expectCode(status, 200, body)
	if asMap(body)["app_key"] != "crm" {
		t.Fatalf("account-login = %v", body)
	}

	// The invitation is one-shot.
	status, body = doJSON("POST", "/api/v1/invitations/redeem", "", map[string]any{"code": invitationCode})
	expectCode(status, 404, body)

	// ---------- 14. refresh rotation + reuse detection over HTTP
	status, body = doJSON("POST", "/api/v1/auth/token/refresh", "", map[string]any{"refresh_token": aliceRefresh})
	expectCode(status, 200, body)
	rotated := str(asMap(body), "refresh_token")
	if rotated == aliceRefresh {
		t.Fatal("refresh must rotate the token")
	}
	status, body = doJSON("POST", "/api/v1/auth/token/refresh", "", map[string]any{"refresh_token": aliceRefresh})
	expectCode(status, 401, body)

	// ---------- 15. logout revokes the presented access token
	status, body = doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "alice", "password": "AlicePassw0rd",
	})
	expectCode(status, 200, body)
	throwaway := str(asMap(body), "access_token")
	status, _ = doJSON("POST", "/api/v1/auth/logout", throwaway, nil)
	expectCode(status, 204, nil)
	status, _ = doJSON("GET", "/api/v1/me", throwaway, nil)
	expectCode(status, 401, nil)

	// ---------- 16. jwks
	status, body = doJSON("GET", "/.well-known/jwks.json", "", nil)
	expectCode(status, 200, body)
	if len(asMap(body)["keys"].([]any)) != 1 {
		t.Fatalf("jwks = %v", body)
	}

	// ---------- 17. audit trail recorded the events
	status, body = doJSON("GET", "/api/v1/admin/audit-logs?action=login_success", rootToken, nil)
	expectCode(status, 200, body)
	if num(asMap(body), "total") < 1 {
		t.Fatalf("audit logs missing login_success entries: %v", body)
	}
	status, body = doJSON("GET", "/api/v1/admin/audit-logs?action=admin_resource_synced", rootToken, nil)
	expectCode(status, 200, body)
	if num(asMap(body), "total") < 1 {
		t.Fatalf("audit logs missing admin_resource_synced: %v", body)
	}
	status, body = doJSON("GET", "/api/v1/admin/audit-logs?org_key=acme", rootToken, nil)
	expectCode(status, 200, body)
}
