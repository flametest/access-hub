package api_test

import (
	"fmt"
	"testing"
)

// TestBatch3RoleResourcesReadAndAccountPaging covers the two console-contract
// fixes: GET roles/{id}/resources returns the CURRENT bindings (so the bind
// drawer preloads instead of blind-replacing) and the accounts list is truly
// paginated (total/page/page_size from the backend, not fabricated).
func TestBatch3RoleResourcesReadAndAccountPaging(t *testing.T) {
	env := newOAuthEnv(t)
	root := env.rootToken

	status, body := env.doJSON("POST", "/api/v1/admin/orgs", root, map[string]any{"key": "b3org", "name": "B3"})
	if status != 201 && status != 200 {
		t.Fatalf("org: %d %v", status, body)
	}
	status, body = env.doJSON("POST", "/api/v1/admin/apps", root, map[string]any{
		"key": "b3app", "org_key": "b3org", "name": "B3 App", "type": "web"})
	if status != 201 && status != 200 {
		t.Fatalf("app: %d %v", status, body)
	}
	status, body = env.doJSON("PUT", "/api/v1/admin/apps/b3app/resources:batch", root, map[string]any{"items": []any{
		map[string]any{"code": "r:one", "name": "One", "type": "api", "method": "GET", "route_path": "/one"},
		map[string]any{"code": "r:two", "name": "Two", "type": "api", "method": "GET", "route_path": "/two"},
	}})
	if status != 200 {
		t.Fatalf("resources: %d %v", status, body)
	}

	// Role with mixed-effect bindings.
	status, body = env.doJSON("POST", "/api/v1/admin/apps/b3app/roles", root, map[string]any{"code": "ops", "name": "Ops"})
	if status != 201 && status != 200 {
		t.Fatalf("role: %d %v", status, body)
	}
	roleID := env.str(env.asMap(body), "id")
	status, body = env.doJSON("GET", "/api/v1/admin/apps/b3app/resources", root, nil)
	ids := map[string]string{}
	var walkFn func(map[string]any)
	walkFn = func(node map[string]any) {
		if code, ok := node["code"].(string); ok {
			ids[code], _ = node["id"].(string)
		}
		if children, ok := node["children"].([]any); ok {
			for _, c := range children {
				if m, ok := c.(map[string]any); ok {
					walkFn(m)
				}
			}
		}
	}
	for _, n := range env.asList(body) {
		walkFn(n.(map[string]any))
	}

	status, body = env.doJSON("PUT", fmt.Sprintf("/api/v1/admin/apps/b3app/roles/%s/resources", roleID), root,
		map[string]any{"items": []any{
			map[string]any{"resource_id": ids["r:one"], "effect": "allow"},
			map[string]any{"resource_id": ids["r:two"], "effect": "deny"},
		}})
	if status != 200 {
		t.Fatalf("bind: %d %v", status, body)
	}

	// The read endpoint returns the bindings WITH effects.
	status, body = env.doJSON("GET", fmt.Sprintf("/api/v1/admin/apps/b3app/roles/%s/resources", roleID), root, nil)
	if status != 200 {
		t.Fatalf("read bindings: %d %v", status, body)
	}
	got := map[string]string{}
	for _, raw := range env.asList(body) {
		item := raw.(map[string]any)
		got[item["code"].(string)] = item["effect"].(string)
	}
	if got["r:one"] != "allow" || got["r:two"] != "deny" {
		t.Fatalf("bindings = %v, want r:one=allow r:two=deny", got)
	}

	// Account pagination: three accounts, page_size=2.
	for i := 1; i <= 3; i++ {
		status, body = env.doJSON("POST", "/api/v1/admin/apps/b3app/accounts", root, map[string]any{
			"email":    fmt.Sprintf("b3user%d@test.dev", i),
			"password": fmt.Sprintf("B3Passw0rd%d", i),
		})
		if status != 201 && status != 200 {
			t.Fatalf("provision %d: %d %v", i, status, body)
		}
	}
	status, body = env.doJSON("GET", "/api/v1/admin/apps/b3app/accounts?page=1&page_size=2", root, nil)
	if status != 200 {
		t.Fatalf("accounts page1: %d", status)
	}
	page := env.asMap(body)
	if n := len(env.asList(page["items"])); n != 2 {
		t.Fatalf("page1 items = %d, want 2", n)
	}
	if total := page["total"]; total.(float64) != 3 {
		t.Fatalf("total = %v, want 3", total)
	}
	if page["page"].(float64) != 1 || page["page_size"].(float64) != 2 {
		t.Fatalf("paging echo = %v/%v", page["page"], page["page_size"])
	}
	status, body = env.doJSON("GET", "/api/v1/admin/apps/b3app/accounts?page=2&page_size=2", root, nil)
	if status != 200 || len(env.asList(env.asMap(body)["items"])) != 1 {
		t.Fatalf("page2: %d %v", status, body)
	}
}
