package api_test

import (
	"context"
	"testing"
)

// TestBatch4ReadCodesLeastPrivilege pins the :read code split: plain users
// are denied even read access, org_admins keep read+manage on app-scoped
// resources, and read-only semantics no longer ride on manage codes.
func TestBatch4ReadCodesLeastPrivilege(t *testing.T) {
	env := newOAuthEnv(t)
	root := env.rootToken

	env.doJSON("POST", "/api/v1/admin/orgs", root, map[string]any{"key": "b4org", "name": "B4"})
	env.doJSON("POST", "/api/v1/admin/apps", root, map[string]any{
		"key": "b4app", "org_key": "b4org", "name": "B4 App", "type": "web"})
	env.doJSON("PUT", "/api/v1/admin/apps/b4app/resources:batch", root, map[string]any{"items": []any{
		map[string]any{"code": "b4:r", "name": "R", "type": "api", "method": "GET", "route_path": "/r"},
	}})

	// A plain registered identity has no admin app account at all: 403.
	status, body := env.doJSON("POST", "/api/v1/auth/register", "", map[string]any{
		"username": "b4plain", "email": "b4plain@test.dev", "password": "B4PlainPass1"})
	if status != 201 {
		t.Fatalf("register: %d %v", status, body)
	}
	plain := env.str(env.asMap(body), "access_token")
	for _, path := range []string{
		"/api/v1/admin/apps/b4app/resources",
		"/api/v1/admin/apps/b4app/roles",
		"/api/v1/admin/apps/b4app/invitations",
	} {
		status, body = env.doJSON("GET", path, plain, nil)
		if status != 403 {
			t.Fatalf("plain user GET %s = %d, want 403", path, status)
		}
	}

	// org_admin keeps read access on every app-scoped read endpoint.
	status, body = env.doJSON("POST", "/api/v1/auth/register", "", map[string]any{
		"username": "b4orgadmin", "email": "b4orgadmin@test.dev", "password": "B4OrgAdmin1"})
	orgAdminIdentity := env.str(env.asMap(body), "access_token")
	orgAdminRole, err := env.tc.RoleRepo().FindGlobalByCode(context.Background(), "org_admin")
	if err != nil {
		env.t.Fatalf("find org_admin role: %v", err)
	}
	status, body = env.doJSON("POST", "/api/v1/admin/apps/admin/accounts", root, map[string]any{
		"email": "b4orgadmin@test.dev", "role_ids": []string{orgAdminRole.Id}, "password": "B4AdminPass1"})
	if status != 201 && status != 200 {
		t.Fatalf("org admin account: %d %v", status, body)
	}
	env.doJSON("POST", "/api/v1/admin/orgs/b4org/members", root, map[string]any{
		"email": "b4orgadmin@test.dev", "org_role": "admin"})
	for _, path := range []string{
		"/api/v1/admin/apps/b4app/resources",
		"/api/v1/admin/apps/b4app/roles",
		"/api/v1/admin/apps/b4app/invitations",
	} {
		status, body = env.doJSON("GET", path, orgAdminIdentity, nil)
		if status != 200 {
			t.Fatalf("org_admin GET %s = %d %v, want 200", path, status, body)
		}
	}
}
