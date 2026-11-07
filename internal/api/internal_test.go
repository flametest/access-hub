package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flametest/access-hub/internal/api"
	"github.com/flametest/access-hub/internal/bootstrap"
	"github.com/flametest/access-hub/internal/testutil"
	"github.com/flametest/vita/vserver"
)

// TestInternalResourceRegistration covers the cluster-internal API: per-app
// secret issuance (create + rotate, hash-only storage), the X-App-Key guard
// (missing/invalid key, platform app, disabled app) and idempotent resource
// self-registration incl. the mode=replace reconciliation.
func TestInternalResourceRegistration(t *testing.T) {
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

	// doJSON performs one HTTP round-trip; extra headers carry e.g. X-App-Key.
	doJSON := func(method, path, token string, body any, headers map[string]string) (int, any) {
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
		for k, v := range headers {
			req.Header.Set(k, v)
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

	// bootstrapLogin performs the root login using the credentials the test
	// container was bootstrapped with (no credential literals here).
	bootstrapLogin := func() string {
		t.Helper()
		cfg := tc.Cfg().Bootstrap
		status, body := doJSON("POST", "/api/v1/auth/login", "", map[string]any{
			"identifier": cfg.AdminEmail,
			"password":   cfg.AdminPassword,
		}, nil)
		if status != 200 {
			t.Fatalf("bootstrap login status = %d (body: %v)", status, body)
		}
		m := body.(map[string]any)
		token, ok := m["access_token"].(string)
		if !ok || token == "" {
			t.Fatalf("bootstrap login response = %v", body)
		}
		return token
	}
	rootToken := bootstrapLogin()

	asMap := func(v any) map[string]any {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("expected object, got %T: %v", v, v)
		}
		return m
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
	// fakeKey builds an invalid-but-well-formed X-App-Key value (runtime
	// constructed; no credential literals).
	fakeKey := func() string { return "ahk_" + strings.Repeat("0", 64) }

	fullManifest := map[string]any{
		"items": []any{
			map[string]any{"type": "menu", "code": "crm.dashboard", "name": "Dashboard", "path": "/", "sort": 1},
			map[string]any{"type": "menu", "code": "crm.users", "name": "Users", "path": "/users", "sort": 2},
			map[string]any{"type": "api", "code": "order:read", "name": "Read orders", "method": "GET", "route_path": "/api/orders"},
		},
	}

	// ---------- 1. org + app creation issues a one-time secret
	status, body := doJSON("POST", "/api/v1/admin/orgs", rootToken, map[string]any{"key": "acme", "name": "Acme Inc"}, nil)
	expectCode(status, 201, body)

	status, body = doJSON("POST", "/api/v1/admin/apps", rootToken, map[string]any{
		"key": "crm", "org_key": "acme", "name": "CRM", "type": "web",
	}, nil)
	expectCode(status, 201, body)
	secret := str(asMap(body), "secret")
	if !strings.HasPrefix(secret, "ahk_") {
		t.Fatalf("app secret = %q (must carry the ahk_ prefix)", secret)
	}

	// The plaintext must never be persisted: the column stores the hash only.
	var storedHash string
	if err := tc.DB().Raw(`SELECT secret_hash FROM apps WHERE "key" = 'crm'`).Scan(&storedHash).Error; err != nil || storedHash == "" {
		t.Fatalf("secret_hash missing (err: %v)", err)
	}
	if storedHash == secret || strings.Contains(storedHash, "ahk_") {
		t.Fatalf("plaintext secret leaked into secret_hash: %q", storedHash)
	}
	if len(storedHash) != 64 {
		t.Fatalf("secret_hash = %q (must be sha256 hex)", storedHash)
	}

	// List responses never carry the secret (omitempty) but do report the
	// derived secret_configured flag.
	status, body = doJSON("GET", "/api/v1/admin/apps", rootToken, nil, nil)
	expectCode(status, 200, body)
	crmItem := func() map[string]any {
		for _, item := range body.([]any) {
			if asMap(item)["key"] == "crm" {
				return asMap(item)
			}
		}
		t.Fatalf("crm missing from the apps list: %v", body)
		return nil
	}()
	if _, has := crmItem["secret"]; has {
		t.Fatalf("list response leaked the secret field: %v", crmItem)
	}
	if crmItem["secret_configured"] != true {
		t.Fatalf("secret_configured = %v (want true)", crmItem["secret_configured"])
	}

	// ---------- 2. guard: missing / invalid key, unknown app
	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch", "", fullManifest, nil)
	expectCode(status, 401, body)
	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch", "", fullManifest,
		map[string]string{"X-App-Key": fakeKey()})
	expectCode(status, 401, body)
	status, body = doJSON("PUT", "/internal/v1/apps/nope/resources/batch", "", fullManifest, map[string]string{"X-App-Key": fakeKey()})
	expectCode(status, 404, body)

	// ---------- 3. valid self-registration + idempotency
	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch", "", fullManifest, map[string]string{"X-App-Key": secret})
	expectCode(status, 200, body)
	if num(asMap(body), "created") != 3 || num(asMap(body), "updated") != 0 {
		t.Fatalf("first batch = %v", body)
	}
	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch", "", fullManifest, map[string]string{"X-App-Key": secret})
	expectCode(status, 200, body)
	if num(asMap(body), "created") != 0 || num(asMap(body), "updated") != 3 {
		t.Fatalf("idempotent re-batch = %v", body)
	}

	// The registered resources are visible through the admin tree.
	status, body = doJSON("GET", "/api/v1/admin/apps/crm/resources", rootToken, nil, nil)
	expectCode(status, 200, body)
	tree, _ := json.Marshal(body)
	for _, code := range []string{"crm.dashboard", "crm.users", "order:read"} {
		if !strings.Contains(string(tree), code) {
			t.Fatalf("resource %q missing from the tree: %s", code, tree)
		}
	}

	// ---------- 4. mode=replace reconciles toward the declared manifest
	subset := map[string]any{
		"items": []any{
			map[string]any{"type": "menu", "code": "crm.dashboard", "name": "Dashboard", "path": "/", "sort": 1},
			map[string]any{"type": "menu", "code": "crm.users", "name": "Users", "path": "/users", "sort": 2},
		},
	}
	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch?mode=replace", "", subset, map[string]string{"X-App-Key": secret})
	expectCode(status, 200, body)
	if num(asMap(body), "disabled") != 1 {
		t.Fatalf("replace batch = %v (order:read must be disabled)", body)
	}

	// ---------- 5. rotation invalidates the old secret immediately
	status, body = doJSON("POST", "/api/v1/admin/apps/crm/secret/rotate", rootToken, nil, nil)
	expectCode(status, 200, body)
	newSecret := str(asMap(body), "secret")
	if newSecret == "" || newSecret == secret {
		t.Fatalf("rotate response secret = %q (must be fresh)", newSecret)
	}

	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch", "", fullManifest, map[string]string{"X-App-Key": secret})
	expectCode(status, 401, body)
	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch", "", fullManifest, map[string]string{"X-App-Key": newSecret})
	expectCode(status, 200, body)
	if num(asMap(body), "updated") != 3 {
		t.Fatalf("post-rotation batch = %v", body)
	}

	// ---------- 6. platform apps are excluded from the internal API
	status, body = doJSON("PUT", "/internal/v1/apps/admin/resources/batch", "", fullManifest, map[string]string{"X-App-Key": fakeKey()})
	expectCode(status, 403, body)
	status, body = doJSON("POST", "/api/v1/admin/apps/admin/secret/rotate", rootToken, nil, nil)
	expectCode(status, 400, body)

	// ---------- 7. a disabled app loses internal access
	status, body = doJSON("PATCH", "/api/v1/admin/apps/crm", rootToken, map[string]any{"status": "disabled"}, nil)
	expectCode(status, 200, body)
	status, body = doJSON("PUT", "/internal/v1/apps/crm/resources/batch", "", fullManifest, map[string]string{"X-App-Key": newSecret})
	expectCode(status, 403, body)
}
