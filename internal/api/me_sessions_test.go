package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flametest/access-hub/internal/api"
	"github.com/flametest/access-hub/internal/bootstrap"
	"github.com/flametest/access-hub/internal/testutil"
	"github.com/flametest/vita/vserver"
)

// TestMeSessions covers the /me/sessions surface: listing includes every
// session with the active flag and the current marker, a single revoke flips
// one entry inactive, and revoke-others spares only the presenting session.
func TestMeSessions(t *testing.T) {
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

	const testUA = "TestAgent/1.0"
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
		req.Header.Set("User-Agent", testUA)
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
	str := func(m map[string]any, key string) string {
		v, ok := m[key].(string)
		if !ok {
			t.Fatalf("field %q missing or not a string: %v", key, m)
		}
		return v
	}

	// loginOrRegister issues a fresh identity session and returns (token, sessionID).
	// Register answers 201, the login endpoints 200.
	loginOrRegister := func(path, username, password string) (string, string) {
		t.Helper()
		status, body := doJSON("POST", path, "", map[string]any{
			"identifier": username, "username": username,
			"email": username + "@test.dev", "password": password,
		})
		if status != 200 && status != 201 {
			t.Fatalf("status = %d, want 200 or 201 (body: %v)", status, body)
		}
		m := asMap(body)
		session := asMap(m["session"])
		return str(m, "access_token"), str(session, "id")
	}

	// ---------- register + second login = two sessions
	tokenA, sessionA := loginOrRegister("/api/v1/auth/register", "Sessa", "SessaPassw0rd")
	_, sessionB := loginOrRegister("/api/v1/auth/login", "sessa", "SessaPassw0rd")
	if sessionA == sessionB {
		t.Fatal("each login must create a distinct session")
	}

	// ---------- listing shows both sessions, active, with the caller's marker
	status, body := doJSON("GET", "/api/v1/me/sessions", tokenA, nil)
	expectCode(status, 200, body)
	items := asList(body)
	if len(items) != 2 {
		t.Fatalf("sessions = %d entries, want 2: %v", len(items), body)
	}
	deviceSeen := false
	for _, raw := range items {
		item := asMap(raw)
		if item["active"] != true {
			t.Fatalf("fresh sessions must be active, got %v", item)
		}
		if str(item, "id") == sessionA && item["current"] != true {
			t.Fatalf("caller session %s must be marked current: %v", sessionA, item)
		}
		if str(item, "id") == sessionB && item["current"] != false {
			t.Fatalf("other session %s must not be current: %v", sessionB, item)
		}
		if str(item, "device") == testUA {
			deviceSeen = true
		}
	}
	if !deviceSeen {
		t.Fatalf("no session carries the request user-agent %q: %v", testUA, body)
	}

	// ---------- single revoke flips the target entry inactive
	status, _ = doJSON("DELETE", "/api/v1/me/sessions/"+sessionB, tokenA, nil)
	expectCode(status, 204, nil)
	// Revoking a session owned by a different identity is 404.
	_, sessionX := loginOrRegister("/api/v1/auth/register", "Sessx", "SessxPassw0rd")
	status, _ = doJSON("DELETE", "/api/v1/me/sessions/"+sessionX, tokenA, nil)
	expectCode(status, 404, nil)

	status, body = doJSON("GET", "/api/v1/me/sessions", tokenA, nil)
	expectCode(status, 200, body)
	for _, raw := range asList(body) {
		item := asMap(raw)
		want := item["id"] != sessionB
		if item["active"] != want {
			t.Fatalf("session %s active = %v, want %v", item["id"], item["active"], want)
		}
	}

	// ---------- revoke-others keeps only the presenting session
	tokenC, sessionC := loginOrRegister("/api/v1/auth/register", "Sessb", "SessbPassw0rd")
	_, sessionD := loginOrRegister("/api/v1/auth/login", "sessb", "SessbPassw0rd")

	status, _ = doJSON("DELETE", "/api/v1/me/sessions", tokenC, nil)
	expectCode(status, 204, nil)

	status, body = doJSON("GET", "/api/v1/me/sessions", tokenC, nil)
	expectCode(status, 200, body)
	for _, raw := range asList(body) {
		item := asMap(raw)
		want := item["id"] == sessionC
		if item["active"] != want {
			t.Fatalf("after revoke-others session %s active = %v, want %v", item["id"], item["active"], want)
		}
	}
	_ = sessionD
}
