package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/api"
	"github.com/flametest/access-hub/internal/bootstrap"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/testutil"
	"github.com/flametest/vita/vgorm"
	"github.com/google/uuid"
	"github.com/flametest/vita/vserver"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
)

// oauthEnv is the shared harness for the M4 integration tests: bootstrapped
// container + HTTP server + JSON/form helpers + a logged-in super admin.
type oauthEnv struct {
	t  *testing.T
	tc *testutil.TestContainer
	ts *httptest.Server

	rootToken        string
	noRedirectClient *http.Client
	// socialCookie is the browser-binding cookie captured by the most recent
	// socialStart call (the social CSRF defense under test).
	socialCookie *http.Cookie
}

func newOAuthEnv(t *testing.T) *oauthEnv {
	t.Helper()
	tc := testutil.New(t)
	ctx := context.Background()
	if err := bootstrap.Run(ctx, tc); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := api.SyncAdminResources(ctx, tc); err != nil {
		t.Fatalf("sync admin resources: %v", err)
	}
	srv, err := vserver.NewEchoServer(ctx, &vserver.EchoServerConfig{Name: "access-hub-m4-it", Addr: ":0"})
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	srv = api.NewApp(tc).Router(srv)
	ts := httptest.NewServer(srv.(*vserver.EchoServer).GetEchoServer())
	t.Cleanup(ts.Close)

	env := &oauthEnv{t: t, tc: tc, ts: ts}
	env.noRedirectClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Bootstrap admin login.
	status, body := env.doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "root@access-hub.test", "password": "RootPassw0rd",
	})
	if status != 200 {
		t.Fatalf("root login: %d %v", status, body)
	}
	env.rootToken = env.str(body, "access_token")
	return env
}

func (e *oauthEnv) doJSON(method, path, token string, body any) (int, any) {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, e.ts.URL+path, reader)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) == 0 {
		return resp.StatusCode, nil
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
	}
	return resp.StatusCode, out
}

// doForm sends an application/x-www-form-encoded request (OAuth2 token
// endpoint shape) and returns status + raw JSON.
func (e *oauthEnv) doForm(path string, values url.Values, basicUser, basicPass, bearer string) (int, map[string]any) {
	e.t.Helper()
	req, err := http.NewRequest("POST", e.ts.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		e.t.Fatalf("new form request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("form %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			e.t.Fatalf("decode form response %q: %v", raw, err)
		}
	}
	return resp.StatusCode, out
}

func (e *oauthEnv) asMap(v any) map[string]any {
	e.t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		e.t.Fatalf("expected object, got %T: %v", v, v)
	}
	return m
}

func (e *oauthEnv) asList(v any) []any {
	e.t.Helper()
	l, ok := v.([]any)
	if !ok {
		e.t.Fatalf("expected array, got %T: %v", v, v)
	}
	return l
}

func (e *oauthEnv) str(v any, key string) string {
	e.t.Helper()
	m := e.asMap(v)
	s, ok := m[key].(string)
	if !ok {
		e.t.Fatalf("field %q missing or not a string: %v", key, m)
	}
	return s
}

// registerIdentity registers a fresh identity and returns its center token.
func (e *oauthEnv) registerIdentity(username, email, password string) string {
	e.t.Helper()
	status, body := e.doJSON("POST", "/api/v1/auth/register", "", map[string]any{
		"username": username, "email": email, "password": password,
	})
	if status != 201 {
		e.t.Fatalf("register %s: %d %v", username, status, body)
	}
	return e.str(body, "access_token")
}

// createAppWithRole provisions a business app with one api resource and a
// role binding both, returning (roleID).
func (e *oauthEnv) createAppWithRole(key string) string {
	e.t.Helper()
	status, body := e.doJSON("POST", "/api/v1/admin/orgs", e.rootToken, map[string]any{"key": key + "org", "name": key + " Org"})
	if status != 201 {
		e.t.Fatalf("create org: %d %v", status, body)
	}
	status, body = e.doJSON("POST", "/api/v1/admin/apps", e.rootToken, map[string]any{
		"key": key, "org_key": key + "org", "name": strings.ToUpper(key), "type": "web",
	})
	if status != 201 {
		e.t.Fatalf("create app: %d %v", status, body)
	}
	status, body = e.doJSON("PUT", "/api/v1/admin/apps/"+key+"/resources:batch", e.rootToken, map[string]any{
		"items": []any{map[string]any{"type": "api", "code": "order:read", "name": "Read orders", "method": "GET", "route_path": "/api/orders"}},
	})
	if status != 200 {
		e.t.Fatalf("batch resources: %d %v", status, body)
	}
	status, body = e.doJSON("POST", "/api/v1/admin/apps/"+key+"/roles", e.rootToken, map[string]any{"code": "manager", "name": "Manager"})
	if status != 201 {
		e.t.Fatalf("create role: %d %v", status, body)
	}
	roleID := e.str(body, "id")
	status, body = e.doJSON("GET", "/api/v1/admin/apps/"+key+"/resources", e.rootToken, nil)
	if status != 200 {
		e.t.Fatalf("resource tree: %d %v", status, body)
	}
	var resID string
	var walk func(nodes []any)
	walk = func(nodes []any) {
		for _, n := range nodes {
			node := e.asMap(n)
			if node["code"] == "order:read" {
				resID = node["id"].(string)
			}
			if kids, ok := node["children"].([]any); ok {
				walk(kids)
			}
		}
	}
	walk(e.asList(body))
	status, _ = e.doJSON("PUT", "/api/v1/admin/apps/"+key+"/roles/"+roleID+"/resources", e.rootToken, map[string]any{"resource_ids": []string{resID}})
	if status != 200 {
		e.t.Fatalf("bind role resources: %d", status)
	}
	return roleID
}

// createOAuthClient creates an OIDC client via the admin API and returns
// (client_id, client_secret).
func (e *oauthEnv) createOAuthClient(appKey, name, clientType string, grants []string) (string, string) {
	e.t.Helper()
	status, body := e.doJSON("POST", "/api/v1/admin/apps/"+appKey+"/oauth-clients", e.rootToken, map[string]any{
		"name":          name,
		"client_type":   clientType,
		"grant_types":   grants,
		"redirect_uris": []string{"https://rp.example.com/cb"},
		"scopes":        []string{"openid", "profile", "email", "offline_access"},
	})
	if status != 201 {
		e.t.Fatalf("create oauth client: %d %v", status, body)
	}
	clientID := e.str(body, "client_id")
	secret := e.asMap(body)["client_secret"]
	if clientType == "confidential" {
		if s, ok := secret.(string); !ok || !strings.HasPrefix(s, "sec_") {
			e.t.Fatalf("confidential client must return a sec_ secret once: %v", body)
		}
	}
	return clientID, e.str(body, "client_secret")
}

// pkcePair generates a verifier + S256 challenge.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyRS256 pulls the JWKS and verifies the token signature, returning the
// parsed claims (proves the id_token is a genuine RS256 JWT verifiable via
// /.well-known/jwks.json).
func (e *oauthEnv) verifyRS256(token string) jwt.MapClaims {
	e.t.Helper()
	status, body := e.doJSON("GET", "/.well-known/jwks.json", "", nil)
	if status != 200 {
		e.t.Fatalf("jwks: %d %v", status, body)
	}
	keys := e.asList(e.asMap(body)["keys"])
	if len(keys) != 1 {
		e.t.Fatalf("jwks keys = %v", keys)
	}
	k := e.asMap(keys[0])
	nBytes, err := base64.RawURLEncoding.DecodeString(e.str(k, "n"))
	if err != nil {
		e.t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(e.str(k, "e"))
	if err != nil {
		e.t.Fatalf("decode e: %v", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if _, _, err := parser.ParseUnverified(token, claims); err == nil {
		_ = claims // fallthrough to real verification below
	}
	if _, err := jwt.Parse(token, func(t *jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired()); err != nil {
		e.t.Fatalf("id_token RS256 verification failed: %v", err)
	}
	// Re-parse to plain claims for assertions.
	tok, err := jwt.Parse(token, func(t *jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if err != nil {
		e.t.Fatalf("id_token parse: %v", err)
	}
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		e.t.Fatalf("claims type %T", tok.Claims)
	}
	return mc
}

// ---------------------------------------------------------------------------
// 1. 2FA lifecycle: enroll -> confirm -> login challenge -> backup codes ->
// disable.
// ---------------------------------------------------------------------------

func TestTwoFactorFlow(t *testing.T) {
	env := newOAuthEnv(t)
	alice := env.registerIdentity("alice2fa", "alice2fa@test.dev", "AlicePassw0rd")

	// Status starts disabled.
	status, body := env.doJSON("GET", "/api/v1/me/2fa/status", alice, nil)
	if status != 200 {
		t.Fatalf("2fa status: %d %v", status, body)
	}
	if env.asMap(body)["enabled"] != false || env.asMap(body)["confirmed"] != false {
		t.Fatalf("initial 2fa status = %v", body)
	}

	// Enroll -> secret + otpauth URI (unconfirmed draft).
	status, body = env.doJSON("POST", "/api/v1/me/2fa/enroll", alice, nil)
	if status != 201 {
		t.Fatalf("2fa enroll: %d %v", status, body)
	}
	secret := env.str(body, "secret")
	if !strings.Contains(env.str(body, "otpauth_uri"), "otpauth://totp/") {
		t.Fatalf("otpauth_uri = %v", body)
	}
	// The draft does not enable 2FA yet.
	status, body = env.doJSON("GET", "/api/v1/me/2fa/status", alice, nil)
	if env.asMap(body)["enabled"] != false {
		t.Fatalf("draft must not count as enabled: %v", body)
	}

	// Re-enroll replaces the draft with a fresh secret.
	status, body = env.doJSON("POST", "/api/v1/me/2fa/enroll", alice, nil)
	if status != 201 {
		t.Fatalf("re-enroll: %d %v", status, body)
	}
	secret = env.str(body, "secret")

	// Confirm with a valid TOTP code -> backup codes returned once.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	status, body = env.doJSON("POST", "/api/v1/me/2fa/confirm", alice, map[string]any{"code": code})
	if status != 200 {
		t.Fatalf("2fa confirm: %d %v", status, body)
	}
	backupCodes := env.asList(env.asMap(body)["backup_codes"])
	if len(backupCodes) != 8 {
		t.Fatalf("backup_codes = %v", backupCodes)
	}
	status, body = env.doJSON("GET", "/api/v1/me/2fa/status", alice, nil)
	if env.asMap(body)["enabled"] != true || env.asMap(body)["confirmed"] != true {
		t.Fatalf("post-confirm status = %v", body)
	}
	// /me carries two_fa_enabled.
	status, body = env.doJSON("GET", "/api/v1/me", alice, nil)
	if env.asMap(body)["two_fa_enabled"] != true {
		t.Fatalf("me.two_fa_enabled = %v", body)
	}
	// Enrolling again is refused.
	status, _ = env.doJSON("POST", "/api/v1/me/2fa/enroll", alice, nil)
	if status != 409 {
		t.Fatalf("re-enroll while enabled must 409, got %d", status)
	}

	// Login now returns the challenge instead of tokens.
	status, body = env.doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "alice2fa@test.dev", "password": "AlicePassw0rd",
	})
	if status != 200 {
		t.Fatalf("mfa login: %d %v", status, body)
	}
	if env.asMap(body)["mfa_required"] != true {
		t.Fatalf("login must demand mfa: %v", body)
	}
	mfaToken := env.str(body, "mfa_token")
	if _, exists := env.asMap(body)["access_token"]; exists {
		t.Fatal("mfa challenge response must not carry tokens")
	}

	// A wrong code is 403 and consumes nothing.
	status, _ = env.doJSON("POST", "/api/v1/auth/login/2fa", "", map[string]any{"mfa_token": mfaToken, "code": "000000"})
	if status != 403 {
		t.Fatalf("wrong 2fa code must 403, got %d", status)
	}

	// A fresh valid code completes the login.
	status, body = env.doJSON("POST", "/api/v1/auth/login/2fa", "", map[string]any{
		"mfa_token": mfaToken, "code": mustCode(t, secret),
	})
	if status != 200 {
		t.Fatalf("2fa login: %d %v", status, body)
	}
	centerToken := env.str(body, "access_token")
	if centerToken == "" || env.str(body, "refresh_token") == "" {
		t.Fatalf("2fa login must issue a token pair: %v", body)
	}
	status, body = env.doJSON("GET", "/api/v1/me", centerToken, nil)
	if status != 200 || env.asMap(body)["email"] != "alice2fa@test.dev" {
		t.Fatalf("me after 2fa login: %d %v", status, body)
	}

	// Second challenge: the same step's code (identical value) is rejected
	// as a replay (matched step == last_used_step); the next step's code
	// passes (the ±1 window includes it).
	status, body2 := env.doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "alice2fa@test.dev", "password": "AlicePassw0rd",
	})
	if status != 200 {
		t.Fatalf("second mfa login: %d %v", status, body2)
	}
	replayToken := env.str(body2, "mfa_token")
	sameStepCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	status, _ = env.doJSON("POST", "/api/v1/auth/login/2fa", "", map[string]any{
		"mfa_token": replayToken, "code": sameStepCode,
	})
	if status != 403 {
		t.Fatalf("same-step code must be rejected as replay, got %d", status)
	}
	nextStepCode, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("generate next-step code: %v", err)
	}
	status, _ = env.doJSON("POST", "/api/v1/auth/login/2fa", "", map[string]any{
		"mfa_token": replayToken, "code": nextStepCode,
	})
	if status != 200 {
		t.Fatalf("next-step code must pass: %d %v", status, body)
	}

	// A backup code works exactly once.
	status, body = env.doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "alice2fa@test.dev", "password": "AlicePassw0rd",
	})
	mfaToken = env.str(body, "mfa_token")
	backupCode := backupCodes[0].(string)
	status, body = env.doJSON("POST", "/api/v1/auth/login/2fa", "", map[string]any{
		"mfa_token": mfaToken, "code": backupCode,
	})
	if status != 200 {
		t.Fatalf("backup code login: %d %v", status, body)
	}
	// Same backup code again -> rejected.
	status, body = env.doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "alice2fa@test.dev", "password": "AlicePassw0rd",
	})
	mfaToken = env.str(body, "mfa_token")
	status, _ = env.doJSON("POST", "/api/v1/auth/login/2fa", "", map[string]any{
		"mfa_token": mfaToken, "code": backupCode,
	})
	if status != 403 {
		t.Fatalf("reused backup code must 403, got %d", status)
	}

	// Disable requires the correct password (403 otherwise).
	status, _ = env.doJSON("POST", "/api/v1/me/2fa/disable", alice, map[string]any{"password": "WrongPassw0rd"})
	if status != 403 {
		t.Fatalf("disable with wrong password must 403, got %d", status)
	}
	status, _ = env.doJSON("POST", "/api/v1/me/2fa/disable", alice, map[string]any{"password": "AlicePassw0rd"})
	if status != 200 {
		t.Fatalf("disable: %d", status)
	}
	status, body = env.doJSON("GET", "/api/v1/me/2fa/status", alice, nil)
	if env.asMap(body)["enabled"] != false {
		t.Fatalf("post-disable status = %v", body)
	}

	// Plain login works again (no challenge).
	status, body = env.doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "alice2fa@test.dev", "password": "AlicePassw0rd",
	})
	if status != 200 || env.str(body, "access_token") == "" {
		t.Fatalf("login after disable must issue tokens directly: %d %v", status, body)
	}
	if env.asMap(body)["mfa_required"] == true {
		t.Fatal("mfa_required must be absent after disable")
	}
}

// audContains checks the aud claim against a value regardless of whether
// the parser delivered it as string or list.
func audContains(claims jwt.MapClaims, want string) bool {
	switch v := claims["aud"].(type) {
	case string:
		return v == want
	case []string:
		for _, a := range v {
			if a == want {
				return true
			}
		}
	case []any:
		for _, a := range v {
			if fmt.Sprint(a) == want {
				return true
			}
		}
	}
	return false
}

func mustCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}

// ---------------------------------------------------------------------------
// 2. Full OIDC authorization-code flow: admin client CRUD -> authorize (SPA)
// -> token (Basic auth + PKCE) -> id_token (nonce/RS256/at_hash) -> userinfo
// -> refresh rotation + family revocation on reuse.
// ---------------------------------------------------------------------------

func TestOAuthOIDCCodeFlow(t *testing.T) {
	env := newOAuthEnv(t)
	roleID := env.createAppWithRole("crm")

	// Provision alice's CRM account with the manager role (workspace
	// resolution path: the identity's unique existing account in the app).
	alice := env.registerIdentity("aliceoidc", "aliceoidc@test.dev", "AlicePassw0rd")
	status, body := env.doJSON("POST", "/api/v1/admin/apps/crm/accounts", env.rootToken, map[string]any{
		"email": "aliceoidc@test.dev", "role_ids": []string{roleID}, "password": "AliceCrmPass1",
	})
	if status != 201 {
		t.Fatalf("provision account: %d %v", status, body)
	}

	// Admin CRUD: create a confidential authorization-code client.
	status, body = env.doJSON("POST", "/api/v1/admin/apps/crm/oauth-clients", env.rootToken, map[string]any{
		"name":          "CRM Web",
		"client_type":   "confidential",
		"grant_types":   []string{"authorization_code", "refresh_token"},
		"redirect_uris": []string{"https://rp.example.com/cb", "https://rp.example.com/cb2"},
		"scopes":        []string{"openid", "profile", "email", "offline_access"},
	})
	if status != 201 {
		t.Fatalf("create oauth client: %d %v", status, body)
	}
	clientID := env.str(body, "client_id")
	clientSecret := env.str(body, "client_secret")
	if !strings.HasPrefix(clientID, "cli_") || !strings.HasPrefix(clientSecret, "sec_") {
		t.Fatalf("client id/secret shapes: %v", body)
	}

	status, body = env.doJSON("GET", "/api/v1/admin/apps/crm/oauth-clients", env.rootToken, nil)
	if status != 200 || len(env.asList(body)) != 1 {
		t.Fatalf("list oauth clients: %d %v", status, body)
	}

	// Validation failures first: unregistered redirect URI.
	verifier, challenge := pkcePair(t)
	status, body = env.doJSON("POST", "/api/v1/oauth/authorize", alice, map[string]any{
		"client_id": clientID, "redirect_uri": "https://evil.example.com/cb",
		"scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256",
	})
	if status != 400 {
		t.Fatalf("unregistered redirect_uri must 400, got %d %v", status, body)
	}
	// Missing PKCE for... (confidential: allowed, so instead check a bad method)
	status, body = env.doJSON("POST", "/api/v1/oauth/authorize", alice, map[string]any{
		"client_id": clientID, "redirect_uri": "https://rp.example.com/cb",
		"scope": "openid", "code_challenge": challenge, "code_challenge_method": "plain",
	})
	if status != 400 {
		t.Fatalf("plain method must 400, got %d %v", status, body)
	}
	// Anonymous SPA authorize requires a center token.
	status, _ = env.doJSON("POST", "/api/v1/oauth/authorize", "", map[string]any{
		"client_id": clientID, "redirect_uri": "https://rp.example.com/cb",
	})
	if status != 401 {
		t.Fatalf("anonymous authorize must 401, got %d", status)
	}

	// SPA authorize: full request with PKCE + nonce + state.
	status, body = env.doJSON("POST", "/api/v1/oauth/authorize", alice, map[string]any{
		"client_id": clientID, "redirect_uri": "https://rp.example.com/cb",
		"scope": "openid profile email offline_access", "state": "st-123",
		"code_challenge": challenge, "code_challenge_method": "S256", "nonce": "n-123",
	})
	if status != 200 {
		t.Fatalf("spa authorize: %d %v", status, body)
	}
	redirectTo := env.str(body, "redirect_to")
	u, err := url.Parse(redirectTo)
	if err != nil {
		t.Fatalf("parse redirect_to: %v", err)
	}
	q := u.Query()
	if u.String()[:len("https://rp.example.com/cb")] != "https://rp.example.com/cb" ||
		q.Get("state") != "st-123" || q.Get("iss") != "http://localhost:8080" || q.Get("code") == "" {
		t.Fatalf("redirect_to = %q (query %v)", redirectTo, q)
	}
	code := q.Get("code")

	// Token exchange: a wrong verifier is invalid_grant (the library burns
	// the code on any exchange attempt, so a fresh code is issued after).
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://rp.example.com/cb"}, "code_verifier": {"wrong-verifier-wrong-verifier-wrong-verifier"},
	}, clientID, clientSecret, "")
	if status != 400 || env.asMap(body)["error"] != "invalid_grant" {
		t.Fatalf("wrong PKCE verifier must be invalid_grant, got %d %v", status, body)
	}
	status, body = env.doJSON("POST", "/api/v1/oauth/authorize", alice, map[string]any{
		"client_id": clientID, "redirect_uri": "https://rp.example.com/cb",
		"scope": "openid profile email offline_access", "state": "st-123",
		"code_challenge": challenge, "code_challenge_method": "S256", "nonce": "n-123",
	})
	if status != 200 {
		t.Fatalf("spa authorize (2nd): %d %v", status, body)
	}
	code = env.str(body, "redirect_to")
	if idx := strings.Index(code, "code="); idx >= 0 {
		code = code[idx+5:]
		if amp := strings.Index(code, "&"); amp >= 0 {
			code = code[:amp]
		}
	} else {
		t.Fatalf("no code in redirect_to: %q", code)
	}

	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://rp.example.com/cb"}, "code_verifier": {verifier},
	}, clientID, clientSecret, "")
	if status != 200 {
		t.Fatalf("token exchange: %d %v", status, body)
	}
	accessToken := env.str(body, "access_token")
	refreshToken := env.str(body, "refresh_token")
	idToken := env.str(body, "id_token")
	if env.str(body, "token_type") != "Bearer" || accessToken == "" || refreshToken == "" || idToken == "" {
		t.Fatalf("token response incomplete: %v", body)
	}
	if _, ok := env.asMap(body)["scope"]; !ok {
		t.Fatal("token response must echo the scope")
	}

	// The code is single-use.
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://rp.example.com/cb"}, "code_verifier": {verifier},
	}, clientID, clientSecret, "")
	if status != 400 {
		t.Fatalf("code reuse must 400, got %d %v", status, body)
	}

	// id_token: RS256-verifiable via JWKS, with nonce + at_hash bound to the
	// access token.
	idClaims := env.verifyRS256(idToken)
	if idClaims["nonce"] != "n-123" {
		t.Fatalf("id_token nonce = %v", idClaims["nonce"])
	}
	if idClaims["iss"] != "http://localhost:8080" {
		t.Fatalf("id_token iss = %v", idClaims["iss"])
	}
	if !strings.HasPrefix(fmt.Sprint(idClaims["sub"]), "account:") {
		t.Fatalf("id_token sub = %v", idClaims["sub"])
	}
	if !audContains(idClaims, clientID) {
		t.Fatalf("id_token aud = %v (want %s)", idClaims["aud"], clientID)
	}
	sum := sha256.Sum256([]byte(accessToken))
	if idClaims["at_hash"] != base64.RawURLEncoding.EncodeToString(sum[:16]) {
		t.Fatalf("id_token at_hash = %v", idClaims["at_hash"])
	}

	// Userinfo with the account-subject access token.
	req, _ := http.NewRequest("GET", env.ts.URL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, raw)
	}
	var ui map[string]any
	_ = json.Unmarshal(raw, &ui)
	if ui["sub"] != idClaims["sub"] || ui["email"] != "aliceoidc@test.dev" || ui["app"] != "crm" {
		t.Fatalf("userinfo = %v", ui)
	}
	roles, _ := ui["roles"].([]any)
	if len(roles) != 1 || roles[0] != "manager" {
		t.Fatalf("userinfo roles = %v", ui["roles"])
	}

	// Refresh rotation: new refresh token; reuse of the old one revokes the
	// whole family.
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
	}, clientID, clientSecret, "")
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, body)
	}
	refresh2 := env.str(body, "refresh_token")
	if refresh2 == refreshToken {
		t.Fatal("refresh must rotate the token")
	}
	// Reuse of the rotated hash -> family revoked.
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
	}, clientID, clientSecret, "")
	if status != 400 {
		t.Fatalf("refresh reuse must 400, got %d %v", status, body)
	}
	// The family (including the NEW token) is now revoked.
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh2},
	}, clientID, clientSecret, "")
	if status != 400 {
		t.Fatalf("refresh after family revocation must 400, got %d %v", status, body)
	}

	// Disabling the client blocks further authorizes.
	status, _ = env.doJSON("PATCH", "/api/v1/admin/apps/crm/oauth-clients/"+clientID, env.rootToken, map[string]any{
		"status": "disabled",
	})
	if status != 200 {
		t.Fatalf("disable client: %d", status)
	}
	status, body = env.doJSON("POST", "/api/v1/oauth/authorize", alice, map[string]any{
		"client_id": clientID, "redirect_uri": "https://rp.example.com/cb",
		"scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256",
	})
	if status != 401 || env.asMap(body)["error"] != "unauthorized_client" {
		t.Fatalf("disabled client authorize must be unauthorized_client, got %d %v", status, body)
	}
	// DELETE removes the registration.
	status, _ = env.doJSON("DELETE", "/api/v1/admin/apps/crm/oauth-clients/"+clientID, env.rootToken, nil)
	if status != 204 {
		t.Fatalf("delete client: %d", status)
	}
}

// ---------------------------------------------------------------------------
// 2b. refresh_token grant: client authentication (RFC 6749 §6) and live
// subject-status checks (a disabled account/identity cannot refresh).
// ---------------------------------------------------------------------------

func TestOAuthRefreshClientAuthAndSubjectStatus(t *testing.T) {
	env := newOAuthEnv(t)
	roleID := env.createAppWithRole("crmra")
	alice := env.registerIdentity("alicera", "alicera@test.dev", "AlicePassw0rd")
	status, body := env.doJSON("POST", "/api/v1/admin/apps/crmra/accounts", env.rootToken, map[string]any{
		"email": "alicera@test.dev", "role_ids": []string{roleID}, "password": "AliceCrmPass1",
	})
	if status != 201 {
		t.Fatalf("provision account: %d %v", status, body)
	}
	clientID, clientSecret := env.createOAuthClient("crmra", "RP RA", "confidential",
		[]string{"authorization_code", "refresh_token"})
	otherID, otherSecret := env.createOAuthClient("crmra", "RP RA 2", "confidential",
		[]string{"authorization_code", "refresh_token"})

	verifier, challenge := pkcePair(t)
	status, body = env.doJSON("POST", "/api/v1/oauth/authorize", alice, map[string]any{
		"client_id": clientID, "redirect_uri": "https://rp.example.com/cb",
		"scope": "openid offline_access", "code_challenge": challenge, "code_challenge_method": "S256",
	})
	if status != 200 {
		t.Fatalf("spa authorize: %d %v", status, body)
	}
	code := env.str(body, "redirect_to")
	if idx := strings.Index(code, "code="); idx >= 0 {
		code = code[idx+5:]
		if amp := strings.Index(code, "&"); amp >= 0 {
			code = code[:amp]
		}
	}
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://rp.example.com/cb"}, "code_verifier": {verifier},
	}, clientID, clientSecret, "")
	if status != 200 {
		t.Fatalf("token exchange: %d %v", status, body)
	}
	refreshToken := env.str(body, "refresh_token")

	// No client credentials at all -> invalid_client (was: token worked).
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
	}, "", "", "")
	if status != 401 || env.asMap(body)["error"] != "invalid_client" {
		t.Fatalf("refresh without client auth must be 401 invalid_client, got %d %v", status, body)
	}
	// Right client, wrong secret.
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
	}, clientID, "sec_wrong", "")
	if status != 401 || env.asMap(body)["error"] != "invalid_client" {
		t.Fatalf("refresh with wrong secret must be 401 invalid_client, got %d %v", status, body)
	}
	// Another client's credentials must not be able to use the token.
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
	}, otherID, otherSecret, "")
	if status != 401 || env.asMap(body)["error"] != "invalid_client" {
		t.Fatalf("refresh with foreign client must be 401 invalid_client, got %d %v", status, body)
	}
	// Correct credentials still work, and rotate.
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
	}, clientID, clientSecret, "")
	if status != 200 {
		t.Fatalf("authenticated refresh: %d %v", status, body)
	}
	refresh2 := env.str(body, "refresh_token")

	// Disable the account under the token: further refreshes must fail with
	// invalid_grant even though the token row itself is untouched.
	user, err := env.tc.UserRepo().FindByEmail(context.Background(), "alicera@test.dev")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	accounts, err := env.tc.AccountRepo().ListByIdentity(context.Background(), user.Id)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("list accounts: %v (%d)", err, len(accounts))
	}
	if err := env.tc.AccountRepo().UpdateFields(context.Background(),
		accounts[0].Id, map[string]any{"status": domain.AccountStatusDisabled}); err != nil {
		t.Fatalf("disable account: %v", err)
	}
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh2},
	}, clientID, clientSecret, "")
	if status != 400 || env.asMap(body)["error"] != "invalid_grant" {
		t.Fatalf("refresh for disabled account must be invalid_grant, got %d %v", status, body)
	}

	// Same for a disabled identity.
	if err := env.tc.AccountRepo().UpdateFields(context.Background(),
		accounts[0].Id, map[string]any{"status": domain.AccountStatusActive}); err != nil {
		t.Fatalf("re-enable account: %v", err)
	}
	if err := env.tc.UserRepo().UpdateFields(context.Background(),
		user.Id, map[string]any{"status": domain.UserStatusDisabled}); err != nil {
		t.Fatalf("disable identity: %v", err)
	}
	status, body = env.doForm("/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh2},
	}, clientID, clientSecret, "")
	if status != 400 || env.asMap(body)["error"] != "invalid_grant" {
		t.Fatalf("refresh for disabled identity must be invalid_grant, got %d %v", status, body)
	}
}

// ---------------------------------------------------------------------------
// 2c. refresh reuse revokes only the replayed token's family (the row), not
// every refresh token of the client (a client-wide logout DoS before the
// fix: any user could replay their own old token and kick everyone off).
// ---------------------------------------------------------------------------

func TestOAuthRefreshReuseRevokesOnlyTheTokenFamily(t *testing.T) {
	env := newOAuthEnv(t)
	roleID := env.createAppWithRole("crmr")
	alice := env.registerIdentity("alicefam", "alicefam@test.dev", "AlicePassw0rd")
	bob := env.registerIdentity("bobfam", "bobfam@test.dev", "BobPassw0rd1")
	for _, u := range []struct{ email string }{{"alicefam@test.dev"}, {"bobfam@test.dev"}} {
		status, body := env.doJSON("POST", "/api/v1/admin/apps/crmr/accounts", env.rootToken, map[string]any{
			"email": u.email, "role_ids": []string{roleID}, "password": "CrmPassw0rd1",
		})
		if status != 201 {
			t.Fatalf("provision account %s: %d %v", u.email, status, body)
		}
	}
	clientID, clientSecret := env.createOAuthClient("crmr", "RP Fam", "confidential",
		[]string{"authorization_code", "refresh_token"})

	issueRefresh := func(who string, center string) string {
		t.Helper()
		verifier, challenge := pkcePair(t)
		status, body := env.doJSON("POST", "/api/v1/oauth/authorize", center, map[string]any{
			"client_id": clientID, "redirect_uri": "https://rp.example.com/cb",
			"scope": "offline_access", "code_challenge": challenge, "code_challenge_method": "S256",
		})
		if status != 200 {
			t.Fatalf("%s authorize: %d %v", who, status, body)
		}
		code := env.str(body, "redirect_to")
		if idx := strings.Index(code, "code="); idx >= 0 {
			code = code[idx+5:]
			if amp := strings.Index(code, "&"); amp >= 0 {
				code = code[:amp]
			}
		}
		status, body = env.doForm("/oauth2/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://rp.example.com/cb"}, "code_verifier": {verifier},
		}, clientID, clientSecret, "")
		if status != 200 {
			t.Fatalf("%s token exchange: %d %v", who, status, body)
		}
		return env.str(body, "refresh_token")
	}
	doRefresh := func(token string) (int, map[string]any) {
		t.Helper()
		return env.doForm("/oauth2/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {token},
		}, clientID, clientSecret, "")
	}

	aliceV1 := issueRefresh("alice", alice)
	// Rotate once: aliceV1 is now a retired hash.
	status, body := doRefresh(aliceV1)
	if status != 200 {
		t.Fatalf("alice refresh: %d %v", status, body)
	}
	aliceV2 := env.str(body, "refresh_token")
	bobV1 := issueRefresh("bob", bob)

	// Alice replays the retired token: her family (including aliceV2) dies…
	status, _ = doRefresh(aliceV1)
	if status != 400 {
		t.Fatalf("alice replay must 400, got %d", status)
	}
	status, _ = doRefresh(aliceV2)
	if status != 400 {
		t.Fatalf("alice family must be revoked, got %d", status)
	}
	// …but bob's token from the same client keeps working.
	status, body = doRefresh(bobV1)
	if status != 200 {
		t.Fatalf("bob's token must survive alice's replay: %d %v", status, body)
	}
}

// ---------------------------------------------------------------------------
// 3. client_credentials: service token works on userinfo and passes
// authz/check against its OWN app via the Casbin loader wildcard rule.
// ---------------------------------------------------------------------------

func TestOAuthClientCredentials(t *testing.T) {
	env := newOAuthEnv(t)
	env.createAppWithRole("crm")
	clientID, clientSecret := env.createOAuthClient("crm", "CRM Service", "confidential", []string{"client_credentials"})

	// The loader only picks up new service clients on a policy reload
	// (documented behavior; production reloads via NotifyReload/restart).
	if err := env.tc.EnfVal.Reload(); err != nil {
		t.Fatalf("reload enforcer: %v", err)
	}

	// Public clients cannot use client_credentials: creation is refused.
	status, _ := env.doJSON("POST", "/api/v1/admin/apps/crm/oauth-clients", env.rootToken, map[string]any{
		"name": "Bad Public", "client_type": "public", "grant_types": []string{"client_credentials"},
		"redirect_uris": []string{"https://rp.example.com/cb"},
	})
	if status != 400 {
		t.Fatalf("public client_credentials must be refused, got %d", status)
	}

	// Token exchange with Basic auth.
	status, body := env.doForm("/oauth2/token", url.Values{
		"grant_type": {"client_credentials"}, "scope": {"email"},
	}, clientID, clientSecret, "")
	if status != 200 {
		t.Fatalf("client_credentials: %d %v", status, body)
	}
	accessToken := env.str(body, "access_token")
	if _, ok := env.asMap(body)["refresh_token"]; ok {
		t.Fatal("client_credentials must not mint a refresh token")
	}
	if _, ok := env.asMap(body)["id_token"]; ok {
		t.Fatal("client_credentials must not mint an id_token")
	}

	// Userinfo reports the client subject.
	req, _ := http.NewRequest("GET", env.ts.URL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, raw)
	}
	var ui map[string]any
	_ = json.Unmarshal(raw, &ui)
	if !strings.HasPrefix(fmt.Sprint(ui["sub"]), "client:") || ui["app"] != "crm" {
		t.Fatalf("client userinfo = %v", ui)
	}

	// authz/check: the loader rule allows own-app objects.
	var check any
	status, check = env.doJSON("POST", "/api/v1/authz/check", accessToken, map[string]any{"obj": "order:read"})
	if status != 200 {
		t.Fatalf("authz check: %d %v", status, body)
	}
	if env.asMap(check)["allowed"] != true {
		t.Fatalf("client token must be allowed on its own app resource: %v", check)
	}
	// A wrong client secret is rejected.
	status, body = env.doForm("/oauth2/token", url.Values{"grant_type": {"client_credentials"}},
		clientID, "sec_wrong", "")
	if status != 401 || env.asMap(body)["error"] != "invalid_client" {
		t.Fatalf("wrong secret must be invalid_client, got %d %v", status, body)
	}
}

// ---------------------------------------------------------------------------
// 4. Browser authorize endpoint: anonymous -> portal login redirect with
// next; with a center bearer token -> 302 to the redirect_uri with code.
// ---------------------------------------------------------------------------

func TestOAuthBrowserAuthorize(t *testing.T) {
	env := newOAuthEnv(t)
	env.createAppWithRole("crm")
	alice := env.registerIdentity("alicebrowser", "alicebrowser@test.dev", "AlicePassw0rd")
	clientID, _ := env.createOAuthClient("crm", "CRM Web", "confidential", []string{"authorization_code"})

	authorizeQuery := url.Values{
		"response_type": {"code"}, "client_id": {clientID},
		"redirect_uri": {"https://rp.example.com/cb"}, "state": {"xyz"},
		"scope": {"openid"},
	}

	// Anonymous: 302 to {portalURL}/login?next={original authorize URL}.
	target := "/oauth2/authorize?" + authorizeQuery.Encode()
	req, _ := http.NewRequest("GET", env.ts.URL+target, nil)
	resp, err := env.noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("browser authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("anonymous browser authorize must 302, got %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if location.String()[:len("http://localhost:3000/login")] != "http://localhost:3000/login" {
		t.Fatalf("portal redirect = %q", location.String())
	}
	next := location.Query().Get("next")
	// The portal contract: next carries the FULL original authorize URL so
	// the frontend can bounce the browser straight back after its login.
	if !strings.HasPrefix(next, "http://localhost:8080/oauth2/authorize?") {
		t.Fatalf("next = %q", next)
	}
	if !strings.Contains(next, "client_id="+clientID) || !strings.Contains(next, "state=xyz") {
		t.Fatalf("next must embed the original authorize URL: %q", next)
	}

	// With a center identity token: 302 to the redirect_uri with code+state.
	req, _ = http.NewRequest("GET", env.ts.URL+target, nil)
	req.Header.Set("Authorization", "Bearer "+alice)
	resp, err = env.noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("browser authorize with token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("authenticated browser authorize must 302, got %d", resp.StatusCode)
	}
	to := resp.Header.Get("Location")
	q := (&url.URL{RawQuery: strings.SplitN(to, "?", 2)[1]}).Query()
	if !strings.HasPrefix(to, "https://rp.example.com/cb") || q.Get("code") == "" || q.Get("state") != "xyz" {
		t.Fatalf("redirect = %q", to)
	}
}

// ---------------------------------------------------------------------------
// 2d. disable / transfer convergence: workspace (account-scope) sessions and
// OAuth refresh tokens die with the identity or the account binding.
// ---------------------------------------------------------------------------

func TestDisableAndTransferConvergeSessions(t *testing.T) {
	env := newOAuthEnv(t)
	roleID := env.createAppWithRole("crmc")
	alice := env.registerIdentity("aliceconv", "aliceconv@test.dev", "AlicePassw0rd")
	// bob is only the transfer target; the API matches by email.
	_ = env.registerIdentity("bobconv", "bobconv@test.dev", "BobPassw0rd1")
	status, body := env.doJSON("POST", "/api/v1/admin/apps/crmc/accounts", env.rootToken, map[string]any{
		"email": "aliceconv@test.dev", "role_ids": []string{roleID}, "password": "CrmPassw0rd1",
	})
	if status != 201 {
		t.Fatalf("provision account: %d %v", status, body)
	}
	accountID := env.str(body, "account_id")

	// Workspace (account-scope) session for alice.
	status, body = env.doJSON("POST", "/api/v1/me/workspaces/"+accountID+"/token", alice, nil)
	if status != 200 {
		t.Fatalf("workspace token: %d %v", status, body)
	}
	wsRefresh := env.str(body, "refresh_token")

	// A planted OAuth refresh token owned by alice's identity.
	uid, err := env.tc.UserRepo().FindByEmail(context.Background(), "aliceconv@test.dev")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	seedSum := sha256.Sum256([]byte("seeded-oauth-refresh"))
	seeded := hex.EncodeToString(seedSum[:])
	if err := env.tc.OAuthRefreshTokenRepo().Create(context.Background(), &model.OAuthRefreshToken{
		BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
		ClientID:     "cli_test",
		UserID:       &uid.Id,
		AccountID:    &accountID,
		TokenHash:    seeded,
		Scope:        "openid",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	// 1) Admin identity-disable must revoke BOTH scopes plus the OAuth
	// refresh tokens.
	status, _ = env.doJSON("PATCH", "/api/v1/admin/users/"+uid.Id, env.rootToken, map[string]any{"status": "disabled"})
	if status != 200 {
		t.Fatalf("disable user: %d", status)
	}
	status, body = env.doJSON("POST", "/api/v1/auth/token/refresh", "", map[string]any{"refresh_token": wsRefresh})
	if status != 401 {
		t.Fatalf("workspace refresh after identity disable must 401, got %d %v", status, body)
	}
	row, err := env.tc.OAuthRefreshTokenRepo().FindByTokenHash(context.Background(), seeded)
	if err != nil || row.RevokedAt == nil {
		t.Fatalf("oauth refresh token must be revoked after identity disable: %v %v", row, err)
	}
	status, _ = env.doJSON("PATCH", "/api/v1/admin/users/"+uid.Id, env.rootToken, map[string]any{"status": "active"})
	if status != 200 {
		t.Fatalf("re-enable user: %d", status)
	}

	// 2) Live status enforcement: disable the identity in the DB WITHOUT
	// revoking the (fresh) workspace session — refresh must still refuse.
	status, body = env.doJSON("POST", "/api/v1/me/workspaces/"+accountID+"/token", alice, nil)
	if status != 200 {
		t.Fatalf("workspace token (2nd): %d %v", status, body)
	}
	wsRefresh2 := env.str(body, "refresh_token")
	if err := env.tc.UserRepo().UpdateFields(context.Background(), uid.Id,
		map[string]any{"status": domain.UserStatusDisabled}); err != nil {
		t.Fatalf("disable user (direct): %v", err)
	}
	status, body = env.doJSON("POST", "/api/v1/auth/token/refresh", "", map[string]any{"refresh_token": wsRefresh2})
	if status != 401 {
		t.Fatalf("refresh with disabled identity must 401, got %d %v", status, body)
	}
	if err := env.tc.UserRepo().UpdateFields(context.Background(), uid.Id,
		map[string]any{"status": domain.UserStatusActive}); err != nil {
		t.Fatalf("re-enable user (direct): %v", err)
	}

	// 3) Transfer to bob: alice's live workspace session must be revoked.
	status, body = env.doJSON("POST", "/api/v1/admin/apps/crmc/accounts/"+accountID+"/transfer", env.rootToken,
		map[string]any{"identity_email": "bobconv@test.dev"})
	if status != 200 {
		t.Fatalf("transfer: %d %v", status, body)
	}
	status, body = env.doJSON("POST", "/api/v1/auth/token/refresh", "", map[string]any{"refresh_token": wsRefresh2})
	if status != 401 {
		t.Fatalf("old identity's refresh after transfer must 401, got %d %v", status, body)
	}
	row, err = env.tc.OAuthRefreshTokenRepo().FindByTokenHash(context.Background(), seeded)
	if err != nil {
		t.Fatalf("reload seeded token: %v", err)
	}
	// The planted token must now also be revoked by the transfer sweep.
	if row.RevokedAt == nil {
		t.Fatalf("oauth refresh token must be revoked after transfer")
	}
}

// ---------------------------------------------------------------------------
// 2e. browser authorize identity resolution: a logged-out (denylisted) or
// disabled caller must be treated as "no session" and bounced to the portal
// login, never mint codes from a merely well-signed token.
// ---------------------------------------------------------------------------

func TestBrowserAuthorizeRejectsLoggedOutOrDisabledCaller(t *testing.T) {
	env := newOAuthEnv(t)
	env.createAppWithRole("crmb")
	alice := env.registerIdentity("alicebo", "alicebo@test.dev", "AlicePassw0rd")
	uid, err := env.tc.UserRepo().FindByEmail(context.Background(), "alicebo@test.dev")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	clientID, _ := env.createOAuthClient("crmb", "CRM B", "confidential", []string{"authorization_code"})
	target := "/oauth2/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID},
		"redirect_uri": {"https://rp.example.com/cb"}, "state": {"xyz"}, "scope": {"openid"},
	}.Encode()
	authorize := func(token string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", env.ts.URL+target, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := env.noRedirectClient.Do(req)
		if err != nil {
			t.Fatalf("browser authorize: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Location")
	}
	goLogin := func(loc string) {
		t.Helper()
		if !strings.Contains(loc, "localhost:3000/login") {
			t.Fatalf("must bounce to the portal login, got %q", loc)
		}
	}

	// Sanity: a live token mints codes.
	status, loc := authorize(alice)
	if status != 302 || !strings.HasPrefix(loc, "https://rp.example.com/cb") {
		t.Fatalf("live token must mint codes: %d %q", status, loc)
	}

	// A disabled user is "no session" even with a perfectly valid token.
	if err := env.tc.UserRepo().UpdateFields(context.Background(), uid.Id,
		map[string]any{"status": domain.UserStatusDisabled}); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	status, loc = authorize(alice)
	if status != 302 {
		t.Fatalf("disabled user authorize must 302, got %d", status)
	}
	goLogin(loc)
	if err := env.tc.UserRepo().UpdateFields(context.Background(), uid.Id,
		map[string]any{"status": domain.UserStatusActive}); err != nil {
		t.Fatalf("re-enable user: %v", err)
	}

	// A logged-out (jti-denylisted) token is "no session" too.
	status, _ = env.doJSON("POST", "/api/v1/auth/logout", alice, nil)
	if status != 204 && status != 200 {
		t.Fatalf("logout: %d", status)
	}
	status, loc = authorize(alice)
	if status != 302 {
		t.Fatalf("logged-out authorize must 302, got %d", status)
	}
	goLogin(loc)

	// And a fresh login recovers the flow (the denylist, not the endpoint,
	// was the blocker).
	status, body := env.doJSON("POST", "/api/v1/auth/login", "", map[string]any{
		"identifier": "alicebo@test.dev", "password": "AlicePassw0rd",
	})
	if status != 200 {
		t.Fatalf("re-login: %d %v", status, body)
	}
	status, loc = authorize(env.str(body, "access_token"))
	if status != 302 || !strings.HasPrefix(loc, "https://rp.example.com/cb") {
		t.Fatalf("fresh token must mint codes again: %d %q", status, loc)
	}
}

// ---------------------------------------------------------------------------
// 2f. invitation accept: a logged-in identity may only claim invitations
// addressed to their own email (a leaked/forwarded code is not a bearer
// credential for whoever is signed in).
// ---------------------------------------------------------------------------

func TestInvitationAcceptRequiresEmailMatch(t *testing.T) {
	env := newOAuthEnv(t)
	roleID := env.createAppWithRole("crmi")
	mallory := env.registerIdentity("malloryi", "malloryi@test.dev", "MalloryPass1")
	status, body := env.doJSON("POST", "/api/v1/admin/apps/crmi/invitations", env.rootToken, map[string]any{
		"email": "adai@test.dev", "role_ids": []string{roleID},
	})
	if status != 201 {
		t.Fatalf("create invitation: %d %v", status, body)
	}
	reHex := regexp.MustCompile(`\b[0-9a-f]{64}\b`)
	code := reHex.FindString(env.tc.Mail.Last().Body)
	if code == "" {
		t.Fatalf("invitation code not found in mail: %q", env.tc.Mail.Last().Body)
	}

	// Mallory (signed in) must not be able to claim ada's invitation.
	status, body = env.doJSON("POST", "/api/v1/invitations/accept", mallory, map[string]any{"code": code})
	if status != 403 {
		t.Fatalf("accepting someone else's invitation must 403, got %d %v", status, body)
	}

	// The invitation is untouched: the real invitee (anonymous auto-provision
	// path) can still redeem it.
	status, body = env.doJSON("POST", "/api/v1/invitations/accept", "", map[string]any{
		"code": code, "new_password": "AdaiPassw0rd1",
	})
	if status != 200 {
		t.Fatalf("real invitee accept: %d %v", status, body)
	}
}

// ---------------------------------------------------------------------------
// 2g. authz/check result cache: consulted BEFORE the enforce (a hit skips
// the evaluation) and keyed with escaped components so distinct obj/act
// tuples can never alias onto one cached entry.
// ---------------------------------------------------------------------------

func TestAuthzCheckCacheKeysDoNotCollide(t *testing.T) {
	env := newOAuthEnv(t)
	roleID := env.createAppWithRole("crmcz")
	alice := env.registerIdentity("alicecz", "alicecz@test.dev", "AlicePassw0rd")
	status, body := env.doJSON("POST", "/api/v1/admin/apps/crmcz/accounts", env.rootToken, map[string]any{
		"email": "alicecz@test.dev", "role_ids": []string{roleID}, "password": "AliceCrmPass1",
	})
	if status != 201 {
		t.Fatalf("provision account: %d %v", status, body)
	}
	accountID := env.str(body, "account_id")
	check := func(obj, act string) bool {
		t.Helper()
		status, body := env.doJSON("POST", "/api/v1/authz/check", alice, map[string]any{
			"app": "crmcz", "account_id": accountID, "obj": obj, "act": act,
		})
		if status != 200 {
			t.Fatalf("authz/check %s@%s: %d %v", obj, act, status, body)
		}
		return env.asMap(body)["allowed"] == true
	}

	// Granted tuple, then a DIFFERENT tuple whose legacy ':'-joined cache key
	// would be identical ("order:read:*" vs "order:read:*").
	if !check("order:read", "*") {
		t.Fatal("order:read@* must be allowed")
	}
	if check("order", "read:*") {
		t.Fatal("order@read:* must be denied on its own merits (legacy key would alias it to the cached allow)")
	}
}
