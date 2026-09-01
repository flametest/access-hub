package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/flametest/access-hub/internal/infra/social"
)

// fakeSocialProvider is a controllable social.Provider for integration tests:
// AuthCodeURL captures the state (needed to drive the callback), and Exchange
// hands out a canned profile for the code "good".
type fakeSocialProvider struct {
	id      string
	enabled bool
	profile *social.Profile
	called  int

	lastState string
}

func (f *fakeSocialProvider) ID() string    { return f.id }
func (f *fakeSocialProvider) Enabled() bool { return f.enabled }
func (f *fakeSocialProvider) AuthCodeURL(_ string, state string) string {
	f.lastState = state
	return "https://fake.provider/auth?state=" + state
}
func (f *fakeSocialProvider) Exchange(_ context.Context, code, _ string) (*social.Profile, error) {
	f.called++
	if code != "good" {
		return nil, errors.New("bad code")
	}
	return f.profile, nil
}

func newFakeSocial(id, email string, verified bool) *fakeSocialProvider {
	return &fakeSocialProvider{
		id:      id,
		enabled: true,
		profile: &social.Profile{
			ProviderUserID: id + "-user-1",
			Email:          email,
			EmailVerified:  verified,
			DisplayName:    strings.ToUpper(id[:1]) + id[1:] + " User",
		},
	}
}

// socialStart drives the start endpoint and returns the captured state.
func (e *oauthEnv) socialStart(provider, mode, token string) string {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		e.ts.URL+fmt.Sprintf("/api/v1/auth/social/%s/start?mode=%s&redirect=/workspaces", provider, mode), nil)
	if err != nil {
		e.t.Fatalf("start request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.noRedirectClient.Do(req)
	if err != nil {
		e.t.Fatalf("start: %v", err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || loc == "" {
		e.t.Fatalf("start: status=%d want 302 with Location", resp.StatusCode)
	}
	return loc
}

// socialCallback drives the provider callback and returns the redirect target.
func (e *oauthEnv) socialCallback(provider, code, state string) string {
	e.t.Helper()
	resp, err := e.noRedirectClient.Get(e.ts.URL + fmt.Sprintf("/api/v1/auth/social/%s/callback?code=%s&state=%s", provider, code, url.QueryEscape(state)))
	if err != nil {
		e.t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || loc == "" {
		e.t.Fatalf("callback: status=%d want 302 with Location", resp.StatusCode)
	}
	return loc
}

func locationParam(loc, key string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}

func TestSocialAutoRegisterAndCompleteOnce(t *testing.T) {
	env := newOAuthEnv(t)
	env.tc.CfgVal.Auth.AllowAutoRegister = true
	fp := newFakeSocial("fake", "newbie@fake.dev", true)
	env.tc.SocialVal["fake"] = fp

	loc := env.socialStart("fake", "login", "")
	state := locationParam(loc, "state")
	if state == "" {
		t.Fatalf("auth URL must carry state: %s", loc)
	}
	loc = env.socialCallback("fake", "good", state)
	loginCode := locationParam(loc, "login_code")
	if loginCode == "" {
		t.Fatalf("callback must redirect with login_code: %s", loc)
	}
	status, body := env.doJSON("POST", "/api/v1/auth/social/complete", "", map[string]any{"login_code": loginCode})
	if status != 200 {
		t.Fatalf("complete: %d %v", status, body)
	}
	token := env.str(body, "access_token")
	if token == "" {
		t.Fatalf("complete must return tokens: %v", body)
	}
	// The one-time code must not work twice.
	status, _ = env.doJSON("POST", "/api/v1/auth/social/complete", "", map[string]any{"login_code": loginCode})
	if status < 400 {
		t.Fatalf("complete must be one-time, got %d", status)
	}
	// Auto-provisioned identity: verified email, no password, one binding.
	status, body = env.doJSON("GET", "/api/v1/me", token, nil)
	if status != 200 || env.str(body, "email") != "newbie@fake.dev" {
		t.Fatalf("me: %d %v", status, body)
	}
	status, body = env.doJSON("GET", "/api/v1/me/social-identities", token, nil)
	if status != 200 || len(env.asList(body)) != 1 {
		t.Fatalf("social identities: %d %v", status, body)
	}
	_ = token
}

func TestSocialAutoRegisterOff(t *testing.T) {
	env := newOAuthEnv(t)
	env.tc.CfgVal.Auth.AllowAutoRegister = false
	fp := newFakeSocial("fake", "stranger@fake.dev", true)
	env.tc.SocialVal["fake"] = fp

	loc := env.socialStart("fake", "login", "")
	loc = env.socialCallback("fake", "good", fp.lastState)
	if got := locationParam(loc, "error"); got != "not_registered" {
		t.Fatalf("want error=not_registered, got %s", loc)
	}
}

func TestSocialVerifiedEmailMerge(t *testing.T) {
	env := newOAuthEnv(t)
	env.tc.CfgVal.Auth.AllowAutoRegister = false
	passwordToken := env.registerIdentity("ada", "ada@test.dev", "AdaPassw0rd")
	_ = passwordToken
	fp := newFakeSocial("fake", "ada@test.dev", true)
	env.tc.SocialVal["fake"] = fp

	loc := env.socialStart("fake", "login", "")
	loc = env.socialCallback("fake", "good", fp.lastState)
	status, body := env.doJSON("POST", "/api/v1/auth/social/complete", "", map[string]any{"login_code": locationParam(loc, "login_code")})
	if status != 200 {
		t.Fatalf("complete: %d %v", status, body)
	}
	status, body = env.doJSON("GET", "/api/v1/me", env.str(body, "access_token"), nil)
	if status != 200 || env.str(body, "username") != "ada" {
		t.Fatalf("social login must merge into the existing identity ada: %d %v", status, body)
	}
}

func TestSocialDisabledUserRejected(t *testing.T) {
	env := newOAuthEnv(t)
	env.tc.CfgVal.Auth.AllowAutoRegister = false
	env.registerIdentity("mallory", "mallory@test.dev", "MalloryPass1")
	fp := newFakeSocial("fake", "mallory@test.dev", true)
	env.tc.SocialVal["fake"] = fp
	// Disable the identity directly.
	user, err := env.tc.UserRepo().FindByEmail(context.Background(), "mallory@test.dev")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if err := env.tc.UserRepo().UpdateFields(context.Background(),
		user.Id, map[string]any{"status": "disabled"}); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	loc := env.socialStart("fake", "login", "")
	loc = env.socialCallback("fake", "good", fp.lastState)
	if got := locationParam(loc, "error"); got != "account_disabled" {
		t.Fatalf("want error=account_disabled, got %s", loc)
	}
}

func TestSocialLinkModeAndUnlinkGuard(t *testing.T) {
	env := newOAuthEnv(t)
	// Auto-register ON: the social login creates a passwordless identity, so
	// its single binding is the only sign-in method (unlink must 409).
	env.tc.CfgVal.Auth.AllowAutoRegister = true
	fp1 := newFakeSocial("fake", "linker@fake.dev", true)
	env.tc.SocialVal["fake"] = fp1
	loc := env.socialStart("fake", "login", "")
	loc = env.socialCallback("fake", "good", fp1.lastState)
	status, body := env.doJSON("POST", "/api/v1/auth/social/complete", "", map[string]any{"login_code": locationParam(loc, "login_code")})
	if status != 200 {
		t.Fatalf("complete: %d %v", status, body)
	}
	token := env.str(body, "access_token")

	status, body = env.doJSON("GET", "/api/v1/me/social-identities", token, nil)
	if status != 200 || len(env.asList(body)) != 1 {
		t.Fatalf("one binding expected: %d %v", status, body)
	}
	bindingID := env.str(env.asList(body)[0].(map[string]any), "id")
	status, body = env.doJSON("DELETE", "/api/v1/me/social-identities/"+bindingID, token, nil)
	if status != 409 {
		t.Fatalf("unlinking the last sign-in method must 409, got %d %v", status, body)
	}

	// Link a second provider (mode=link with the identity token), then the
	// first unlink succeeds.
	fp2 := newFakeSocial("fake2", "linker+2@fake.dev", true)
	env.tc.SocialVal["fake2"] = fp2
	loc = env.socialStart("fake2", "link", token)
	loc = env.socialCallback("fake2", "good", fp2.lastState)
	if locationParam(loc, "linked") != "1" {
		t.Fatalf("link mode must redirect with linked=1: %s", loc)
	}
	status, body = env.doJSON("GET", "/api/v1/me/social-identities", token, nil)
	if status != 200 || len(env.asList(body)) != 2 {
		t.Fatalf("two bindings expected: %d %v", status, body)
	}
	status, _ = env.doJSON("DELETE", "/api/v1/me/social-identities/"+bindingID, token, nil)
	if status != 200 {
		t.Fatalf("unlink with another method present must 200, got %d", status)
	}
}

func TestSocialCompleteRespectsMFA(t *testing.T) {
	env := newOAuthEnv(t)
	env.tc.CfgVal.Auth.AllowAutoRegister = false
	passwordToken := env.registerIdentity("totpuser", "totpuser@test.dev", "TotpPassw0rd")
	secret := enable2FA(t, env, passwordToken)

	fp := newFakeSocial("fake", "totpuser@test.dev", true)
	env.tc.SocialVal["fake"] = fp
	loc := env.socialStart("fake", "login", "")
	loc = env.socialCallback("fake", "good", fp.lastState)
	status, body := env.doJSON("POST", "/api/v1/auth/social/complete", "", map[string]any{"login_code": locationParam(loc, "login_code")})
	if status != 200 {
		t.Fatalf("complete: %d %v", status, body)
	}
	if env.str(body, "mfa_token") == "" {
		t.Fatalf("2FA-enabled user must get the login challenge: %v", body)
	}
	// Finish via the M4 login/2fa endpoint.
	status, body = env.doJSON("POST", "/api/v1/auth/login/2fa", "", map[string]any{
		"mfa_token": env.str(body, "mfa_token"),
		"code":      mustCode(t, secret),
	})
	if status != 200 || env.str(body, "access_token") == "" {
		t.Fatalf("login/2fa: %d %v", status, body)
	}
}

func TestSocialStateSingleUse(t *testing.T) {
	env := newOAuthEnv(t)
	env.tc.CfgVal.Auth.AllowAutoRegister = true
	fp := newFakeSocial("fake", "once@fake.dev", true)
	env.tc.SocialVal["fake"] = fp

	loc := env.socialStart("fake", "login", "")
	state := locationParam(loc, "state")
	_ = env.socialCallback("fake", "good", state)
	loc = env.socialCallback("fake", "good", state)
	if got := locationParam(loc, "error"); got != "invalid_state" {
		t.Fatalf("state reuse must fail with error=invalid_state, got %s", loc)
	}
}

// enable2FA enrolls and confirms TOTP through the API; returns the secret.
func enable2FA(t *testing.T, env *oauthEnv, identityToken string) string {
	t.Helper()
	status, body := env.doJSON("POST", "/api/v1/me/2fa/enroll", identityToken, nil)
	if status != 200 && status != 201 {
		t.Fatalf("2fa enroll: %d %v", status, body)
	}
	secret := env.str(body, "secret")
	if secret == "" {
		t.Fatalf("enroll returned no secret: %v", body)
	}
	status, body = env.doJSON("POST", "/api/v1/me/2fa/confirm", identityToken, map[string]any{"code": mustCode(t, secret)})
	if status != 200 {
		t.Fatalf("2fa confirm: %d %v", status, body)
	}
	return secret
}
