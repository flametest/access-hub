package social

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	log "github.com/flametest/vita/vlog"

	"github.com/flametest/access-hub/internal/config"
	"github.com/flametest/access-hub/internal/domain"
)

// newFakeOAuthServer spins up an httptest fake of a plain OAuth2 provider:
// POST /token answers a bearer token (asserting the authorization-code
// request shape), GET /userinfo answers the given JSON fixture.
func newFakeOAuthServer(t *testing.T, userinfo any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type = %q, want authorization_code", got)
			}
			if got := r.Form.Get("code"); got != "auth-code" {
				t.Errorf("code = %q, want auth-code", got)
			}
			if got := r.Form.Get("redirect_uri"); got != "https://app.test/cb" {
				t.Errorf("redirect_uri = %q, want https://app.test/cb", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfo)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestRegistry builds a registry whose google/microsoft/facebook providers
// carry test credentials and point their endpoints at the fake server.
func newTestRegistry(srv *httptest.Server) map[string]Provider {
	return NewRegistry(config.SocialConfig{
		Google:    config.GoogleConfig{ClientID: "google-id", ClientSecret: "google-secret"},
		Microsoft: config.MicrosoftConfig{ClientID: "ms-id", ClientSecret: "ms-secret"},
		Facebook:  config.FacebookConfig{ClientID: "fb-id", ClientSecret: "fb-secret"},
	}, WithEndpoints(Endpoints{
		GoogleAuthURL:        srv.URL + "/auth",
		GoogleTokenURL:       srv.URL + "/token",
		GoogleUserinfoURL:    srv.URL + "/userinfo",
		MicrosoftAuthURL:     srv.URL + "/auth",
		MicrosoftTokenURL:    srv.URL + "/token",
		MicrosoftUserinfoURL: srv.URL + "/userinfo",
		FacebookAuthURL:      srv.URL + "/auth",
		FacebookTokenURL:     srv.URL + "/token",
		FacebookMeURL:        srv.URL + "/userinfo",
	}))
}

const testRedirectURI = "https://app.test/cb"

func exchangeFor(t *testing.T, reg map[string]Provider, providerID string) *Profile {
	t.Helper()
	profile, err := reg[providerID].Exchange(context.Background(), "auth-code", testRedirectURI)
	if err != nil {
		t.Fatalf("%s exchange: %v", providerID, err)
	}
	return profile
}

// assertAuthCodeURL checks the provider authorization URL carries the client
// id, redirect URI, state and a non-empty scope.
func assertAuthCodeURL(t *testing.T, p Provider, providerID string) {
	t.Helper()
	raw := p.AuthCodeURL(testRedirectURI, "st-123")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s auth url: %v", providerID, err)
	}
	q := u.Query()
	if q.Get("client_id") == "" || q.Get("state") != "st-123" || q.Get("redirect_uri") != testRedirectURI {
		t.Fatalf("%s auth url = %q (query %v)", providerID, raw, q)
	}
	if q.Get("scope") == "" {
		t.Fatalf("%s auth url must request scopes: %q", providerID, raw)
	}
}

func TestGoogleExchange(t *testing.T) {
	srv := newFakeOAuthServer(t, map[string]any{
		"sub": "g-123", "email": "User@Example.com", "email_verified": true,
		"name": "Google User", "picture": "https://photos.example.com/g.png",
	})
	reg := newTestRegistry(srv)
	p := reg[domain.SocialProviderGoogle]
	assertAuthCodeURL(t, p, domain.SocialProviderGoogle)

	profile := exchangeFor(t, reg, domain.SocialProviderGoogle)
	if profile.ProviderUserID != "g-123" || profile.Email != "User@Example.com" ||
		!profile.EmailVerified || profile.DisplayName != "Google User" ||
		profile.AvatarURL != "https://photos.example.com/g.png" {
		t.Fatalf("google profile = %+v", profile)
	}
	if profile.Raw["sub"] != "g-123" {
		t.Fatalf("raw payload not kept: %v", profile.Raw)
	}
}

func TestGoogleUnverifiedEmail(t *testing.T) {
	srv := newFakeOAuthServer(t, map[string]any{
		"sub": "g-124", "email": "unverified@example.com", "email_verified": false,
	})
	reg := newTestRegistry(srv)
	profile := exchangeFor(t, reg, domain.SocialProviderGoogle)
	if profile.EmailVerified {
		t.Fatalf("email_verified=false must not flip: %+v", profile)
	}
}

func TestMicrosoftExchange(t *testing.T) {
	// Preferred-username (UPN) fallback + tenant-implied verification.
	srv := newFakeOAuthServer(t, map[string]any{
		"sub": "ms-1", "email": "", "preferred_username": "user@tenant.example.com",
		"name": "MS User",
	})
	reg := newTestRegistry(srv)
	profile := exchangeFor(t, reg, domain.SocialProviderMicrosoft)
	if profile.ProviderUserID != "ms-1" || profile.Email != "user@tenant.example.com" || !profile.EmailVerified {
		t.Fatalf("microsoft profile = %+v", profile)
	}

	// An explicit email_verified=false wins over the tenant-implied one.
	srv2 := newFakeOAuthServer(t, map[string]any{
		"sub": "ms-2", "email": "ms@example.com", "email_verified": false,
	})
	reg2 := newTestRegistry(srv2)
	profile = exchangeFor(t, reg2, domain.SocialProviderMicrosoft)
	if profile.Email != "ms@example.com" || profile.EmailVerified {
		t.Fatalf("microsoft profile (explicit unverified) = %+v", profile)
	}
}

func TestFacebookExchange(t *testing.T) {
	srv := newFakeOAuthServer(t, map[string]any{
		"id": "fb-1", "name": "FB User", "email": "fb@example.com",
		"picture": map[string]any{"data": map[string]any{"url": "https://graph.facebook.com/fb-1/picture.jpg"}},
	})
	reg := newTestRegistry(srv)
	assertAuthCodeURL(t, reg[domain.SocialProviderFacebook], domain.SocialProviderFacebook)

	profile := exchangeFor(t, reg, domain.SocialProviderFacebook)
	if profile.ProviderUserID != "fb-1" || profile.Email != "fb@example.com" ||
		!profile.EmailVerified || profile.DisplayName != "FB User" {
		t.Fatalf("facebook profile = %+v", profile)
	}
	if profile.AvatarURL != "https://graph.facebook.com/fb-1/picture.jpg" {
		t.Fatalf("facebook picture.data.url not resolved: %+v", profile)
	}
	if profile.Raw["picture"] == nil {
		t.Fatalf("raw facebook payload not kept: %v", profile.Raw)
	}
}

func TestFacebookUnverifiedEmail(t *testing.T) {
	// No email in the payload: the platform-verified shortcut must not mark
	// the (absent) address as verified.
	srv := newFakeOAuthServer(t, map[string]any{"id": "fb-2", "name": "No Email"})
	reg := newTestRegistry(srv)
	profile := exchangeFor(t, reg, domain.SocialProviderFacebook)
	if profile.Email != "" || profile.EmailVerified {
		t.Fatalf("facebook profile without email = %+v", profile)
	}
}

func TestExchangeProfileFailure(t *testing.T) {
	// A 500 from the userinfo endpoint must surface as an exchange error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "x", "token_type": "Bearer"})
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	reg := newTestRegistry(srv)
	if _, err := reg[domain.SocialProviderGoogle].Exchange(context.Background(), "auth-code", testRedirectURI); err == nil {
		t.Fatal("userinfo 500 must fail the exchange")
	}
}

func TestDisabledProviders(t *testing.T) {
	// Without credentials every provider stays registered but disabled (the
	// start/callback routes answer 404 for them).
	reg := NewRegistry(config.SocialConfig{})
	for _, id := range []string{
		domain.SocialProviderGoogle, domain.SocialProviderMicrosoft,
		domain.SocialProviderFacebook, domain.SocialProviderApple,
	} {
		p, ok := reg[id]
		if !ok {
			t.Fatalf("provider %s missing from the registry", id)
		}
		if p.Enabled() {
			t.Fatalf("provider %s must be disabled without credentials", id)
		}
	}
	if got := reg[domain.SocialProviderApple].ID(); got != domain.SocialProviderApple {
		t.Fatalf("apple provider id = %q", got)
	}
	if !strings.Contains(reg[domain.SocialProviderApple].AuthCodeURL("https://app.test/cb", "st"), "response_mode=form_post") {
		t.Fatal("apple auth url must use response_mode=form_post")
	}
}

// TestMain initializes the package-level logger; vlog's default logger is
// nil until InitLogger runs, and the provider code logs warnings on
// misconfiguration (e.g. a missing Apple .p8 key).
func TestMain(m *testing.M) {
	log.InitLogger(log.ZerologType, "access-hub-social-test", log.DebugLevel)
	os.Exit(m.Run())
}
