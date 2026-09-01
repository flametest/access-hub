// Package social implements the social sign-in providers of design.md §12 M5:
// Google, Microsoft and Facebook on top of golang.org/x/oauth2, Apple with its
// form_post + ES256 client_secret flavor. Every provider URL is injectable
// through Endpoints so tests can point the whole package at a local
// httptest fake.
package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/config"
	"github.com/flametest/access-hub/internal/domain"
	"golang.org/x/oauth2"
)

// Profile is the normalized provider view of a social user.
type Profile struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	DisplayName    string
	AvatarURL      string
	// Raw is the untouched provider payload (kept for identities.raw_profile).
	Raw map[string]any
}

// Provider is one social login provider.
type Provider interface {
	ID() string
	// Enabled reports whether the provider has usable credentials configured.
	Enabled() bool
	// AuthCodeURL builds the provider authorization URL for the given
	// redirect URI (the registered callback) and state.
	AuthCodeURL(redirectURI, state string) string
	// Exchange converts an authorization code into the provider profile.
	Exchange(ctx context.Context, code, redirectURI string) (*Profile, error)
}

// FormExchanger is implemented by providers whose callback posts extra form
// fields (Apple form_post: code + id_token + user). form carries the raw
// POSTed values; redirectURI is the registered callback URL.
type FormExchanger interface {
	ExchangeForm(ctx context.Context, form Form, redirectURI string) (*Profile, error)
}

// Form is the callback form payload (POSTed by form_post providers).
type Form map[string]string

// Get returns the first value for key ("" when absent).
func (f Form) Get(key string) string { return f[key] }

// Endpoints overrides provider endpoint URLs (test hook). Empty entries fall
// back to the production defaults.
type Endpoints struct {
	GoogleAuthURL     string
	GoogleTokenURL    string
	GoogleUserinfoURL string

	MicrosoftAuthURL     string
	MicrosoftTokenURL    string
	MicrosoftUserinfoURL string

	FacebookAuthURL  string
	FacebookTokenURL string
	FacebookMeURL    string

	AppleAuthURL  string
	AppleTokenURL string
	AppleJWKSURL  string
}

// Option customizes the registry construction.
type Option func(*Endpoints)

// WithEndpoints overrides provider endpoint URLs (tests).
func WithEndpoints(e Endpoints) Option {
	return func(dst *Endpoints) {
		if e.GoogleAuthURL != "" {
			dst.GoogleAuthURL = e.GoogleAuthURL
		}
		if e.GoogleTokenURL != "" {
			dst.GoogleTokenURL = e.GoogleTokenURL
		}
		if e.GoogleUserinfoURL != "" {
			dst.GoogleUserinfoURL = e.GoogleUserinfoURL
		}
		if e.MicrosoftAuthURL != "" {
			dst.MicrosoftAuthURL = e.MicrosoftAuthURL
		}
		if e.MicrosoftTokenURL != "" {
			dst.MicrosoftTokenURL = e.MicrosoftTokenURL
		}
		if e.MicrosoftUserinfoURL != "" {
			dst.MicrosoftUserinfoURL = e.MicrosoftUserinfoURL
		}
		if e.FacebookAuthURL != "" {
			dst.FacebookAuthURL = e.FacebookAuthURL
		}
		if e.FacebookTokenURL != "" {
			dst.FacebookTokenURL = e.FacebookTokenURL
		}
		if e.FacebookMeURL != "" {
			dst.FacebookMeURL = e.FacebookMeURL
		}
		if e.AppleAuthURL != "" {
			dst.AppleAuthURL = e.AppleAuthURL
		}
		if e.AppleTokenURL != "" {
			dst.AppleTokenURL = e.AppleTokenURL
		}
		if e.AppleJWKSURL != "" {
			dst.AppleJWKSURL = e.AppleJWKSURL
		}
	}
}

// Production endpoints (design.md §12 M5).
const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

	microsoftAuthURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	microsoftTokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	microsoftUserinfoURL      = "https://graph.microsoft.com/oidc/userinfo"

	facebookAuthURL  = "https://www.facebook.com/v19.0/dialog/oauth"
	facebookTokenURL = "https://graph.facebook.com/v19.0/oauth/access_token"
	facebookMeURL    = "https://graph.facebook.com/v19.0/me?fields=id,name,email,picture.type(large)"
)

// or returns the override when non-empty, the default otherwise.
func or(override, def string) string {
	if override != "" {
		return override
	}
	return def
}

// NewRegistry builds the social provider registry from the global yaml
// credentials. Providers without credentials are still present but report
// Enabled()==false (start/callback answer 404 for them).
func NewRegistry(cfg config.SocialConfig, opts ...Option) map[string]Provider {
	var e Endpoints
	for _, opt := range opts {
		opt(&e)
	}
	tenant := strings.TrimSpace(cfg.Microsoft.Tenant)
	if tenant == "" {
		tenant = "common"
	}
	out := map[string]Provider{
		domain.SocialProviderGoogle: newOAuthProvider(oauthSpec{
			id:          domain.SocialProviderGoogle,
			clientID:    cfg.Google.ClientID,
			clientSecret: cfg.Google.ClientSecret,
			authURL:     or(e.GoogleAuthURL, googleAuthURL),
			tokenURL:    or(e.GoogleTokenURL, googleTokenURL),
			userinfoURL: or(e.GoogleUserinfoURL, googleUserinfoURL),
			scopes:      []string{"openid", "email", "profile"},
			parse:       parseGoogleProfile,
		}),
		domain.SocialProviderMicrosoft: newOAuthProvider(oauthSpec{
			id:          domain.SocialProviderMicrosoft,
			clientID:    cfg.Microsoft.ClientID,
			clientSecret: cfg.Microsoft.ClientSecret,
			authURL: or(e.MicrosoftAuthURL, fmt.Sprintf(microsoftAuthURLTemplate, tenant)),
			tokenURL: or(e.MicrosoftTokenURL, fmt.Sprintf(microsoftTokenURLTemplate, tenant)),
			userinfoURL: or(e.MicrosoftUserinfoURL, microsoftUserinfoURL),
			scopes:      []string{"openid", "email", "profile"},
			parse:       parseMicrosoftProfile,
		}),
		domain.SocialProviderFacebook: newOAuthProvider(oauthSpec{
			id:          domain.SocialProviderFacebook,
			clientID:    cfg.Facebook.ClientID,
			clientSecret: cfg.Facebook.ClientSecret,
			authURL:     or(e.FacebookAuthURL, facebookAuthURL),
			tokenURL:    or(e.FacebookTokenURL, facebookTokenURL),
			userinfoURL: or(e.FacebookMeURL, facebookMeURL),
			scopes:      []string{"email,public_profile"},
			parse:       parseFacebookProfile,
		}),
		domain.SocialProviderApple: newAppleProvider(cfg.Apple, e),
	}
	return out
}

// ---------- google / microsoft / facebook (x/oauth2) ----------

// oauthSpec is the construction input of an x/oauth2 backed provider.
type oauthSpec struct {
	id, clientID, clientSecret string
	authURL, tokenURL          string
	userinfoURL                string
	scopes                     []string
	parse                      func(raw []byte) (*Profile, error)
}

// oauthProvider implements Provider for the three plain OAuth2 providers.
type oauthProvider struct {
	spec oauthSpec
}

func newOAuthProvider(spec oauthSpec) *oauthProvider {
	return &oauthProvider{spec: spec}
}

func (p *oauthProvider) ID() string { return p.spec.id }

// Enabled requires both client credentials (config.go convention).
func (p *oauthProvider) Enabled() bool {
	return p.spec.clientID != "" && p.spec.clientSecret != ""
}

func (p *oauthProvider) config(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.spec.clientID,
		ClientSecret: p.spec.clientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: p.spec.authURL, TokenURL: p.spec.tokenURL},
		RedirectURL:  redirectURI,
		Scopes:       p.spec.scopes,
	}
}

func (p *oauthProvider) AuthCodeURL(redirectURI, state string) string {
	return p.config(redirectURI).AuthCodeURL(state)
}

// Exchange swaps the authorization code for an access token, then fetches the
// provider profile with the authenticated client.
func (p *oauthProvider) Exchange(ctx context.Context, code, redirectURI string) (*Profile, error) {
	cfg := p.config(redirectURI)
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oauth2 exchange: %w", err)
	}
	resp, err := cfg.Client(ctx, tok).Get(p.spec.userinfoURL)
	if err != nil {
		return nil, fmt.Errorf("fetch profile: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch profile: status %d: %s", resp.StatusCode, truncateForLog(raw))
	}
	return p.spec.parse(raw)
}

// openidBody is the shared OIDC userinfo shape (google / microsoft).
type openidBody struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	PreferredUsername string `json:"preferred_username"`
}

func parseGoogleProfile(raw []byte) (*Profile, error) {
	var body openidBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode google profile: %w", err)
	}
	if body.Sub == "" {
		return nil, fmt.Errorf("google profile has no sub claim")
	}
	verified := false
	if body.EmailVerified != nil {
		verified = *body.EmailVerified
	}
	return newProfile(body.Sub, body.Email, verified, body.Name, body.Picture, raw), nil
}

func parseMicrosoftProfile(raw []byte) (*Profile, error) {
	var body openidBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode microsoft profile: %w", err)
	}
	if body.Sub == "" {
		return nil, fmt.Errorf("microsoft profile has no sub claim")
	}
	email := body.Email
	// Some tenants expose the address only as preferred_username (UPN).
	if email == "" && strings.Contains(body.PreferredUsername, "@") {
		email = body.PreferredUsername
	}
	// Microsoft omits email_verified on several tenants; a returned address
	// is an account-verified one there.
	verified := email != ""
	if body.EmailVerified != nil {
		verified = *body.EmailVerified
	}
	return newProfile(body.Sub, email, verified, body.Name, body.Picture, raw), nil
}

func parseFacebookProfile(raw []byte) (*Profile, error) {
	var body struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode facebook profile: %w", err)
	}
	if body.ID == "" {
		return nil, fmt.Errorf("facebook profile has no id")
	}
	// Facebook emails are account-verified by the platform.
	return newProfile(body.ID, body.Email, body.Email != "", body.Name, body.Picture.Data.URL, raw), nil
}

// newProfile assembles a Profile and keeps the raw payload as a map.
func newProfile(providerUserID, email string, emailVerified bool, displayName, avatarURL string, raw []byte) *Profile {
	p := &Profile{
		ProviderUserID: providerUserID,
		Email:          strings.TrimSpace(email),
		EmailVerified:  emailVerified,
		DisplayName:    displayName,
		AvatarURL:      avatarURL,
	}
	_ = json.Unmarshal(raw, &p.Raw)
	return p
}

// truncateForLog bounds an error body snippet.
func truncateForLog(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 256 {
		s = s[:256] + "..."
	}
	return s
}

// timeNow is the clock hook (tests).
var timeNow = time.Now
