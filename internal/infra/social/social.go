// Package social implements the social sign-in providers of design.md §12 M5:
// Google, Microsoft and Facebook on top of golang.org/x/oauth2, Apple with its
// form_post + ES256 client_secret flavor. Every provider URL is injectable
// through Endpoints so tests can point the whole package at a local
// httptest fake.
package social

import (
	"context"
	"encoding/base64"
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
	// EmailMergeAllowed gates the verified-email auto-merge in
	// resolveSocialUser (binding this profile to an EXISTING access-hub
	// account). It is deliberately stricter than EmailVerified: auto-register
	// only creates a fresh account under the claimed address, while a merge
	// hands over an existing one, so it requires the provider to vouch the
	// exact address on the wire (an explicit verification claim, or
	// Microsoft's xms_edov domain-ownership signal). Presence-only trust
	// (Facebook) and admin-settable claims (Microsoft mail/UPN) never
	// qualify. Invariant: EmailMergeAllowed implies EmailVerified.
	EmailMergeAllowed bool
	DisplayName       string
	AvatarURL         string
	// Raw is the untouched provider payload (kept for identities.raw_profile).
	Raw map[string]any
}

// Provider is one social login provider.
type Provider interface {
	ID() string
	// Enabled reports whether the provider has usable credentials configured.
	Enabled() bool
	// AuthCodeURL builds the provider authorization URL for the given
	// redirect URI (the registered callback), state and OIDC nonce ("" =
	// none; Apple echoes it in the id_token so the exchange can detect
	// replays).
	AuthCodeURL(redirectURI, state, nonce string) string
	// Exchange converts an authorization code into the provider profile.
	Exchange(ctx context.Context, code, redirectURI string) (*Profile, error)
}

// FormExchanger is implemented by providers whose callback posts extra form
// fields (Apple form_post: code + id_token + user). form carries the raw
// POSTed values; redirectURI is the registered callback URL; nonce is the
// OIDC nonce from the start request (verified against the id_token).
type FormExchanger interface {
	ExchangeForm(ctx context.Context, form Form, redirectURI, nonce string) (*Profile, error)
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
			id:           domain.SocialProviderGoogle,
			clientID:     cfg.Google.ClientID,
			clientSecret: cfg.Google.ClientSecret,
			authURL:      or(e.GoogleAuthURL, googleAuthURL),
			tokenURL:     or(e.GoogleTokenURL, googleTokenURL),
			userinfoURL:  or(e.GoogleUserinfoURL, googleUserinfoURL),
			scopes:       []string{"openid", "email", "profile"},
			parse:        parseGoogleProfile,
		}),
		domain.SocialProviderMicrosoft: newOAuthProvider(oauthSpec{
			id:           domain.SocialProviderMicrosoft,
			clientID:     cfg.Microsoft.ClientID,
			clientSecret: cfg.Microsoft.ClientSecret,
			authURL:      or(e.MicrosoftAuthURL, fmt.Sprintf(microsoftAuthURLTemplate, tenant)),
			tokenURL:     or(e.MicrosoftTokenURL, fmt.Sprintf(microsoftTokenURLTemplate, tenant)),
			userinfoURL:  or(e.MicrosoftUserinfoURL, microsoftUserinfoURL),
			scopes:       []string{"openid", "email", "profile"},
			parse:        parseMicrosoftProfile,
		}),
		domain.SocialProviderFacebook: newOAuthProvider(oauthSpec{
			id:           domain.SocialProviderFacebook,
			clientID:     cfg.Facebook.ClientID,
			clientSecret: cfg.Facebook.ClientSecret,
			authURL:      or(e.FacebookAuthURL, facebookAuthURL),
			tokenURL:     or(e.FacebookTokenURL, facebookTokenURL),
			userinfoURL:  or(e.FacebookMeURL, facebookMeURL),
			scopes:       []string{"email,public_profile"},
			parse:        parseFacebookProfile,
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
	// parse receives the userinfo payload plus the token endpoint response
	// (providers may consult its id_token claims, e.g. Microsoft xms_edov).
	parse func(raw []byte, tok *oauth2.Token) (*Profile, error)
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

func (p *oauthProvider) AuthCodeURL(redirectURI, state, _ string) string {
	// The plain providers carry no verifiable id_token in this flow, so the
	// nonce has no replay value here and stays off the URL.
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
	return p.spec.parse(raw, tok)
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

func parseGoogleProfile(raw []byte, _ *oauth2.Token) (*Profile, error) {
	var body openidBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode google profile: %w", err)
	}
	if body.Sub == "" {
		return nil, fmt.Errorf("google profile has no sub claim")
	}
	// Google always emits email_verified and verifies every address it
	// returns (gmail accounts at signup, workspace domains at tenant setup),
	// so the claim backs both auto-register and the merge.
	verified := false
	if body.EmailVerified != nil {
		verified = *body.EmailVerified
	}
	return newProfile(body.Sub, body.Email, verified, verified, body.Name, body.Picture, raw), nil
}

// microsoftIDTokenClaims is the subset of the Entra id_token claims used for
// the nOAuth mitigations (Descope, 2023): xms_edov vouches that the issuer
// tenant DNS-verified the domain of its own email claim.
type microsoftIDTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	XmsEdov       bool   `json:"xms_edov"`
}

func parseMicrosoftProfile(raw []byte, tok *oauth2.Token) (*Profile, error) {
	var body openidBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode microsoft profile: %w", err)
	}
	if body.Sub == "" {
		return nil, fmt.Errorf("microsoft profile has no sub claim")
	}
	email := body.Email
	upnFallback := false
	// Some tenants expose the address only as preferred_username (UPN). The
	// UPN is an admin-settable login name, not an address the tenant verified:
	// keep it for display, but it must never confirm itself (a tenant admin
	// can freely point it at someone else's address).
	if email == "" && strings.Contains(body.PreferredUsername, "@") {
		email = body.PreferredUsername
		upnFallback = true
	}
	// Only explicit wire claims count as verification. Mere presence of an
	// address does not: with tenant=common any Entra tenant can authenticate,
	// and its admin can set mail on their users to a victim's address — the
	// nOAuth account-takeover pattern.
	verified := false
	if body.EmailVerified != nil && !upnFallback {
		verified = *body.EmailVerified
	}
	// xms_edov (id_token) re-opens the merge when it vouches for the exact
	// address in use; the id_token comes straight from the token endpoint
	// over TLS (code flow, confidential client — OIDC §3.1.3.7 allows
	// reading its claims without re-verifying the JWS, unlike Apple's
	// browser-borne form_post token which IS verified).
	if claims, ok := decodeIDTokenClaims(tok); ok {
		if claims.XmsEdov && strings.EqualFold(strings.TrimSpace(claims.Email), email) {
			verified = true
		}
		if claims.EmailVerified != nil && *claims.EmailVerified && !upnFallback {
			verified = true
		}
	}
	return newProfile(body.Sub, email, verified, verified, body.Name, body.Picture, raw), nil
}

func parseFacebookProfile(raw []byte, _ *oauth2.Token) (*Profile, error) {
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
	// Facebook emails are account-verified by the platform (unverified or
	// missing addresses are omitted from the response), so presence implies
	// verified for auto-register. But no verification claim travels on the
	// wire, so the address is never trusted for the auto-merge into an
	// existing account — those bindings are made via explicit link only.
	verified := body.Email != ""
	return newProfile(body.ID, body.Email, verified, false, body.Name, body.Picture.Data.URL, raw), nil
}

// decodeIDTokenClaims extracts the payload claims of the id_token returned
// directly by the token endpoint ("" / absent when the provider did not send
// one).
func decodeIDTokenClaims(tok *oauth2.Token) (*microsoftIDTokenClaims, bool) {
	if tok == nil {
		return nil, false
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, false
	}
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	claims := &microsoftIDTokenClaims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, false
	}
	return claims, true
}

// newProfile assembles a Profile and keeps the raw payload as a map.
// emailMergeAllowed must imply emailVerified (see Profile.EmailMergeAllowed).
func newProfile(providerUserID, email string, emailVerified, emailMergeAllowed bool, displayName, avatarURL string, raw []byte) *Profile {
	p := &Profile{
		ProviderUserID:    providerUserID,
		Email:             strings.TrimSpace(email),
		EmailVerified:     emailVerified,
		EmailMergeAllowed: emailMergeAllowed,
		DisplayName:       displayName,
		AvatarURL:         avatarURL,
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
