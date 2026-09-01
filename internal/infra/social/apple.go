// Apple provider (design.md §12 M5). Sign in with Apple deviates from the
// plain OAuth2 providers:
//   - the authorization request uses response_mode=form_post with
//     response_type "code id_token" (no PKCE — the id_token IS the proof);
//   - the client_secret posted to the token endpoint is an ES256 JWT minted
//     at request time from the .p8 (PKCS#8 EC) key of the team;
//   - the id_token is an RS256 JWT signed with Apple's keys, verified against
//     the JWKS document (cached with a TTL).
package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/flametest/access-hub/internal/config"
	log "github.com/flametest/vita/vlog"
	"github.com/golang-jwt/jwt/v5"
)

// appleIssuer is the iss claim of every Apple id_token and the aud of the
// client_secret JWT.
const appleIssuer = "https://appleid.apple.com"

// appleClientSecretTTL bounds the minted client_secret (spec allows <= 6mo).
const appleClientSecretTTL = time.Hour

// appleProvider implements Provider for Sign in with Apple.
type appleProvider struct {
	cfg        config.AppleConfig
	authURL    string
	tokenURL   string
	jwksURL    string
	privateKey *ecdsa.PrivateKey
	jwks       *jwksCache
	httpClient *http.Client
}

// newAppleProvider builds the Apple provider. When the .p8 key cannot be
// loaded the provider stays present but disabled (a warning is logged so the
// misconfiguration is visible).
func newAppleProvider(cfg config.AppleConfig, e Endpoints) *appleProvider {
	p := &appleProvider{
		cfg:        cfg,
		authURL:    or(e.AppleAuthURL, "https://appleid.apple.com/auth/authorize"),
		tokenURL:   or(e.AppleTokenURL, "https://appleid.apple.com/auth/token"),
		jwksURL:    or(e.AppleJWKSURL, "https://appleid.apple.com/auth/keys"),
		jwks:       newJWKSCache(or(e.AppleJWKSURL, "https://appleid.apple.com/auth/keys")),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
	if cfg.ServicesID == "" || cfg.TeamID == "" || cfg.KeyID == "" || cfg.PrivateKeyPath == "" {
		return p // disabled (missing credentials)
	}
	key, err := loadECPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		log.Warn().Any("error", err).Msg("apple social login disabled: cannot load the .p8 private key")
		return p
	}
	p.privateKey = key
	return p
}

func (p *appleProvider) ID() string { return "apple" }

// Enabled requires the full credential set AND a loadable private key.
func (p *appleProvider) Enabled() bool {
	return p.privateKey != nil &&
		p.cfg.ServicesID != "" && p.cfg.TeamID != "" && p.cfg.KeyID != ""
}

// AuthCodeURL builds the Apple authorization URL. Apple requires
// form_post + "code id_token" + scope "name email" (no PKCE).
func (p *appleProvider) AuthCodeURL(redirectURI, state string) string {
	v := url.Values{}
	v.Set("client_id", p.cfg.ServicesID)
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	return p.authURL + "?response_mode=form_post&response_type=code%20id_token&scope=name%20email&" + v.Encode()
}

// Exchange swaps the authorization code for an id_token via the Apple token
// endpoint (client_secret = freshly minted ES256 JWT) and verifies it.
func (p *appleProvider) Exchange(ctx context.Context, code, redirectURI string) (*Profile, error) {
	return p.exchangeIDToken(ctx, code, redirectURI, nil)
}

// ExchangeForm handles the form_post callback: the id_token may be POSTed
// directly (response_type includes id_token) or only the code arrives. The
// `user` form field (first authorization only) carries the display name.
func (p *appleProvider) ExchangeForm(ctx context.Context, form Form, redirectURI string) (*Profile, error) {
	return p.exchangeIDToken(ctx, form.Get("code"), redirectURI, form)
}

func (p *appleProvider) exchangeIDToken(ctx context.Context, code, redirectURI string, form Form) (*Profile, error) {
	rawIDToken := ""
	if form != nil {
		rawIDToken = strings.TrimSpace(form.Get("id_token"))
	}
	if rawIDToken == "" {
		if strings.TrimSpace(code) == "" {
			return nil, fmt.Errorf("apple callback carried neither id_token nor code")
		}
		token, err := p.tokenExchange(ctx, code, redirectURI)
		if err != nil {
			return nil, err
		}
		rawIDToken = token
	}
	claims, err := p.verifyIDToken(rawIDToken)
	if err != nil {
		return nil, err
	}
	profile := &Profile{
		ProviderUserID: claims.Subject,
		Email:          strings.TrimSpace(claims.Email),
		EmailVerified:  flexibleBool(claims.EmailVerified),
	}
	if form != nil {
		mergeAppleUser(profile, form.Get("user"))
	}
	return profile, nil
}

// tokenExchange POSTs the authorization code to the Apple token endpoint and
// returns the embedded id_token.
func (p *appleProvider) tokenExchange(ctx context.Context, code, redirectURI string) (string, error) {
	secret, err := p.mintClientSecret(timeNow())
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", p.cfg.ServicesID)
	form.Set("client_secret", secret)
	form.Set("redirect_uri", redirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build apple token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("apple token endpoint: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read apple token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("apple token endpoint: status %d: %s", resp.StatusCode, truncateForLog(raw))
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.IDToken == "" {
		return "", fmt.Errorf("apple token endpoint returned no id_token")
	}
	return body.IDToken, nil
}

// mintClientSecret signs the ES256 client_secret JWT: header kid=KeyID,
// alg=ES256; claims iss=TeamID, sub=ServicesID, aud=appleid.apple.com,
// iat=now, exp=now+1h.
func (p *appleProvider) mintClientSecret(now time.Time) (string, error) {
	if p.privateKey == nil {
		return "", fmt.Errorf("apple private key not loaded")
	}
	claims := jwt.MapClaims{
		"iss": p.cfg.TeamID,
		"sub": p.cfg.ServicesID,
		"aud": appleIssuer,
		"iat": now.Unix(),
		"exp": now.Add(appleClientSecretTTL).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.cfg.KeyID
	signed, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign apple client_secret: %w", err)
	}
	return signed, nil
}

// appleIDTokenClaims are the verified id_token claims.
type appleIDTokenClaims struct {
	jwt.RegisteredClaims
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"` // bool or string in the wild
}

// verifyIDToken validates an Apple id_token: RS256 only, kid resolved
// against the (cached) JWKS, iss/aud/exp enforced.
func (p *appleProvider) verifyIDToken(raw string) (*appleIDTokenClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(appleIssuer),
		jwt.WithAudience(p.cfg.ServicesID),
		jwt.WithExpirationRequired(),
	)
	var claims appleIDTokenClaims
	if _, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return p.jwks.publicKey(kid)
	}); err != nil {
		return nil, fmt.Errorf("verify apple id_token: %w", err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("apple id_token has no sub claim")
	}
	return &claims, nil
}

// appleUserForm is the `user` form field Apple posts on FIRST authorization.
type appleUserForm struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
	Email string `json:"email"`
}

// mergeAppleUser folds the form `user` payload into the profile (best
// effort: the name only ever arrives once).
func mergeAppleUser(profile *Profile, raw string) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	var u appleUserForm
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		return
	}
	name := strings.TrimSpace(strings.TrimSpace(u.Name.FirstName) + " " + strings.TrimSpace(u.Name.LastName))
	if name != "" {
		profile.DisplayName = name
	}
	if profile.Email == "" && u.Email != "" {
		profile.Email = strings.TrimSpace(u.Email)
	}
}

// flexibleBool decodes email_verified, which Apple serializes as a bool or
// a string ("true"/"1"). Absent counts as false.
func flexibleBool(raw json.RawMessage) bool {
	v := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	return v == "true" || v == "1"
}

// loadECPrivateKey reads a .p8 (PKCS#8 PEM) Sign in with Apple key.
func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read apple .p8 key %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("apple .p8 key %s: no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse apple .p8 key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("apple .p8 key is %T, want EC private key", parsed)
	}
	return key, nil
}

// ---------- JWKS cache ----------

// jwksTTL bounds the cached Apple JWKS document.
const jwksTTL = time.Hour

// jwksCache caches Apple's RSA signing keys with a TTL. An unknown kid
// forces one synchronous refresh (Apple rotates keys).
type jwksCache struct {
	mu        sync.Mutex
	url       string
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{url: url}
}

// publicKey resolves a kid to its RSA key, refreshing the cache when stale
// or when the kid is unknown.
func (c *jwksCache) publicKey(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil && time.Since(c.fetchedAt) < jwksTTL {
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
	}
	if err := c.refreshLocked(); err != nil {
		return nil, err
	}
	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("apple jwks has no key %q", kid)
	}
	return key, nil
}

func (c *jwksCache) refreshLocked() error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetch apple jwks: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read apple jwks: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch apple jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("decode apple jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		key, err := rsaKeyFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = key
	}
	if len(keys) == 0 {
		return fmt.Errorf("apple jwks %s has no usable rsa keys", c.url)
	}
	c.keys = keys
	c.fetchedAt = timeNow()
	return nil
}

// rsaKeyFromJWK rebuilds an RSA public key from the base64url n/e components.
func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode rsa modulus: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode rsa exponent: %w", err)
	}
	eInt := new(big.Int).SetBytes(e)
	if !eInt.IsInt64() || eInt.Int64() <= 0 || eInt.Int64() > 0xFFFFFFFF {
		return nil, fmt.Errorf("rsa exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}, nil
}
