package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flametest/access-hub/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

// writeP8 generates an EC P-256 key and writes it as a PKCS#8 PEM file
// (the .p8 shape of a Sign in with Apple key), returning the key and path.
func writeP8(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "apple.p8")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write .p8: %v", err)
	}
	return key, path
}

// newTestAppleProvider builds an Apple provider from a generated .p8 (full
// credential set => enabled).
func newTestAppleProvider(t *testing.T) (*appleProvider, *ecdsa.PrivateKey) {
	t.Helper()
	key, p8Path := writeP8(t)
	cfg := config.AppleConfig{
		ServicesID:     "com.example.portal",
		TeamID:         "TEAM1234",
		KeyID:          "KEY1234",
		PrivateKeyPath: p8Path,
	}
	p := newAppleProvider(cfg, Endpoints{})
	if !p.Enabled() {
		t.Fatal("apple provider must be enabled with the full credential set")
	}
	return p, key
}

// mintAppleIDToken signs an RS256 id_token the way Apple does (kid in the
// header, iss/aud/sub/email claims).
func mintAppleIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return signed
}

// newFakeAppleJWKS serves a JWKS document exposing the given RSA public key
// under kid.
func newFakeAppleJWKS(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	pub := &key.PublicKey
	doc := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// mintAppleClaims builds the standard claim set of a happy-path id_token.
func mintAppleClaims(sub, email string, emailVerified any) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            appleIssuer,
		"aud":            "com.example.portal",
		"sub":            sub,
		"email":          email,
		"email_verified": emailVerified,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func TestAppleClientSecret(t *testing.T) {
	p, key := newTestAppleProvider(t)
	now := time.Now()
	secret, err := p.mintClientSecret(now)
	if err != nil {
		t.Fatalf("mint client_secret: %v", err)
	}

	tok, err := jwt.Parse(secret, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("client_secret must verify with the .p8 public key: %v", err)
	}
	// Header: kid = KeyID, alg = ES256.
	if tok.Header["kid"] != "KEY1234" || tok.Header["alg"] != "ES256" {
		t.Fatalf("client_secret header = %v (want kid KEY1234 / alg ES256)", tok.Header)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type %T", tok.Claims)
	}
	if claims["iss"] != "TEAM1234" || claims["sub"] != "com.example.portal" || claims["aud"] != appleIssuer {
		t.Fatalf("client_secret claims = %v (want iss TeamID / sub ServicesID / aud %s)", claims, appleIssuer)
	}
	if claims["iat"].(float64) != float64(now.Unix()) ||
		claims["exp"].(float64) != float64(now.Add(appleClientSecretTTL).Unix()) {
		t.Fatalf("client_secret iat/exp = %v/%v (want now / now+1h)", claims["iat"], claims["exp"])
	}
}

func TestAppleAuthCodeURL(t *testing.T) {
	p, _ := newTestAppleProvider(t)
	raw := p.AuthCodeURL("https://hub.example.com/api/v1/auth/social/apple/callback", "st-9")
	for _, want := range []string{
		"response_mode=form_post", "response_type=code%20id_token", "scope=name%20email",
		"client_id=com.example.portal",
		"redirect_uri=https%3A%2F%2Fhub.example.com%2Fapi%2Fv1%2Fauth%2Fsocial%2Fapple%2Fcallback",
		"state=st-9",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("apple auth url %q missing %q", raw, want)
		}
	}
}

func TestAppleVerifyIDToken(t *testing.T) {
	p, _ := newTestAppleProvider(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	p.jwks = newJWKSCache(newFakeAppleJWKS(t, rsaKey, "apple-kid-1").URL)

	raw := mintAppleIDToken(t, rsaKey, "apple-kid-1",
		mintAppleClaims("apple-user-1", "ada@example.com", true))
	claims, err := p.verifyIDToken(raw)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if claims.Subject != "apple-user-1" || claims.Email != "ada@example.com" || !flexibleBool(claims.EmailVerified) {
		t.Fatalf("id_token claims = %+v", claims)
	}

	// Apple serializes email_verified as a string in the wild.
	raw = mintAppleIDToken(t, rsaKey, "apple-kid-1",
		mintAppleClaims("apple-user-1", "ada@example.com", "true"))
	claims, err = p.verifyIDToken(raw)
	if err != nil || !flexibleBool(claims.EmailVerified) {
		t.Fatalf("string email_verified must decode: %v / %+v", err, claims)
	}
}

func TestAppleVerifyIDTokenFailures(t *testing.T) {
	p, _ := newTestAppleProvider(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	p.jwks = newJWKSCache(newFakeAppleJWKS(t, rsaKey, "apple-kid-1").URL)

	cases := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{
			name: "wrong audience",
			claims: func() jwt.MapClaims {
				c := mintAppleClaims("s", "a@example.com", true)
				c["aud"] = "com.other.app"
				return c
			}(),
		},
		{
			name: "expired",
			claims: func() jwt.MapClaims {
				c := mintAppleClaims("s", "a@example.com", true)
				c["exp"] = time.Now().Add(-time.Hour).Unix()
				return c
			}(),
		},
		{
			name: "wrong issuer",
			claims: func() jwt.MapClaims {
				c := mintAppleClaims("s", "a@example.com", true)
				c["iss"] = "https://evil.example.com"
				return c
			}(),
		},
		{
			name:   "unknown kid",
			claims: mintAppleClaims("s", "a@example.com", true),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The unknown-kid case is minted under a kid the JWKS does not
			// publish; the others reuse the registered kid.
			kid := "apple-kid-1"
			if tc.name == "unknown kid" {
				kid = "other-kid"
			}
			raw := mintAppleIDToken(t, rsaKey, kid, tc.claims)
			if _, err := p.verifyIDToken(raw); err == nil {
				t.Fatalf("%s must fail the verification", tc.name)
			}
		})
	}
}

func TestAppleExchangeForm(t *testing.T) {
	p, _ := newTestAppleProvider(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	p.jwks = newJWKSCache(newFakeAppleJWKS(t, rsaKey, "apple-kid-1").URL)

	raw := mintAppleIDToken(t, rsaKey, "apple-kid-1",
		mintAppleClaims("apple-user-2", "grace@example.com", "true"))
	profile, err := p.ExchangeForm(context.Background(), Form{
		"id_token": raw,
		"user":     `{"name":{"firstName":"Grace","lastName":"Hopper"}}`,
	}, "https://app.test/cb")
	if err != nil {
		t.Fatalf("exchange form: %v", err)
	}
	if profile.ProviderUserID != "apple-user-2" || profile.Email != "grace@example.com" ||
		!profile.EmailVerified || profile.DisplayName != "Grace Hopper" {
		t.Fatalf("apple profile = %+v", profile)
	}
}

func TestAppleDisabled(t *testing.T) {
	// No credentials at all.
	if p := newAppleProvider(config.AppleConfig{}, Endpoints{}); p.Enabled() {
		t.Fatal("apple must be disabled without credentials")
	}
	// Credentials but an unloadable key file.
	cfg := config.AppleConfig{
		ServicesID: "com.example.portal", TeamID: "TEAM1234", KeyID: "KEY1234",
		PrivateKeyPath: filepath.Join(t.TempDir(), "missing.p8"),
	}
	if p := newAppleProvider(cfg, Endpoints{}); p.Enabled() {
		t.Fatal("apple must be disabled when the .p8 cannot be loaded")
	}
}

func TestFlexibleBool(t *testing.T) {
	cases := map[string]bool{
		`true`:    true,
		`"true"`:  true,
		`"1"`:     true,
		`false`:   false,
		`"false"`: false,
		``:        false,
		`null`:    false,
	}
	for raw, want := range cases {
		if got := flexibleBool(json.RawMessage(raw)); got != want {
			t.Fatalf("flexibleBool(%s) = %v, want %v", raw, got, want)
		}
	}
}
