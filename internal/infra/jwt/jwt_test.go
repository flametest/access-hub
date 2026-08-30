package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPair generates an RSA key pair and writes PKCS#8/PKCS#1 private and
// PKIX public PEM files into a temp dir (no committed key files in tests).
func writeKeyPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := t.TempDir()

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	privatePath = filepath.Join(dir, "private.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatalf("write private: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	publicPath = filepath.Join(dir, "public.pem")
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		t.Fatalf("write public: %v", err)
	}
	return privatePath, publicPath
}

func TestIssueParseRoundTrip(t *testing.T) {
	privatePath, publicPath := writeKeyPair(t)
	m, err := NewManager(privatePath, publicPath)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	identityClaims := NewIdentityClaims("11111111-1111-1111-1111-111111111111", "sess-1", "alice", "alice@example.com", 15*time.Minute)
	token, err := m.Issue(identityClaims)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	got, err := m.Parse(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Subject != SubjectPrefixUser+"11111111-1111-1111-1111-111111111111" {
		t.Fatalf("subject = %q", got.Subject)
	}
	if got.Aud() != AudienceCentral {
		t.Fatalf("aud = %q", got.Aud())
	}
	if got.Sid != "sess-1" || got.Username != "alice" || got.Email != "alice@example.com" {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if got.ID == "" {
		t.Fatal("jti must be set")
	}
	if got.IsAccountToken() {
		t.Fatal("identity claims must not carry aid")
	}
}

func TestAccountTokenRoundTrip(t *testing.T) {
	privatePath, publicPath := writeKeyPair(t)
	m, err := NewManager(privatePath, publicPath)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	claims := NewAccountClaims("acc-1", "user-1", "demo-app", "sess-2", "bob", "bob@example.com", 15*time.Minute)
	token, err := m.Issue(claims)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := m.Parse(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Subject != SubjectPrefixAccount+"acc-1" {
		t.Fatalf("subject = %q", got.Subject)
	}
	if got.Aud() != "demo-app" || got.Aid != "acc-1" || got.Iid != "user-1" {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if !got.IsAccountToken() {
		t.Fatal("account token should be detected")
	}
}

func TestParseRejectsTamperedAndExpired(t *testing.T) {
	privatePath, publicPath := writeKeyPair(t)
	m, err := NewManager(privatePath, publicPath)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	token, err := m.Issue(NewIdentityClaims("u1", "s1", "a", "a@e.com", 15*time.Minute))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := m.Parse(token + "x"); err == nil {
		t.Fatal("tampered token must be rejected")
	}

	expired := NewIdentityClaims("u1", "s1", "a", "a@e.com", -time.Minute)
	expiredToken, err := m.Issue(expired)
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	if _, err := m.Parse(expiredToken); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestParseRejectsNonRS256(t *testing.T) {
	privatePath, publicPath := writeKeyPair(t)
	m, err := NewManager(privatePath, publicPath)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	// A HS256-signed token must be rejected by the method allow-list.
	forged := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.ZTyE9UjD0Y0ZkKgDZ5bTFG8XJmIqTn0dJv0B9pHzuSY"
	if _, err := m.Parse(forged); err == nil {
		t.Fatal("HS256 token must be rejected")
	}
}

func TestJWKSDocument(t *testing.T) {
	privatePath, publicPath := writeKeyPair(t)
	m, err := NewManager(privatePath, publicPath)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	raw, err := m.JWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Fatalf("bad jwk: %+v", k)
	}
	if k.Kid == "" || len(k.Kid) != 16 {
		t.Fatalf("kid = %q, want 16 hex chars", k.Kid)
	}
	if k.N == "" || k.E != "AQAB" {
		t.Fatalf("bad modulus/exponent: n=%q e=%q", k.N, k.E)
	}
	if m.KID() != k.Kid {
		t.Fatalf("KID() = %q, want %q", m.KID(), k.Kid)
	}
}

func TestNewManagerRejectsMismatchedKeys(t *testing.T) {
	p1, pub1 := writeKeyPair(t)
	_, pub2 := writeKeyPair(t)
	if _, err := NewManager(p1, pub2); err == nil {
		t.Fatal("mismatched key pair must be rejected")
	}
	if _, err := NewManager(p1, pub1); err != nil {
		t.Fatalf("matching pair should load: %v", err)
	}
}

func TestNewManagerFailsOnMissingFiles(t *testing.T) {
	if _, err := NewManager("/nonexistent/private.pem", "/nonexistent/public.pem"); err == nil {
		t.Fatal("missing key files must fail fast")
	}
}
