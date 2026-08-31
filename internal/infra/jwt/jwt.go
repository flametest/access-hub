// Package jwt implements RS256 token issuance/verification and the JWKS
// endpoint payload (design.md §2.5, §7).
//
// Token flavors:
//   - identity (portal) tokens: sub = "user:{identityID}", aud = "access-hub"
//   - account (workspace) tokens: sub = "account:{accountID}", iid/aid set,
//     aud = the target app key
package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/flametest/vita/verrors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// Issuer is the iss claim value for every access-hub token.
	Issuer = "access-hub"
	// AudienceCentral is the aud for portal/center tokens.
	AudienceCentral = "access-hub"

	SubjectPrefixUser    = "user:"
	SubjectPrefixAccount = "account:"
	SubjectPrefixClient  = "client:"
)

// Token type markers (Claims.Typ). "" is the classic access token issued by
// M1-M3 flows; "mfa" marks the short-lived 2FA login challenge; "client"
// marks an OAuth2 client_credentials service token.
const (
	TypeAccess = ""
	TypeMFA    = "mfa"
	TypeClient = "client"
)

// Claims are access-hub access-token claims. aud serializes as a plain JSON
// string (single audience, see jwt.ClaimStrings marshaling).
type Claims struct {
	jwt.RegisteredClaims
	Sid      string `json:"sid,omitempty"`      // session id
	Iid      string `json:"iid,omitempty"`      // identity id (account tokens)
	Aid      string `json:"aid,omitempty"`      // account id (account tokens)
	Username string `json:"username,omitempty"` // identity username
	Email    string `json:"email,omitempty"`    // identity email
	Typ      string `json:"typ,omitempty"`      // token type marker (see Type* constants)
}

// NewIdentityClaims builds claims for a portal (center) token.
func NewIdentityClaims(identityID, sessionID, username, email string, ttl time.Duration) *Claims {
	return newClaims(SubjectPrefixUser+identityID, AudienceCentral, "", identityID, sessionID, username, email, ttl)
}

// NewAccountClaims builds claims for a workspace app token. appKey becomes
// the audience so business apps can verify locally via JWKS.
func NewAccountClaims(accountID, identityID, appKey, sessionID, username, email string, ttl time.Duration) *Claims {
	return newClaims(SubjectPrefixAccount+accountID, appKey, accountID, identityID, sessionID, username, email, ttl)
}

// NewMFAClaims builds the short-lived 2FA login challenge token
// (sub = user:{id}, aud = access-hub, typ = "mfa").
func NewMFAClaims(identityID string, ttl time.Duration) *Claims {
	c := newClaims(SubjectPrefixUser+identityID, AudienceCentral, "", identityID, "", "", "", ttl)
	c.Typ = TypeMFA
	return c
}

// NewClientClaims builds claims for an OAuth2 client_credentials service
// token (sub = client:{clientID}, aud = the client's app key, no session).
func NewClientClaims(clientID, appKey string, ttl time.Duration) *Claims {
	c := newClaims(SubjectPrefixClient+clientID, appKey, "", "", "", "", "", ttl)
	c.Typ = TypeClient
	return c
}

func newClaims(subject, aud, aid, iid, sessionID, username, email string, ttl time.Duration) *Claims {
	now := time.Now()
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Sid:      sessionID,
		Iid:      iid,
		Aid:      aid,
		Username: username,
		Email:    email,
	}
}

// Aud returns the single audience string ("" when absent).
func (c *Claims) Aud() string {
	if len(c.Audience) == 0 {
		return ""
	}
	return c.Audience[0]
}

// IsAccountToken reports whether the claims describe a workspace app token.
func (c *Claims) IsAccountToken() bool {
	return c.Aid != ""
}

// IsMFAToken reports whether the claims describe a 2FA login challenge.
func (c *Claims) IsMFAToken() bool { return c.Typ == TypeMFA }

// IsClientToken reports whether the claims describe a client_credentials
// service token.
func (c *Claims) IsClientToken() bool { return c.Typ == TypeClient }

// IDTokenClaims are the OIDC ID-token claims (design.md §12 M4). They share
// the RS256 key with access tokens but are a separate type so the access
// token claim shape stays backward compatible.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce  string `json:"nonce,omitempty"`   // authorization-request nonce
	AtHash string `json:"at_hash,omitempty"` // left half of SHA-256(access token), base64url
	Sid    string `json:"sid,omitempty"`     // optional session binding
}

// NewIDTokenClaims builds ID-token claims. iss must be the OIDC issuer URL
// from the discovery document (NOT the static access-hub iss constant).
func NewIDTokenClaims(issuer, subject, audience, nonce, atHash, sessionID string, ttl time.Duration) *IDTokenClaims {
	now := time.Now()
	return &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Nonce:  nonce,
		AtHash: atHash,
		Sid:    sessionID,
	}
}

// Manager signs and verifies RS256 tokens and serves the JWKS document.
type Manager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
	jwks       json.RawMessage
}

// NewManager loads the RSA private and public PEM files (PKCS#1 or PKCS#8 for
// the private key; PKCS#1/PKIX for the public key) and pre-computes the JWKS.
func NewManager(privateKeyPath, publicKeyPath string) (*Manager, error) {
	privatePEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("read rsa private key %s: %v", privateKeyPath, err))
	}
	privateKey, err := parsePrivateKey(privatePEM)
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("parse rsa private key %s: %v", privateKeyPath, err))
	}

	publicPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("read rsa public key %s: %v", publicKeyPath, err))
	}
	publicKey, err := parsePublicKey(publicPEM)
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("parse rsa public key %s: %v", publicKeyPath, err))
	}
	// Fail fast on a mismatched key pair.
	if publicKey.N.Cmp(privateKey.N) != 0 || publicKey.E != privateKey.E {
		return nil, verrors.InternalServerError("rsa public key does not match the private key")
	}

	kid, err := computeKid(publicKey)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(&jwksDoc{
		Keys: []jwk{{
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigEndianExponent(publicKey.E)),
		}},
	})
	if err != nil {
		return nil, verrors.InternalServerError(fmt.Sprintf("marshal jwks: %v", err))
	}
	return &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
		kid:        kid,
		jwks:       raw,
	}, nil
}

// Issue signs the claims with RS256 and returns the compact token.
func (m *Manager) Issue(claims *Claims) (string, error) {
	if claims == nil {
		return "", verrors.BadRequestError("claims is nil")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("sign token: %v", err))
	}
	return signed, nil
}

// IssueIDToken signs OIDC ID-token claims with the same RS256 key.
func (m *Manager) IssueIDToken(claims *IDTokenClaims) (string, error) {
	if claims == nil {
		return "", verrors.BadRequestError("claims is nil")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", verrors.InternalServerError(fmt.Sprintf("sign id_token: %v", err))
	}
	return signed, nil
}

// Parse verifies the token signature (RS256 only) and standard claims
// including a mandatory exp. It does not check session revocation — callers
// consult the Redis denylist separately.
func (m *Manager) Parse(token string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	var claims Claims
	if _, err := parser.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return m.publicKey, nil
	}); err != nil {
		return nil, verrors.UnauthorizedError(fmt.Sprintf("invalid token: %v", err))
	}
	return &claims, nil
}

// JWKS returns the cached JSON Web Key Set document (single RSA signing key).
func (m *Manager) JWKS() (json.RawMessage, error) {
	if len(m.jwks) == 0 {
		return nil, verrors.InternalServerError("jwks not initialized")
	}
	return m.jwks, nil
}

// KID returns the signing key id (stable sha256-of-modulus prefix).
func (m *Manager) KID() string { return m.kid }

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// computeKid derives a stable key id: first 16 hex chars of the sha256 of the
// modulus — deterministic across restarts, as clients cache JWKS by kid.
func computeKid(publicKey *rsa.PublicKey) (string, error) {
	sum := sha256.Sum256(publicKey.N.Bytes())
	return hex.EncodeToString(sum[:])[:16], nil
}

// bigEndianExponent returns the minimal big-endian bytes of the public
// exponent (usually 65537 -> "AQAB").
func bigEndianExponent(e int) []byte {
	buf := make([]byte, 0, 8)
	for v := e; v > 0; v >>= 8 {
		buf = append([]byte{byte(v)}, buf...)
	}
	return buf
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS1/PKCS8: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want *rsa.PrivateKey", parsed)
	}
	return key, nil
}

func parsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS1/PKIX: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want *rsa.PublicKey", parsed)
	}
	return key, nil
}
