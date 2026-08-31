package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/vita/vgorm"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
)

func testClient(t *testing.T, clientType string) *Client {
	t.Helper()
	secret := "sec_abcdef0123456789abcdef0123456789"
	secretHash := sha256Hex(secret)
	row := &model.OAuthClient{
		BasePostgres: vgorm.BasePostgres{Id: "cli_" + uuid.NewString()},
		AppID:        uuid.NewString(),
		Name:         "Test client",
		ClientType:   clientType,
		GrantTypes:   []byte(`["authorization_code","refresh_token","client_credentials"]`),
		RedirectURIs: []byte(`["https://app.example.com/cb"]`),
		Scopes:       []byte(`["openid","profile","email","offline_access"]`),
		Status:       model.OAuthClientStatusActive,
	}
	if clientType == model.OAuthClientTypeConfidential {
		row.SecretHash = &secretHash
	}
	return NewClient(row, "crm")
}

func TestClientSecretVerify(t *testing.T) {
	// The secret generation contract: sha256(presented) == stored hash.
	c := testClient(t, model.OAuthClientTypeConfidential)
	if !c.VerifyPassword("sec_abcdef0123456789abcdef0123456789") {
		t.Fatal("correct secret must verify")
	}
	if c.VerifyPassword("sec_wrong") {
		t.Fatal("wrong secret must not verify")
	}
	if c.VerifyPassword("") {
		t.Fatal("empty secret must not verify against a confidential client")
	}

	// Public clients carry no secret: only the empty secret matches.
	public := testClient(t, model.OAuthClientTypePublic)
	if !public.VerifyPassword("") {
		t.Fatal("public client must accept the empty secret")
	}
	if public.VerifyPassword("sec_abcdef0123456789abcdef0123456789") {
		t.Fatal("public client must reject any secret")
	}
}

func TestClientMetadata(t *testing.T) {
	c := testClient(t, model.OAuthClientTypeConfidential)
	if c.HasGrant("authorization_code") == false || !c.HasGrant("refresh_token") || !c.HasGrant("client_credentials") {
		t.Fatal("grant decoding broken")
	}
	if c.HasGrant("nope") {
		t.Fatal("HasGrant must be false for unregistered grants")
	}
	if !c.AllowsScope([]string{"openid", "profile"}) {
		t.Fatal("registered scopes must be allowed")
	}
	if c.AllowsScope([]string{"openid", "admin"}) {
		t.Fatal("unregistered scope must be rejected")
	}
	if !c.AllowsScope(nil) {
		t.Fatal("empty scope request is always allowed (default scopes)")
	}
	if c.AppKey() != "crm" || c.IsPublic() {
		t.Fatalf("client metadata broken: appKey=%q public=%v", c.AppKey(), c.IsPublic())
	}
	if c.GetDomain() != "https://app.example.com/cb" {
		t.Fatalf("GetDomain = %q", c.GetDomain())
	}
}

// TestPKCES256Verification exercises the library's S256 verifier check used
// at the token endpoint (the same code path the manager runs).
func TestPKCES256Verification(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	s256 := oauth2.CodeChallengeS256
	if !s256.Validate(challenge, verifier) {
		t.Fatal("valid verifier must satisfy the S256 challenge")
	}
	if s256.Validate(challenge, "wrong-verifier-wrong-verifier-wrong-verifier") {
		t.Fatal("wrong verifier must fail")
	}
	if s256.Validate(challenge, challenge) {
		t.Fatal("a plain verifier value must not satisfy S256")
	}
}
