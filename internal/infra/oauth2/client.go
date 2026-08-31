// Package oauth2 adapts the access-hub repositories to github.com/go-oauth2/
// oauth2/v4 (design.md §12 M4): the library acts as the protocol engine
// (authorize code lifecycle, PKCE verification, client_credentials) while the
// OIDC layer (id_token, userinfo, discovery) is built on top in the service
// layer.
package oauth2

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
)

// Client wraps an oauth_clients row as the go-oauth2 ClientInfo. The stored
// secret is a sha256 hash, so verification goes through the
// ClientPasswordVerifier interface (the manager checks the verifier before
// falling back to a plain GetSecret comparison).
type Client struct {
	row    *model.OAuthClient
	appKey string
}

var _ oauth2.ClientInfo = (*Client)(nil)
var _ oauth2.ClientPasswordVerifier = (*Client)(nil)

// NewClient wraps a row; appKey may be "" when unknown.
func NewClient(row *model.OAuthClient, appKey string) *Client {
	return &Client{row: row, appKey: appKey}
}

func (c *Client) GetID() string           { return c.row.Id }
func (c *Client) GetUserID() string       { return "" }
func (c *Client) IsPublic() bool          { return c.row.ClientType == model.OAuthClientTypePublic }
func (c *Client) AppKey() string          { return c.appKey }
func (c *Client) Row() *model.OAuthClient { return c.row }

// GetSecret returns the STORED HASH (not a usable secret); the manager only
// compares it when the client does not implement ClientPasswordVerifier.
func (c *Client) GetSecret() string {
	if c.row.SecretHash == nil {
		return ""
	}
	return *c.row.SecretHash
}

// GetDomain returns the first registered redirect URI. Exact-match
// validation against the registered list happens before the library sees the
// request (see service.ValidateAuthorize), so the library's own
// validateURI is bypassed with a permissive handler.
func (c *Client) GetDomain() string {
	uris := c.RedirectURIs()
	if len(uris) == 0 {
		return ""
	}
	return uris[0]
}

// VerifyPassword compares sha256(presented) against the stored hash in
// constant time.
func (c *Client) VerifyPassword(secret string) bool {
	if c.row.SecretHash == nil || *c.row.SecretHash == "" {
		// Public clients carry no secret: an empty presented secret matches.
		return secret == ""
	}
	sum := sha256Hex(secret)
	return subtle.ConstantTimeCompare([]byte(sum), []byte(*c.row.SecretHash)) == 1
}

// GrantTypes decodes the registered grant types.
func (c *Client) GrantTypes() []string { return jsonStrings(c.row.GrantTypes) }

// RedirectURIs decodes the registered redirect URIs.
func (c *Client) RedirectURIs() []string { return jsonStrings(c.row.RedirectURIs) }

// Scopes decodes the registered scopes.
func (c *Client) Scopes() []string { return jsonStrings(c.row.Scopes) }

// HasGrant reports whether the grant is registered.
func (c *Client) HasGrant(grant string) bool {
	for _, g := range c.GrantTypes() {
		if g == grant {
			return true
		}
	}
	return false
}

// AllowsScope reports whether every requested scope is registered (empty
// request = default scopes, always allowed).
func (c *Client) AllowsScope(requested []string) bool {
	registered := c.Scopes()
	for _, r := range requested {
		found := false
		for _, allowed := range registered {
			if r == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ClientStore adapts OAuthClientRepo to the go-oauth2 ClientStore.
type ClientStore struct {
	repo    repository.OAuthClientRepo
	appRepo repository.AppRepo
}

var _ oauth2.ClientStore = (*ClientStore)(nil)

// NewClientStore builds the adapter.
func NewClientStore(repo repository.OAuthClientRepo, appRepo repository.AppRepo) *ClientStore {
	return &ClientStore{repo: repo, appRepo: appRepo}
}

// GetByID resolves a client; unknown or disabled clients yield the library's
// ErrInvalidClient. Returns *Client (cast in the service layer for grants/
// scopes/PKCE decisions).
func (s *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	row, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, errors.ErrInvalidClient
		}
		return nil, err
	}
	if row.Status != model.OAuthClientStatusActive {
		return nil, errors.ErrInvalidClient
	}
	appKey := ""
	if s.appRepo != nil {
		app, err := s.appRepo.FindByID(ctx, row.AppID)
		if err == nil {
			appKey = app.Key
		}
	}
	return NewClient(row, appKey), nil
}

// jsonStrings decodes a jsonb string-array column, tolerating nil input.
func jsonStrings(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}
