package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"github.com/flametest/access-hub/internal/config"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/kv"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/verrors"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
)

// ctxKeyMeta is the request-context key carrying the authorize-time metadata
// (nonce) into the manager's extension handler, which persists it on the
// authorization code and forwards it to the token response.
type ctxKeyMeta struct{}

// AuthorizeMeta is the authorize-time metadata bound to the code (nonce for
// the id_token; account/identity subjects for the refresh-token row).
type AuthorizeMeta struct {
	Nonce      string
	AccountID  string
	IdentityID string
}

// WithAuthorizeMeta attaches the metadata to a request context.
func WithAuthorizeMeta(ctx context.Context, meta *AuthorizeMeta) context.Context {
	return context.WithValue(ctx, ctxKeyMeta{}, meta)
}

// metaFromRequest extracts the metadata from the request carried in the
// TokenGenerateRequest (nil when absent).
func metaFromRequest(r *http.Request) *AuthorizeMeta {
	if r == nil {
		return nil
	}
	meta, _ := r.Context().Value(ctxKeyMeta{}).(*AuthorizeMeta)
	return meta
}

// Server bundles the configured go-oauth2 manager and protocol server over
// the access-hub repositories.
type Server struct {
	Manager *manage.Manager
	Server  *server.Server
}

// NewServer wires the OAuth2 engine: client store over oauth_clients, code
// storage in the KV store, refresh tokens in oauth_refresh_tokens and RS256
// JWT access tokens from the shared jwt.Manager.
func NewServer(cfg *config.Config, store kv.Store, mgr *jwt.Manager, clients repository.OAuthClientRepo, apps repository.AppRepo, accounts repository.AccountRepo, identities repository.UserRepo, refresh repository.OAuthRefreshTokenRepo) *Server {
	manager := manage.NewManager()
	manager.MapClientStorage(NewClientStore(clients, apps))
	manager.MapTokenStorage(NewTokenStore(store, refresh))
	manager.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	manager.MapAccessGenerate(NewJWTAccessGenerate(mgr, accounts, identities, apps))
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    cfg.Auth.AccessTokenTTL,
		RefreshTokenExp:   cfg.Auth.RefreshTokenTTL,
		IsGenerateRefresh: true,
	})
	manager.SetClientTokenCfg(&manage.Config{
		AccessTokenExp: cfg.Auth.AccessTokenTTL,
	})
	// Redirect-URI exact-match enforcement happens at authorize validation
	// (registered list); the library's containment check is bypassed.
	manager.SetValidateURIHandler(func(baseURI, redirectURI string) error { return nil })
	// Carry the authorize metadata (nonce + subjects) onto the code record.
	manager.SetExtractExtensionHandler(func(tgr *oauth2.TokenGenerateRequest, ti oauth2.ExtendableTokenInfo) {
		meta := metaFromRequest(tgr.Request)
		if meta == nil {
			return
		}
		ext := url.Values{}
		if meta.Nonce != "" {
			ext["nonce"] = []string{meta.Nonce}
		}
		if meta.AccountID != "" {
			ext["account_id"] = []string{meta.AccountID}
		}
		if meta.IdentityID != "" {
			ext["iid"] = []string{meta.IdentityID}
		}
		ti.SetExtension(ext)
	})

	srv := server.NewServer(&server.Config{
		TokenType:                   "Bearer",
		AllowedResponseTypes:        []oauth2.ResponseType{oauth2.Code},
		AllowedGrantTypes:           []oauth2.GrantType{oauth2.AuthorizationCode, oauth2.ClientCredentials},
		AllowedCodeChallengeMethods: []oauth2.CodeChallengeMethod{oauth2.CodeChallengeS256},
	}, manager)
	// Per-client grant enforcement (registered grant_types + active client).
	srv.ClientAuthorizedHandler = func(clientID string, grant oauth2.GrantType) (bool, error) {
		client, err := clients.FindByID(context.Background(), clientID)
		if err != nil {
			return false, nil
		}
		if client.Status != "active" {
			return false, nil
		}
		for _, g := range decodeGrants(client) {
			if g == string(grant) {
				return true, nil
			}
		}
		return false, nil
	}
	// Per-client scope enforcement: the requested scope must be a subset of
	// the registered scopes.
	srv.ClientScopeHandler = func(tgr *oauth2.TokenGenerateRequest) (bool, error) {
		client, err := clients.FindByID(context.Background(), tgr.ClientID)
		if err != nil {
			return false, nil
		}
		requested := strings.Fields(tgr.Scope)
		registered := decodeScopes(client)
		for _, scope := range requested {
			found := false
			for _, allowed := range registered {
				if allowed == scope {
					found = true
					break
				}
			}
			if !found {
				return false, nil
			}
		}
		return true, nil
	}
	return &Server{Manager: manager, Server: srv}
}

func decodeGrants(client *model.OAuthClient) []string { return jsonStrings(client.GrantTypes) }
func decodeScopes(client *model.OAuthClient) []string { return jsonStrings(client.Scopes) }

// opaqueToken returns a 256-bit hex token for OAuth refresh tokens.
func opaqueToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", verrors.InternalServerError("generate refresh token")
	}
	return hex.EncodeToString(buf), nil
}
