package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/model"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/vita/verrors"
	oauth2 "github.com/go-oauth2/oauth2/v4"
)

// JWTAccessGenerate implements oauth2.AccessGenerate: access tokens are RS256
// JWTs issued by the shared jwt.Manager (local verification via JWKS), and
// refresh tokens are opaque 256-bit values. The subject follows the M4
// decisions:
//   - authorization_code flows: gen.UserID = "account:{id}" (set at authorize
//     time by the account resolution) -> claims aid/iid like workspace tokens
//   - client_credentials: gen.UserID = "" -> sub = "client:{id}",
//     aud = the client's app key
type JWTAccessGenerate struct {
	jwt        *jwt.Manager
	accounts   repository.AccountRepo
	identities repository.UserRepo
	apps       repository.AppRepo
}

var _ oauth2.AccessGenerate = (*JWTAccessGenerate)(nil)

// NewJWTAccessGenerate builds the generator.
func NewJWTAccessGenerate(mgr *jwt.Manager, accounts repository.AccountRepo, identities repository.UserRepo, apps repository.AppRepo) *JWTAccessGenerate {
	return &JWTAccessGenerate{jwt: mgr, accounts: accounts, identities: identities, apps: apps}
}

// Token produces the access (and optionally refresh) token.
func (g *JWTAccessGenerate) Token(ctx context.Context, gen *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	ttl := gen.TokenInfo.GetAccessExpiresIn()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	var claims *jwt.Claims
	if gen.UserID != "" {
		claims, err = g.accountClaims(ctx, gen.UserID, ttl)
	} else {
		client, ok := gen.Client.(*Client)
		if !ok {
			return "", "", verrors.InternalServerError("client_credentials requires a known client")
		}
		claims = jwt.NewClientClaims(client.GetID(), client.AppKey(), ttl)
	}
	if err != nil {
		return "", "", err
	}
	access, err = g.jwt.Issue(claims)
	if err != nil {
		return "", "", err
	}
	if isGenRefresh && g.shouldRefresh(gen) {
		refresh, err = opaqueToken()
		if err != nil {
			return "", "", err
		}
	}
	return access, refresh, nil
}

// shouldRefresh decides whether the flow earns a refresh token: the scope
// carries offline_access OR the client registered the refresh_token grant
// (client_credentials never reaches this path with isGenRefresh=true).
func (g *JWTAccessGenerate) shouldRefresh(gen *oauth2.GenerateBasic) bool {
	for _, scope := range strings.Fields(gen.TokenInfo.GetScope()) {
		if scope == "offline_access" {
			return true
		}
	}
	if client, ok := gen.Client.(*Client); ok {
		return client.HasGrant(model.OAuthGrantRefreshToken)
	}
	return false
}

// accountClaims rebuilds the workspace-token claims from the resolved
// account (the single source of truth stays the business tables).
func (g *JWTAccessGenerate) accountClaims(ctx context.Context, userID string, ttl time.Duration) (*jwt.Claims, error) {
	accountID := strings.TrimPrefix(userID, jwt.SubjectPrefixAccount)
	account, err := g.accounts.FindByID(ctx, accountID)
	if err != nil {
		return nil, verrors.InternalServerError("load oauth account subject: " + accountID)
	}
	identity, err := g.identities.FindByID(ctx, account.IdentityID)
	if err != nil {
		return nil, verrors.InternalServerError("load oauth identity subject")
	}
	app, err := g.apps.FindByID(ctx, account.AppID)
	if err != nil {
		return nil, verrors.InternalServerError("load oauth account app")
	}
	// OAuth-issued tokens carry no session id (no portal session row).
	return jwt.NewAccountClaims(account.Id, identity.Id, app.Key, "", identity.Username, identity.Email, ttl), nil
}
