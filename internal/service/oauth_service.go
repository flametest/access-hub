// OAuth2/OIDC provider service (design.md §12 M4). The go-oauth2/v4 engine
// (internal/infra/oauth2) owns the code lifecycle and PKCE verification;
// this service owns the M4 decisions on top: account resolution with
// auto-provisioning at authorize time, RS256 JWT access tokens, id_token
// minting, refresh-token rotation with family revocation, userinfo and the
// discovery document.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/access-hub/internal/infra/model"
	oauth2x "github.com/flametest/access-hub/internal/infra/oauth2"
	"github.com/flametest/access-hub/internal/infra/repository"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vgorm"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/google/uuid"
)

// OAuth scopes with special meaning.
const (
	ScopeOpenID        = "openid"
	ScopeOfflineAccess = "offline_access"
)

// OAuthService implements the OAuth2/OIDC provider endpoints.
type OAuthService interface {
	// AuthorizeSPA implements POST /api/v1/oauth/authorize (JSON variant,
	// center identity token required).
	AuthorizeSPA(ctx context.Context, actx *AuthContextInfo, req *dto.OAuthAuthorizeReq, r *http.Request) (*dto.OAuthAuthorizeResp, error)
	// AuthorizeBrowser implements GET /oauth2/authorize (standard redirect
	// variant). identity == nil means "no session": the returned loginURL is
	// the portal login redirect target.
	AuthorizeBrowser(ctx context.Context, identity *BrowserIdentity, r *http.Request) (redirectURL, loginURL string, err error)
	// Token implements POST /oauth2/token (authorization_code,
	// refresh_token, client_credentials).
	Token(ctx context.Context, r *http.Request) (map[string]any, error)
	// Userinfo implements GET /oauth2/userinfo.
	Userinfo(ctx context.Context, bearer string) (map[string]any, error)
	// Discovery builds GET /.well-known/openid-configuration.
	Discovery() map[string]any
}

// BrowserIdentity is the resolved caller of the browser authorize endpoint
// (bearer token or the portal's ah.session cookie).
type BrowserIdentity struct {
	UserID string
}

// OAuthError is an RFC-6749 error payload rendered as
// {"error": code, "error_description": desc} with the given HTTP status.
type OAuthError struct {
	Code       string
	Desc       string
	StatusCode int
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Desc }

func oauthErr(status int, code, desc string) *OAuthError {
	return &OAuthError{Code: code, Desc: desc, StatusCode: status}
}

// mapOAuthError converts library errors into OAuthError responses.
func mapOAuthError(err error) error {
	switch err {
	case oauth2errors.ErrInvalidClient:
		return oauthErr(401, "invalid_client", oauth2errors.Descriptions[err])
	case oauth2errors.ErrInvalidGrant, oauth2errors.ErrInvalidAuthorizeCode,
		oauth2errors.ErrExpiredRefreshToken, oauth2errors.ErrInvalidRefreshToken,
		oauth2errors.ErrInvalidCodeChallenge, oauth2errors.ErrMissingCodeVerifier,
		oauth2errors.ErrMissingCodeChallenge:
		return oauthErr(400, "invalid_grant", oauth2errors.Descriptions[oauth2errors.ErrInvalidGrant])
	case oauth2errors.ErrUnauthorizedClient:
		return oauthErr(401, "unauthorized_client", oauth2errors.Descriptions[err])
	case oauth2errors.ErrInvalidScope:
		return oauthErr(400, "invalid_scope", oauth2errors.Descriptions[err])
	case oauth2errors.ErrUnsupportedGrantType:
		return oauthErr(400, "unsupported_grant_type", oauth2errors.Descriptions[err])
	}
	return oauthErr(500, "server_error", err.Error())
}

type oauthServiceImpl struct {
	c      container.Container
	engine *oauth2x.Server
}

// NewOAuthService builds the OAuth2 provider service over the shared engine.
func NewOAuthService(c container.Container) OAuthService {
	return &oauthServiceImpl{
		c: c,
		engine: oauth2x.NewServer(
			c.Cfg(), c.KV(), c.JWT(),
			c.OAuthClientRepo(), c.AppRepo(), c.AccountRepo(), c.UserRepo(),
			c.OAuthRefreshTokenRepo(),
		),
	}
}

// ---------- authorize ----------

// validatedAuthorize carries the fully validated authorize request.
type validatedAuthorize struct {
	client *oauth2x.Client
	appID  string
	appKey string
	scope  string
}

// validateAuthorize enforces, before the library sees anything: the client
// exists and is active, supports authorization_code, the redirect URI
// exact-matches a registered one, the scope subset is registered, and PKCE
// rules hold (S256 mandatory for public clients, supported for
// confidential).
func (s *oauthServiceImpl) validateAuthorize(ctx context.Context, clientID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (*validatedAuthorize, error) {
	row, err := s.c.OAuthClientRepo().FindByID(ctx, clientID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, oauthErr(400, "invalid_request", "unknown client_id")
		}
		return nil, verrors.Wrap(err, "find oauth client")
	}
	if row.Status != model.OAuthClientStatusActive {
		return nil, oauthErr(401, "unauthorized_client", "client is disabled")
	}
	app, err := s.c.AppRepo().FindByID(ctx, row.AppID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, oauthErr(400, "invalid_request", "client app not found")
		}
		return nil, verrors.Wrap(err, "find client app")
	}
	if app.Status != domain.AppStatusActive {
		return nil, oauthErr(401, "unauthorized_client", "client app is disabled")
	}
	client := oauth2x.NewClient(row, app.Key)
	if !client.HasGrant(model.OAuthGrantAuthorizationCode) {
		return nil, oauthErr(401, "unauthorized_client", "client is not authorized for the authorization_code grant")
	}
	// Exact-match redirect URI (registered list only).
	registered := client.RedirectURIs()
	matched := false
	for _, uri := range registered {
		if uri == redirectURI {
			matched = true
			break
		}
	}
	if !matched {
		return nil, oauthErr(400, "invalid_request", "redirect_uri is not registered for this client")
	}
	// Scope: empty means the client's default (registered) scopes.
	if strings.TrimSpace(scope) == "" {
		scope = strings.Join(client.Scopes(), " ")
	} else if !client.AllowsScope(strings.Fields(scope)) {
		return nil, oauthErr(400, "invalid_scope", "requested scope exceeds the client registration")
	}
	// PKCE: public clients MUST present an S256 challenge; confidential
	// clients may use it optionally (plain is never accepted).
	if codeChallenge != "" {
		if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
			return nil, oauthErr(400, "invalid_request", "invalid code_challenge length")
		}
		if codeChallengeMethod != "S256" {
			return nil, oauthErr(400, "invalid_request", "code_challenge_method must be S256")
		}
	} else if client.IsPublic() {
		return nil, oauthErr(400, "invalid_request", "PKCE (S256) is required for public clients")
	}
	return &validatedAuthorize{client: client, appID: app.Id, appKey: app.Key, scope: scope}, nil
}

// resolveAccount implements the M4 account resolution at authorize time:
// explicit account_id (must belong to the identity AND the client's app) ->
// the identity's unique existing account in that app -> auto-provision an
// active passwordless account (source=provisioned).
func (s *oauthServiceImpl) resolveAccount(ctx context.Context, appID, appKey, identityID, explicitAccountID string) (string, error) {
	if explicitAccountID != "" {
		account, err := s.c.AccountRepo().FindByID(ctx, explicitAccountID)
		if err != nil {
			if repository.IsNotFound(err) {
				return "", verrors.NotFoundError("account not found")
			}
			return "", verrors.Wrap(err, "find account")
		}
		if account.IdentityID != identityID {
			return "", verrors.ForbiddenError("account does not belong to the caller")
		}
		if account.AppID != appID {
			return "", verrors.ForbiddenError("account does not belong to this app")
		}
		if account.Status != domain.AccountStatusActive {
			return "", verrors.ForbiddenError("account is not active")
		}
		return account.Id, nil
	}
	accounts, err := s.c.AccountRepo().ListByIdentity(ctx, identityID)
	if err != nil {
		return "", verrors.Wrap(err, "list accounts")
	}
	mine := make([]*model.Account, 0, 1)
	for _, a := range accounts {
		if a.AppID == appID {
			mine = append(mine, a)
		}
	}
	switch len(mine) {
	case 1:
		if mine[0].Status != domain.AccountStatusActive {
			return "", verrors.ForbiddenError("account is not active")
		}
		return mine[0].Id, nil
	case 0:
		// Auto-provision (OIDC first login): active, no password (direct
		// login stays impossible until the activation email flow sets one).
		identity, err := s.c.UserRepo().FindByID(ctx, identityID)
		if err != nil {
			return "", verrors.Wrap(err, "find identity for auto-provision")
		}
		account := &model.Account{
			BasePostgres: vgorm.BasePostgres{Id: uuid.NewString()},
			IdentityID:   identityID,
			AppID:        appID,
			Email:        identity.Email,
			DisplayName:  identity.Nickname, // display_name = identity.nickname
			Status:       domain.AccountStatusActive,
			Source:       domain.AccountSourceProvisioned,
		}
		if account.Email == "" {
			return "", verrors.InternalServerError("identity email missing for auto-provision")
		}
		if err := s.c.AccountRepo().Create(ctx, account); err != nil {
			return "", verrors.Wrap(err, "auto-provision account")
		}
		writeAudit(ctx, s.c, ActorIdentity, identityID, nil, AuditAccountProvisioned, "account", account.Id,
			map[string]any{"app_key": appKey, "via": "oidc_authorize"}, "", "")
		return account.Id, nil
	default:
		return "", verrors.BadRequestError("multiple accounts in this app, pass account_id")
	}
}

// buildAuthorizeCode runs the library's authorize pipeline and returns the
// redirect URL (code+state+iss appended).
func (s *oauthServiceImpl) buildAuthorizeCode(ctx context.Context, va *validatedAuthorize, userID, redirectURI, state, nonce, codeChallenge, codeChallengeMethod string, r *http.Request) (string, error) {
	accountID := strings.TrimPrefix(userID, "account:")
	identityID := ""
	if account, err := s.c.AccountRepo().FindByID(ctx, accountID); err == nil {
		identityID = account.IdentityID
	}
	reqCtx := oauth2x.WithAuthorizeMeta(r.Context(), &oauth2x.AuthorizeMeta{
		Nonce:      nonce,
		AccountID:  accountID,
		IdentityID: identityID,
	})
	req := &server.AuthorizeRequest{
		ResponseType:        oauth2.Code,
		ClientID:            va.client.GetID(),
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               va.scope,
		UserID:              userID,
		Request:             r.WithContext(reqCtx),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: oauth2.CodeChallengeMethod(codeChallengeMethod),
	}
	ti, err := s.engine.Server.GetAuthorizeToken(ctx, req)
	if err != nil {
		return "", mapOAuthError(err)
	}
	data := map[string]any{
		"code": ti.GetCode(),
		"iss":  s.c.Cfg().Auth.IssuerURL,
	}
	return s.engine.Server.GetRedirectURI(req, data)
}

// AuthorizeSPA implements POST /api/v1/oauth/authorize.
func (s *oauthServiceImpl) AuthorizeSPA(ctx context.Context, actx *AuthContextInfo, req *dto.OAuthAuthorizeReq, r *http.Request) (*dto.OAuthAuthorizeResp, error) {
	va, err := s.validateAuthorize(ctx, req.ClientID, req.RedirectURI, req.Scope, req.CodeChallenge, req.CodeChallengeMethod)
	if err != nil {
		return nil, err
	}
	accountID, err := s.resolveAccount(ctx, va.appID, va.appKey, actx.UserID, req.AccountID)
	if err != nil {
		return nil, err
	}
	redirect, err := s.buildAuthorizeCode(ctx, va, "account:"+accountID, req.RedirectURI, req.State, req.Nonce,
		req.CodeChallenge, req.CodeChallengeMethod, r)
	if err != nil {
		return nil, err
	}
	return &dto.OAuthAuthorizeResp{RedirectTo: redirect}, nil
}

// AuthorizeBrowser implements GET /oauth2/authorize. Without a resolvable
// identity it returns the portal login URL (the handler 302s there); with
// one it returns the redirect_uri with the code attached.
func (s *oauthServiceImpl) AuthorizeBrowser(ctx context.Context, identity *BrowserIdentity, r *http.Request) (string, string, error) {
	q := r.URL.Query()
	if rt := q.Get("response_type"); rt != "" && rt != "code" {
		return "", "", oauthErr(400, "unsupported_response_type", "only response_type=code is supported")
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		return "", "", oauthErr(400, "invalid_request", "client_id and redirect_uri are required")
	}
	va, err := s.validateAuthorize(ctx, clientID, redirectURI, q.Get("scope"), q.Get("code_challenge"), q.Get("code_challenge_method"))
	if err != nil {
		return "", "", err
	}
	if identity == nil {
		// Contract: the portal must bounce the browser back to the full
		// authorize URL found in `next` after completing its own login.
		next := s.c.Cfg().Auth.IssuerURL + r.URL.RequestURI()
		login := strings.TrimRight(s.c.Cfg().Auth.PortalURL, "/") + "/login?next=" + url.QueryEscape(next)
		return "", login, nil
	}
	accountID, err := s.resolveAccount(ctx, va.appID, va.appKey, identity.UserID, q.Get("account_id"))
	if err != nil {
		return "", "", err
	}
	redirect, err := s.buildAuthorizeCode(ctx, va, "account:"+accountID, redirectURI, q.Get("state"), q.Get("nonce"),
		q.Get("code_challenge"), q.Get("code_challenge_method"), r)
	if err != nil {
		return "", "", err
	}
	return redirect, "", nil
}

// ---------- token ----------

// Token implements POST /oauth2/token. grant_type dispatch:
//   - authorization_code / client_credentials: delegated to the library
//     engine (PKCE verification, client authentication via the hashed
//     secret, per-client grant checks)
//   - refresh_token: in-place rotation on oauth_refresh_tokens; presenting a
//     rotated hash revokes the whole client family (reuse = leak)
func (s *oauthServiceImpl) Token(ctx context.Context, r *http.Request) (map[string]any, error) {
	if err := r.ParseForm(); err != nil {
		return nil, oauthErr(400, "invalid_request", "malformed form body")
	}
	switch gt := r.PostFormValue("grant_type"); gt {
	case "authorization_code", "client_credentials":
		return s.engineToken(ctx, r, oauth2.GrantType(gt))
	case "refresh_token":
		return s.refreshToken(ctx, r)
	default:
		return nil, oauthErr(400, "unsupported_grant_type", "grant_type must be authorization_code, refresh_token or client_credentials")
	}
}

// engineToken runs the library's GenerateAccessToken (client auth + grant
// checks + PKCE) and appends the OIDC id_token when openid was requested.
func (s *oauthServiceImpl) engineToken(ctx context.Context, r *http.Request, gt oauth2.GrantType) (map[string]any, error) {
	clientID, clientSecret := extractClientCredentials(r)
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Request:      r,
	}
	if gt == oauth2.AuthorizationCode {
		tgr.RedirectURI = r.PostFormValue("redirect_uri")
		tgr.Code = r.PostFormValue("code")
		tgr.CodeVerifier = r.PostFormValue("code_verifier")
		if tgr.RedirectURI == "" || tgr.Code == "" {
			return nil, oauthErr(400, "invalid_request", "code and redirect_uri are required")
		}
	} else {
		tgr.Scope = r.PostFormValue("scope")
	}
	ti, err := s.engine.Manager.GenerateAccessToken(ctx, gt, tgr)
	if err != nil {
		return nil, mapOAuthError(err)
	}
	data := s.engine.Server.GetTokenData(ti)
	// OIDC: id_token only for account subjects that requested openid.
	if ti.GetUserID() != "" && hasScope(ti.GetScope(), ScopeOpenID) {
		idToken, err := s.buildIDToken(ctx, ti)
		if err != nil {
			return nil, err
		}
		data["id_token"] = idToken
	}
	return data, nil
}

// refreshToken rotates the refresh token in place (same row: new hash,
// rotation_count++) and issues a fresh account-subject access token. A
// presented hash that is no longer current but is known (rotated away)
// triggers the family revocation.
func (s *oauthServiceImpl) refreshToken(ctx context.Context, r *http.Request) (map[string]any, error) {
	presented := r.PostFormValue("refresh_token")
	if presented == "" {
		return nil, oauthErr(400, "invalid_request", "refresh_token is required")
	}
	now := time.Now()
	presentedHash := sha256Hex(presented)
	row, err := s.c.OAuthRefreshTokenRepo().FindByTokenHash(ctx, presentedHash)
	if err != nil {
		if !repository.IsNotFound(err) {
			return nil, verrors.Wrap(err, "find refresh token")
		}
		// Not the current hash: a hit in the retired-hash index means the
		// token was already rotated away — treat as a leak and revoke the
		// whole family (the index stores the owning client id).
		if clientID, kvErr := s.c.KV().Get(ctx, oauth2x.RetiredHashPrefix+presentedHash); kvErr == nil && clientID != "" {
			_ = s.c.OAuthRefreshTokenRepo().RevokeAllForClient(ctx, clientID, now)
			writeAudit(ctx, s.c, ActorSystem, "", nil, AuditTokenReuse, "oauth_refresh_token", presentedHash,
				map[string]any{"reason": "oauth refresh token reuse detected", "client_id": clientID}, "", "")
		}
		return nil, oauthErr(400, "invalid_grant", "invalid refresh token")
	}
	if row.RevokedAt != nil {
		return nil, oauthErr(400, "invalid_grant", "refresh token has been revoked")
	}
	if !now.Before(row.ExpiresAt) {
		return nil, oauthErr(400, "invalid_grant", "refresh token expired")
	}
	if row.AccountID == nil || row.UserID == nil {
		return nil, oauthErr(400, "invalid_grant", "refresh token has no account subject")
	}
	// The client must still be active and keep the refresh_token grant.
	client, err := s.c.OAuthClientRepo().FindByID(ctx, row.ClientID)
	if err != nil || client.Status != model.OAuthClientStatusActive {
		return nil, oauthErr(400, "invalid_grant", "client is not authorized")
	}
	if !grantListed(jsonStringsOf(client.GrantTypes), model.OAuthGrantRefreshToken) {
		return nil, oauthErr(400, "invalid_grant", "client is not authorized for the refresh_token grant")
	}

	// Rotate in place and retire the presented hash for the reuse window.
	newToken, err := randomToken()
	if err != nil {
		return nil, verrors.InternalServerError("generate refresh token")
	}
	if err := s.c.OAuthRefreshTokenRepo().UpdateFields(ctx, row.Id, map[string]any{
		"token_hash":     sha256Hex(newToken),
		"rotation_count": row.RotationCount + 1,
		"last_used_at":   now,
	}); err != nil {
		return nil, verrors.Wrap(err, "rotate refresh token")
	}
	_ = s.c.KV().Set(ctx, oauth2x.RetiredHashPrefix+presentedHash, row.ClientID, s.c.Cfg().Auth.RefreshTokenTTL)

	// Fresh access token for the stored account subject.
	claims, err := s.accountClaimsFor(ctx, *row.AccountID, *row.UserID, s.c.Cfg().Auth.AccessTokenTTL)
	if err != nil {
		return nil, err
	}
	access, err := s.c.JWT().Issue(claims)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int64(s.c.Cfg().Auth.AccessTokenTTL.Seconds()),
		"refresh_token": newToken,
		"scope":         row.Scope,
	}, nil
}

// ---------- id_token / userinfo / discovery ----------

// buildIDToken mints the OIDC ID token: iss = the discovery issuer, sub =
// account:{id}, aud = client_id, nonce from the code's extension and at_hash
// = left half of SHA-256(access token), base64url.
func (s *oauthServiceImpl) buildIDToken(ctx context.Context, ti oauth2.TokenInfo) (string, error) {
	nonce := ""
	if ext, ok := ti.(oauth2.ExtendableTokenInfo); ok {
		nonce = ext.GetExtension().Get("nonce")
	}
	accountID := strings.TrimPrefix(ti.GetUserID(), "account:")
	identityID, err := s.identityOfAccount(ctx, accountID)
	if err != nil {
		return "", err
	}
	if _, err := s.accountClaimsFor(ctx, accountID, identityID, s.c.Cfg().Auth.AccessTokenTTL); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(ti.GetAccess()))
	atHash := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
	signed, err := s.c.JWT().IssueIDToken(jwt.NewIDTokenClaims(
		s.c.Cfg().Auth.IssuerURL,
		"account:"+accountID,
		ti.GetClientID(),
		nonce,
		atHash,
		"",
		s.c.Cfg().Auth.AccessTokenTTL,
	))
	if err != nil {
		return "", err
	}
	return signed, nil
}

// accountClaimsFor rebuilds the workspace-token claims from DB rows.
func (s *oauthServiceImpl) accountClaimsFor(ctx context.Context, accountID, identityID string, ttl time.Duration) (*jwt.Claims, error) {
	account, err := s.c.AccountRepo().FindByID(ctx, accountID)
	if err != nil {
		return nil, oauthErr(400, "invalid_grant", "account subject no longer exists")
	}
	identity, err := s.c.UserRepo().FindByID(ctx, identityID)
	if err != nil {
		return nil, oauthErr(400, "invalid_grant", "identity subject no longer exists")
	}
	app, err := s.c.AppRepo().FindByID(ctx, account.AppID)
	if err != nil {
		return nil, oauthErr(400, "invalid_grant", "account app no longer exists")
	}
	// OAuth-issued tokens carry no session id (no portal session row).
	return jwt.NewAccountClaims(account.Id, identity.Id, app.Key, "", identity.Username, identity.Email, ttl), nil
}

// identityOfAccount resolves the owning identity of an account.
func (s *oauthServiceImpl) identityOfAccount(ctx context.Context, accountID string) (string, error) {
	account, err := s.c.AccountRepo().FindByID(ctx, accountID)
	if err != nil {
		return "", oauthErr(400, "invalid_grant", "account subject no longer exists")
	}
	return account.IdentityID, nil
}

// Userinfo implements GET /oauth2/userinfo. Bearer access tokens issued by
// access-hub resolve to their claims' subject: account subjects get the
// profile + roles for the token's app; client subjects get their app
// binding. 401 on anything else.
func (s *oauthServiceImpl) Userinfo(ctx context.Context, bearer string) (map[string]any, error) {
	if bearer == "" {
		return nil, oauthErr(401, "invalid_token", "bearer token required")
	}
	claims, err := s.c.JWT().Parse(bearer)
	if err != nil || claims.IsMFAToken() {
		return nil, oauthErr(401, "invalid_token", "invalid access token")
	}
	switch {
	case claims.IsClientToken():
		clientID := strings.TrimPrefix(claims.Subject, "client:")
		row, err := s.c.OAuthClientRepo().FindByID(ctx, clientID)
		if err != nil || row.Status != model.OAuthClientStatusActive {
			return nil, oauthErr(401, "invalid_token", "unknown client subject")
		}
		return map[string]any{
			"sub": claims.Subject,
			"app": claims.Aud(),
		}, nil
	case claims.IsAccountToken():
		account, err := s.c.AccountRepo().FindByID(ctx, claims.Aid)
		if err != nil || account.Status != domain.AccountStatusActive {
			return nil, oauthErr(401, "invalid_token", "unknown account subject")
		}
		app, err := s.c.AppRepo().FindByID(ctx, account.AppID)
		if err != nil {
			return nil, oauthErr(401, "invalid_token", "unknown app")
		}
		roles := make([]string, 0)
		bindings, err := s.c.AccountRoleRepo().ListByAccount(ctx, account.Id)
		if err == nil {
			now := time.Now()
			for _, b := range bindings {
				if b.RoleAppID != account.AppID {
					continue
				}
				if b.ExpiresAt != nil && b.ExpiresAt.Before(now) {
					continue
				}
				roles = append(roles, b.RoleCode)
			}
		}
		preferred := account.Email
		if account.Username != nil && strings.TrimSpace(*account.Username) != "" {
			preferred = *account.Username
		}
		profile := preferred
		if account.DisplayName != nil && strings.TrimSpace(*account.DisplayName) != "" {
			profile = *account.DisplayName
		}
		return map[string]any{
			"sub":                "account:" + account.Id,
			"email":              account.Email,
			"preferred_username": preferred,
			"profile":            profile,
			"roles":              roles,
			"app":                app.Key,
		}, nil
	default:
		return nil, oauthErr(401, "invalid_token", "token subject is not an OAuth resource")
	}
}

// Discovery builds the OIDC discovery document from the configured issuer.
func (s *oauthServiceImpl) Discovery() map[string]any {
	issuer := strings.TrimRight(s.c.Cfg().Auth.IssuerURL, "/")
	return map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/oauth2/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nonce", "at_hash", "email",
			"preferred_username", "profile", "roles", "app",
		},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	}
}

// ---------- small helpers ----------

// extractClientCredentials reads the client credentials from HTTP Basic
// auth, falling back to the form body (public clients send client_id only).
func extractClientCredentials(r *http.Request) (id, secret string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// grantListed reports whether the grant is present in the decoded list.
func grantListed(grants []string, want string) bool {
	for _, g := range grants {
		if g == want {
			return true
		}
	}
	return false
}
