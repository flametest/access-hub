// Package middleware implements the access-hub authentication and
// authorization middlewares: Bearer-token parsing with the Redis jti
// denylist, the identity/audience gates and the admin (dogfood) guard that
// resolves the caller's admin-app account and enforces resource codes.
package middleware

import (
	"context"
	"strings"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/jwt"
	"github.com/flametest/vita/verrors"
	"github.com/labstack/echo/v4"
)

// echo context keys used to stash authentication state.
const (
	ctxKeyClaims = "access_hub.claims"
	ctxKeyAuth   = "access_hub.auth"
	ctxKeyAdmin  = "access_hub.admin"
)

// Token kinds (AuthContext.Kind).
const (
	KindIdentity = "identity"
	KindAccount  = "account"
	// KindClient marks an OAuth2 client_credentials service token (sub =
	// client:{id}); it is only meaningful to the OAuth2/userinfo surfaces.
	KindClient = "client"
)

// AuthContext is the resolved caller identity stashed on the echo context.
type AuthContext struct {
	Kind      string // identity | account
	UserID    string // identity id (both kinds: identity tokens directly, account tokens via the account)
	AccountID string // account id (account tokens only)
	Aud       string // token audience
	SessionID string // session id (sid claim)
}

// AdminContext is the admin (dogfood) caller view: the admin-app account
// subject with its org row-level scope.
type AdminContext struct {
	AccountID  string
	IdentityID string
	Platform   bool
	OrgIDs     []string
}

// AuthMiddleware wires the container into the middleware constructors.
type AuthMiddleware struct {
	c container.Container
}

// NewAuth builds the auth middleware set.
func NewAuth(c container.Container) *AuthMiddleware {
	return &AuthMiddleware{c: c}
}

// bearerToken extracts the raw token from the Authorization header.
func bearerToken(c echo.Context) string {
	header := c.Request().Header.Get("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// authenticate parses and validates the presented Bearer token (signature,
// expiry and jti denylist) and stashes claims + AuthContext. A missing token
// yields ("", nil); an invalid one yields an error.
func (m *AuthMiddleware) authenticate(c echo.Context) (*jwt.Claims, error) {
	raw := bearerToken(c)
	if raw == "" {
		return nil, nil
	}
	claims, err := m.c.JWT().Parse(raw)
	if err != nil {
		return nil, err
	}
	// MFA challenge tokens are single-purpose: they may only be presented to
	// the /auth/login/2fa endpoint, never as API credentials.
	if claims.IsMFAToken() {
		return nil, verrors.UnauthorizedError("mfa challenge token cannot be used here")
	}
	// Logged-out (revoked) access tokens are rejected via the Redis denylist.
	if claims.ID != "" {
		if _, err := m.c.KV().Get(c.Request().Context(), "jwt:deny:"+claims.ID); err == nil {
			return nil, verrors.UnauthorizedError("token has been revoked")
		}
	}
	kind := KindIdentity
	userID := strings.TrimPrefix(claims.Subject, jwt.SubjectPrefixUser)
	var accountID string
	switch {
	case claims.IsClientToken():
		kind = KindClient
		userID = strings.TrimPrefix(claims.Subject, jwt.SubjectPrefixClient)
	case claims.IsAccountToken():
		kind = KindAccount
		accountID = claims.Aid
		userID = claims.Iid
	}
	actx := &AuthContext{
		Kind:      kind,
		UserID:    userID,
		AccountID: accountID,
		Aud:       claims.Aud(),
		SessionID: claims.Sid,
	}
	c.Set(ctxKeyClaims, claims)
	c.Set(ctxKeyAuth, actx)
	return claims, nil
}

// OptionalAuth parses the token when present; requests without a token pass
// through anonymously.
func (m *AuthMiddleware) OptionalAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, err := m.authenticate(c); err != nil {
				return err
			}
			return next(c)
		}
	}
}

// RequireToken accepts any valid access token (identity or account).
func (m *AuthMiddleware) RequireToken() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, err := m.authenticate(c); err != nil {
				return err
			}
			if _, ok := AuthOf(c); !ok {
				return verrors.UnauthorizedError("authentication required")
			}
			return next(c)
		}
	}
}

// RequireIdentity accepts only center tokens (aud = access-hub).
func (m *AuthMiddleware) RequireIdentity() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, err := m.authenticate(c); err != nil {
				return err
			}
			actx, ok := AuthOf(c)
			if !ok {
				return verrors.UnauthorizedError("authentication required")
			}
			if actx.Kind != KindIdentity || actx.Aud != jwt.AudienceCentral {
				return verrors.ForbiddenError("identity token required")
			}
			return next(c)
		}
	}
}

// RequireAdmin implements the admin dogfood guard:
//  1. a valid token is required;
//  2. identity tokens must resolve to an ACTIVE account in the admin app;
//     account tokens must be issued for the admin app itself;
//  3. the resolved admin account must pass the resource code via casbin.
//
// The resolved AdminContext (org row-level scope included) is stashed for the
// handlers/services.
func (m *AuthMiddleware) RequireAdmin(code string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, err := m.authenticate(c); err != nil {
				return err
			}
			actx, ok := AuthOf(c)
			if !ok {
				return verrors.UnauthorizedError("authentication required")
			}
			ctx := c.Request().Context()
			var accountID, identityID string
			if actx.Kind == KindAccount {
				if actx.Aud != "admin" {
					return verrors.ForbiddenError("admin app token required")
				}
				accountID = actx.AccountID
				identityID = actx.UserID
				account, err := m.c.AccountRepo().FindByID(ctx, accountID)
				if err != nil {
					return verrors.ForbiddenError("admin account not found")
				}
				if account.Status != domain.AccountStatusActive {
					return verrors.ForbiddenError("admin account is not active")
				}
				identityID = account.IdentityID
			} else {
				identityID = actx.UserID
				adminApp, err := m.c.AppRepo().FindByKey(ctx, "admin")
				if err != nil {
					return verrors.ForbiddenError("admin app not found")
				}
				accounts, err := m.c.AccountRepo().ListByIdentity(ctx, identityID)
				if err != nil {
					return verrors.ForbiddenError("admin account resolution failed")
				}
				for _, account := range accounts {
					if account.AppID == adminApp.Id && account.Status == domain.AccountStatusActive {
						accountID = account.Id
						break
					}
				}
				if accountID == "" {
					return verrors.ForbiddenError("no active account in the admin app")
				}
			}
			allowed, err := m.c.Enforcer().Enforce("account:"+accountID, "admin", code, "*")
			if err != nil {
				return verrors.Wrap(err, "admin authorization check")
			}
			if !allowed {
				return verrors.ForbiddenError("missing admin permission " + code)
			}
			c.Set(ctxKeyAdmin, m.buildAdminContext(ctx, accountID, identityID))
			return next(c)
		}
	}
}

// buildAdminContext resolves the org row-level scope of the admin caller.
func (m *AuthMiddleware) buildAdminContext(ctx context.Context, accountID, identityID string) *AdminContext {
	admin := &AdminContext{AccountID: accountID, IdentityID: identityID}
	reqCtx := ctx
	// Platform scope: passing the platform-only admin:org:read code implies
	// the super_admin wildcard (the only way org_admin could get it is an
	// explicit grant, which the platform never issues).
	allowed, err := m.c.Enforcer().Enforce("account:"+accountID, "admin", "admin:org:read", "*")
	if err == nil && allowed {
		admin.Platform = true
	}
	memberships, err := m.c.OrgMemberRepo().ListByUser(reqCtx, identityID)
	if err == nil {
		for _, mem := range memberships {
			if mem.OrgRole == domain.OrgRoleOwner || mem.OrgRole == domain.OrgRoleAdmin {
				admin.OrgIDs = append(admin.OrgIDs, mem.OrgID)
			}
		}
	}
	return admin
}

// ClaimsOf returns the stashed token claims (nil when anonymous).
func ClaimsOf(c echo.Context) (*jwt.Claims, bool) {
	claims, ok := c.Get(ctxKeyClaims).(*jwt.Claims)
	return claims, ok && claims != nil
}

// AuthOf returns the stashed AuthContext (false when anonymous).
func AuthOf(c echo.Context) (*AuthContext, bool) {
	actx, ok := c.Get(ctxKeyAuth).(*AuthContext)
	return actx, ok && actx != nil
}

// AdminOf returns the stashed AdminContext (false outside admin routes).
func AdminOf(c echo.Context) (*AdminContext, bool) {
	admin, ok := c.Get(ctxKeyAdmin).(*AdminContext)
	return admin, ok && admin != nil
}
