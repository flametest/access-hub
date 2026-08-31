package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/labstack/echo/v4"
)

// writeOAuthError renders RFC-6749 error payloads for the OAuth endpoints
// (everything else flows through the standard verrors pipeline).
func writeOAuthError(c echo.Context, err error) error {
	var oe *service.OAuthError
	if errors.As(err, &oe) {
		return c.JSON(oe.StatusCode, map[string]string{"error": oe.Code, "error_description": oe.Desc})
	}
	return err
}

// ---------- SPA authorize ----------

// OAuthAuthorize handles POST /api/v1/oauth/authorize (center identity
// token required). Responds {redirect_to} for the SPA to navigate to.
func (h *Handlers) OAuthAuthorize(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	req := &dto.OAuthAuthorizeReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.OAuth.AuthorizeSPA(c.Request().Context(), &service.AuthContextInfo{
		Kind: actx.Kind, UserID: actx.UserID, AccountID: actx.AccountID,
		Aud: actx.Aud, SessionID: actx.SessionID,
	}, req, c.Request())
	if err != nil {
		return writeOAuthError(c, err)
	}
	return okJSON(c, http.StatusOK, resp)
}

// ---------- browser authorize ----------

// oauthSessionCookie is the HttpOnly cookie the portal sets with the center
// identity token; the browser authorize endpoint reads it as a fallback to
// the Authorization header.
const oauthSessionCookie = "ah.session"

// oauthBrowserIdentity resolves the caller from the Authorization header or
// the portal session cookie. Only center identity tokens count; anything
// else (missing, invalid, mfa/client/account tokens) means "no session".
func (h *Handlers) oauthBrowserIdentity(c echo.Context) *service.BrowserIdentity {
	raw := c.Request().Header.Get("Authorization")
	if parts := strings.SplitN(raw, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		raw = strings.TrimSpace(parts[1])
	} else if cookie, err := c.Request().Cookie(oauthSessionCookie); err == nil {
		raw = cookie.Value
	} else {
		return nil
	}
	claims, err := h.c.JWT().Parse(raw)
	if err != nil || claims == nil ||
		claims.IsMFAToken() || claims.IsClientToken() || claims.IsAccountToken() {
		return nil
	}
	return &service.BrowserIdentity{UserID: strings.TrimPrefix(claims.Subject, "user:")}
}

// AuthorizeBrowser handles GET /oauth2/authorize: 302 to the redirect_uri
// with the code when a session exists, else 302 to the portal login page
// carrying next={original authorize URL}.
func (h *Handlers) AuthorizeBrowser(c echo.Context) error {
	redirect, login, err := h.OAuth.AuthorizeBrowser(c.Request().Context(), h.oauthBrowserIdentity(c), c.Request())
	if err != nil {
		return writeOAuthError(c, err)
	}
	if login != "" {
		return c.Redirect(http.StatusFound, login)
	}
	return c.Redirect(http.StatusFound, redirect)
}

// ---------- token ----------

// OAuthToken handles POST /oauth2/token (form-encoded; Basic or body client
// auth). Success: {access_token, token_type, expires_in, refresh_token?,
// id_token?, scope}; failure: {error, error_description}.
func (h *Handlers) OAuthToken(c echo.Context) error {
	data, err := h.OAuth.Token(c.Request().Context(), c.Request())
	if err != nil {
		return writeOAuthError(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	return c.JSON(http.StatusOK, data)
}

// ---------- userinfo / discovery ----------

// OAuthUserinfo handles GET /oauth2/userinfo (Bearer access token).
func (h *Handlers) OAuthUserinfo(c echo.Context) error {
	data, err := h.OAuth.Userinfo(c.Request().Context(), bearerTokenOf(c))
	if err != nil {
		return writeOAuthError(c, err)
	}
	return okJSON(c, http.StatusOK, data)
}

// bearerTokenOf extracts the raw bearer token from the Authorization header.
func bearerTokenOf(c echo.Context) string {
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

// OAuthDiscovery handles GET /.well-known/openid-configuration.
func (h *Handlers) OAuthDiscovery(c echo.Context) error {
	return okJSON(c, http.StatusOK, h.OAuth.Discovery())
}
