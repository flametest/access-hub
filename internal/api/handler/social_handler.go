package handler

import (
	"net/http"

	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/internal/domain"
	"github.com/flametest/access-hub/internal/infra/social"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/labstack/echo/v4"
)

// ---------- social login (M5; public browser endpoints) ----------

// SocialStart handles GET /api/v1/auth/social/{provider}/start. mode=login is
// anonymous; mode=link needs the caller's identity token (the service answers
// 401 when it is missing). The response is a 302 to the provider
// authorization URL.
func (h *Handlers) SocialStart(c echo.Context) error {
	url, err := h.Social.Start(c.Request().Context(), c.Param("provider"),
		c.QueryParam("redirect"), c.QueryParam("mode"), authInfo(c))
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, url)
}

// SocialCallback handles GET /api/v1/auth/social/{provider}/callback: the
// provider redirects the browser back here with code+state (or ?error=...).
// The outcome is always a 302 — either to the portal page carrying the
// one-time login_code, or to the portal error page.
func (h *Handlers) SocialCallback(c echo.Context) error {
	if c.QueryParam("error") != "" {
		// Provider-side failure (user denied consent, etc.): skip the code
		// exchange and land on the portal error page.
		res, err := h.Social.ProviderFailure(c.Request().Context(),
			c.Param("provider"), c.QueryParam("state"), nil)
		if err != nil {
			return err
		}
		return c.Redirect(http.StatusFound, res.RedirectURL)
	}
	res, err := h.Social.Callback(c.Request().Context(), c.Param("provider"),
		c.QueryParam("code"), c.QueryParam("state"), nil)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, res.RedirectURL)
}

// appleCallbackFields are the form fields Apple may POST (form_post).
var appleCallbackFields = []string{"code", "id_token", "state", "user", "error"}

// AppleCallback handles POST /api/v1/auth/social/apple/callback, Apple's
// form_post response_mode. A POST response cannot redirect, so the outcome is
// 200 + a tiny HTML page doing location.replace(<portal url>) (the service
// builds it for non-nil forms); when the service somehow answers a redirect
// URL the handler falls back to a 302.
func (h *Handlers) AppleCallback(c echo.Context) error {
	form := social.Form{}
	for _, field := range appleCallbackFields {
		if v := c.FormValue(field); v != "" {
			form[field] = v
		}
	}
	if errParam := form.Get("error"); errParam != "" {
		res, err := h.Social.ProviderFailure(c.Request().Context(),
			domain.SocialProviderApple, form.Get("state"), form)
		if err != nil {
			return err
		}
		return renderSocialOutcome(c, res)
	}
	res, err := h.Social.Callback(c.Request().Context(), domain.SocialProviderApple,
		form.Get("code"), form.Get("state"), form)
	if err != nil {
		return err
	}
	return renderSocialOutcome(c, res)
}

// renderSocialOutcome answers a POST (form_post) callback: the self-replacing
// HTML page when the service built one, else the redirect.
func renderSocialOutcome(c echo.Context, res *service.SocialCallbackResult) error {
	if res.HTML != "" {
		return c.HTML(http.StatusOK, res.HTML)
	}
	return c.Redirect(http.StatusFound, res.RedirectURL)
}

// SocialComplete handles POST /api/v1/auth/social/complete: the one-time
// login_code is exchanged for the token pair (or the 2FA challenge plus the
// pending invitations).
func (h *Handlers) SocialComplete(c echo.Context) error {
	req := &dto.SocialCompleteReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	device, ip := requestInfo(c)
	resp, err := h.Social.Complete(c.Request().Context(), req.LoginCode, device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// ---------- me: social identities ----------

// ListSocialIdentities handles GET /api/v1/me/social-identities.
func (h *Handlers) ListSocialIdentities(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	items, err := h.Social.ListIdentities(c.Request().Context(), actx.UserID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, items)
}

// DeleteSocialIdentity handles DELETE /api/v1/me/social-identities/{id}
// (409 when it is the caller's last sign-in method).
func (h *Handlers) DeleteSocialIdentity(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	if err := h.Social.RemoveIdentity(c.Request().Context(), actx.UserID, c.Param("id")); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "social_unlinked"})
}
