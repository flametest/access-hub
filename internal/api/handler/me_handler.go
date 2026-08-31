package handler

import (
	"net/http"

	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/labstack/echo/v4"
)

// ---------- identity-scoped /me endpoints ----------

// GetMe handles GET /api/v1/me.
func (h *Handlers) GetMe(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	me, err := h.Me.GetMe(c.Request().Context(), actx.UserID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, me)
}

// UpdateMe handles PATCH /api/v1/me.
func (h *Handlers) UpdateMe(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	req := &dto.UpdateMeReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	info := &service.AuthContextInfo{
		Kind: actx.Kind, UserID: actx.UserID, AccountID: actx.AccountID,
		Aud: actx.Aud, SessionID: actx.SessionID,
	}
	me, err := h.Me.UpdateMe(c.Request().Context(), info, req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, me)
}

// ListMyOrgs handles GET /api/v1/me/orgs.
func (h *Handlers) ListMyOrgs(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	orgs, err := h.Me.ListMyOrgs(c.Request().Context(), actx.UserID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, orgs)
}

// ListWorkspaces handles GET /api/v1/me/workspaces.
func (h *Handlers) ListWorkspaces(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	items, err := h.Me.ListWorkspaces(c.Request().Context(), actx.UserID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, items)
}

// GetWorkspace handles GET /api/v1/me/workspaces/{accountId}.
func (h *Handlers) GetWorkspace(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	item, err := h.Me.GetWorkspace(c.Request().Context(), actx.UserID, c.Param("accountId"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, item)
}

// WorkspaceToken handles POST /api/v1/me/workspaces/{accountId}/token.
func (h *Handlers) WorkspaceToken(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	device, ip := requestInfo(c)
	resp, err := h.Me.WorkspaceToken(c.Request().Context(), actx.UserID, c.Param("accountId"), device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// authInfo converts the middleware AuthContext into the service view.
func authInfo(c echo.Context) *service.AuthContextInfo {
	actx, ok := middleware.AuthOf(c)
	if !ok {
		return nil
	}
	return &service.AuthContextInfo{
		Kind: actx.Kind, UserID: actx.UserID, AccountID: actx.AccountID,
		Aud: actx.Aud, SessionID: actx.SessionID,
	}
}

// Menus handles GET /api/v1/me/menus?app={key}.
func (h *Handlers) Menus(c echo.Context) error {
	menus, err := h.Me.Menus(c.Request().Context(), authInfo(c), c.QueryParam("app"))
	if err != nil {
		return err
	}
	if menus == nil {
		menus = []*dto.MenuNode{}
	}
	return okJSON(c, http.StatusOK, menus)
}

// Permissions handles GET /api/v1/me/permissions?app={key}.
func (h *Handlers) Permissions(c echo.Context) error {
	resp, err := h.Me.Permissions(c.Request().Context(), authInfo(c), c.QueryParam("app"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// SigninMethods handles GET /api/v1/me/signin-methods.
func (h *Handlers) SigninMethods(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	methods, err := h.Me.SigninMethods(c.Request().Context(), actx.UserID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, methods)
}

// ListSessions handles GET /api/v1/me/sessions.
func (h *Handlers) ListSessions(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	sessions, err := h.Me.ListSessions(c.Request().Context(), actx.UserID, actx.SessionID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, sessions)
}

// RevokeSession handles DELETE /api/v1/me/sessions/{id}.
func (h *Handlers) RevokeSession(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	if err := h.Me.RevokeSession(c.Request().Context(), actx.UserID, c.Param("id")); err != nil {
		return err
	}
	return noContent(c)
}

// RevokeOtherSessions handles DELETE /api/v1/me/sessions (keep current).
func (h *Handlers) RevokeOtherSessions(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	if actx.SessionID == "" {
		return verrors.BadRequestError("current session unknown")
	}
	if err := h.Me.RevokeOtherSessions(c.Request().Context(), actx.UserID, actx.SessionID); err != nil {
		return err
	}
	return noContent(c)
}

// ---------- identity-scoped 2FA self-service ----------

// TwoFAStatus handles GET /api/v1/me/2fa/status.
func (h *Handlers) TwoFAStatus(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	resp, err := h.Me.TwoFAStatus(c.Request().Context(), actx.UserID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// TwoFAEnroll handles POST /api/v1/me/2fa/enroll (201).
func (h *Handlers) TwoFAEnroll(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	resp, err := h.Me.TwoFAEnroll(c.Request().Context(), actx.UserID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, resp)
}

// TwoFAConfirm handles POST /api/v1/me/2fa/confirm.
func (h *Handlers) TwoFAConfirm(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	req := &dto.TwoFAConfirmReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.Me.TwoFAConfirm(c.Request().Context(), actx.UserID, req.Code)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// TwoFADisable handles POST /api/v1/me/2fa/disable.
func (h *Handlers) TwoFADisable(c echo.Context) error {
	actx, _ := middleware.AuthOf(c)
	req := &dto.TwoFADisableReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	if err := h.Me.TwoFADisable(c.Request().Context(), actx.UserID, req.Password); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "twofa_disabled"})
}
