package handler

import (
	"net/http"

	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/labstack/echo/v4"
)

// ---------- invitation endpoints (identity or public-with-auto-provision) ----------

// Redeem handles POST /api/v1/invitations/redeem.
func (h *Handlers) Redeem(c echo.Context) error {
	req := &dto.RedeemReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	identityID := ""
	if actx, ok := middleware.AuthOf(c); ok && actx.Kind == middleware.KindIdentity {
		identityID = actx.UserID
	}
	preview, err := h.Invitation.Redeem(c.Request().Context(), req, identityID)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, preview)
}

// Accept handles POST /api/v1/invitations/accept.
func (h *Handlers) Accept(c echo.Context) error {
	req := &dto.AcceptReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	device, ip := requestInfo(c)
	actx := authInfo(c) // nil when anonymous
	resp, err := h.Invitation.Accept(c.Request().Context(), req, actx, device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}
