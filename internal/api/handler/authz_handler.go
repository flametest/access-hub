package handler

import (
	"net/http"

	"github.com/flametest/access-hub/pkg/dto"
	"github.com/labstack/echo/v4"
)

// ---------- authz (PDP) ----------

// AuthzCheck handles POST /api/v1/authz/check.
func (h *Handlers) AuthzCheck(c echo.Context) error {
	req := &dto.AuthzCheckReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.Authz.Check(c.Request().Context(), req, authInfo(c))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}
