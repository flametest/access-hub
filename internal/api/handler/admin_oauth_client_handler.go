package handler

import (
	"net/http"

	"github.com/flametest/access-hub/pkg/dto"
	"github.com/labstack/echo/v4"
)

// ---------- admin oauth clients ----------

// AdminListOAuthClients handles GET /api/v1/admin/apps/{appKey}/oauth-clients.
func (h *Handlers) AdminListOAuthClients(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	items, err := h.AdminOAuth.List(c.Request().Context(), actor, c.Param("appKey"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, items)
}

// AdminCreateOAuthClient handles POST /api/v1/admin/apps/{appKey}/oauth-clients
// (201; the plaintext client_secret is returned exactly once).
func (h *Handlers) AdminCreateOAuthClient(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateOAuthClientReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.AdminOAuth.Create(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, resp)
}

// AdminUpdateOAuthClient handles PATCH
// /api/v1/admin/apps/{appKey}/oauth-clients/{clientId}.
func (h *Handlers) AdminUpdateOAuthClient(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateOAuthClientReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminOAuth.Update(c.Request().Context(), actor, c.Param("appKey"), c.Param("clientId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, item)
}

// AdminDeleteOAuthClient handles DELETE
// /api/v1/admin/apps/{appKey}/oauth-clients/{clientId}.
func (h *Handlers) AdminDeleteOAuthClient(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminOAuth.Delete(c.Request().Context(), actor, c.Param("appKey"), c.Param("clientId")); err != nil {
		return err
	}
	return noContent(c)
}
