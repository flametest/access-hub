package handler

import (
	"net/http"

	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/labstack/echo/v4"
)

// InternalBatchResources handles PUT /internal/v1/apps/{appKey}/resources/batch.
// The caller is the business app itself (X-App-Key guard), self-declaring its
// resource manifest on deploy; semantics mirror the admin batch endpoint
// (idempotent upsert by code, optional mode=replace full reconciliation).
func (h *Handlers) InternalBatchResources(c echo.Context) error {
	app, ok := middleware.AppOf(c)
	if !ok {
		return verrors.UnauthorizedError("app context missing")
	}
	req := &dto.BatchResourcesReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.AdminRes.InternalBatch(c.Request().Context(), app, req, c.QueryParam("mode"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}
