// Package api registers the HTTP routes. The real handler set (auth, me,
// admin, authz) is filled in by the API layer; /api/v1/ping is the wiring
// placeholder.
package api

import (
	"net/http"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/vita/vserver"
	"github.com/labstack/echo/v4"
)

// App owns the HTTP layer.
type App struct {
	c container.Container
}

// NewApp builds the API application on top of the container.
func NewApp(c container.Container) *App {
	return &App{c: c}
}

// pingResponse is the placeholder health payload (field order fixed).
type pingResponse struct {
	Service string `json:"service"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Router registers every route on the vserver Echo server and returns it.
func (a *App) Router(server vserver.Server) vserver.Server {
	srv := server.(*vserver.EchoServer)
	e := srv.GetEchoServer()

	// Placeholder endpoint proving container wiring; replaced by the real
	// handler set later.
	e.GET("/api/v1/ping", func(c echo.Context) error {
		return c.JSON(http.StatusOK, pingResponse{
			Service: "access-hub",
			Code:    0,
			Message: "ok",
		})
	})

	return srv
}
