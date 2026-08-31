package handler

import (
	"encoding/json"
	"net/http"

	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/labstack/echo/v4"
)

// ---------- public auth endpoints ----------

// Register handles POST /api/v1/auth/register (201).
func (h *Handlers) Register(c echo.Context) error {
	req := &dto.RegisterReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	device, ip := requestInfo(c)
	resp, err := h.Auth.Register(c.Request().Context(), req, device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, resp)
}

// Login handles POST /api/v1/auth/login (identity token pair).
func (h *Handlers) Login(c echo.Context) error {
	req := &dto.LoginReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	device, ip := requestInfo(c)
	resp, err := h.Auth.Login(c.Request().Context(), req, device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// Login2FA handles POST /api/v1/auth/login/2fa: completes the 2FA login
// challenge with the short-lived mfa_token plus a TOTP or backup code.
func (h *Handlers) Login2FA(c echo.Context) error {
	req := &dto.Login2FAReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	device, ip := requestInfo(c)
	resp, err := h.Auth.Login2FA(c.Request().Context(), req, device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// AccountLogin handles POST /api/v1/auth/account-login (workspace direct
// sign-in, account token pair).
func (h *Handlers) AccountLogin(c echo.Context) error {
	req := &dto.AccountLoginReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	device, ip := requestInfo(c)
	resp, err := h.Auth.AccountLogin(c.Request().Context(), req, device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// SendEmailCode handles POST /api/v1/auth/email/code (always 202).
func (h *Handlers) SendEmailCode(c echo.Context) error {
	req := &dto.SendEmailCodeReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	_, ip := requestInfo(c)
	if err := h.Auth.SendEmailCode(c.Request().Context(), req, ip); err != nil {
		return err
	}
	return c.JSON(http.StatusAccepted, map[string]string{"status": "sent"})
}

// EmailLogin handles POST /api/v1/auth/email/login.
func (h *Handlers) EmailLogin(c echo.Context) error {
	req := &dto.EmailLoginReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	device, ip := requestInfo(c)
	resp, err := h.Auth.EmailLogin(c.Request().Context(), req, device, ip)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// PasswordSet handles POST /api/v1/auth/password/set.
func (h *Handlers) PasswordSet(c echo.Context) error {
	req := &dto.PasswordSetReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	if err := h.Auth.PasswordSet(c.Request().Context(), req); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "password_set"})
}

// PasswordReset handles POST /api/v1/auth/password/reset.
func (h *Handlers) PasswordReset(c echo.Context) error {
	req := &dto.PasswordResetReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	if err := h.Auth.PasswordReset(c.Request().Context(), req); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "password_reset"})
}

// AccountActivate handles POST /api/v1/auth/accounts/activate.
func (h *Handlers) AccountActivate(c echo.Context) error {
	req := &dto.AccountActivateReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.Auth.AccountActivate(c.Request().Context(), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// Refresh handles POST /api/v1/auth/token/refresh (in-place rotation).
func (h *Handlers) Refresh(c echo.Context) error {
	req := &dto.RefreshReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.Auth.Refresh(c.Request().Context(), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// Logout handles POST /api/v1/auth/logout (auth optional, idempotent 204).
func (h *Handlers) Logout(c echo.Context) error {
	req := &dto.LogoutReq{}
	// Body is optional: an empty body must not fail.
	_ = bindBody(c, req)
	var claims *service.ClaimsLike
	if raw, ok := middleware.ClaimsOf(c); ok {
		claims = &service.ClaimsLike{
			Subject:   raw.Subject,
			Audience:  raw.Aud(),
			ID:        raw.ID,
			SessionID: raw.Sid,
			ExpiresAt: raw.ExpiresAt.Time,
			IsAccount: raw.IsAccountToken(),
		}
	}
	if err := h.Auth.Logout(c.Request().Context(), req.RefreshToken, claims); err != nil {
		return err
	}
	return noContent(c)
}

// JWKS handles GET /.well-known/jwks.json.
func (h *Handlers) JWKS(c echo.Context) error {
	raw, err := h.c.JWT().JWKS()
	if err != nil {
		return err
	}
	var doc json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, doc)
}
