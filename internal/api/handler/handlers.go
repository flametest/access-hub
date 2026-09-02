// Package handler implements the HTTP endpoints: one struct per resource
// group, one method per endpoint, DefaultBinder + go-playground/validator
// for request decoding (taskd style).
package handler

import (
	"net/http"
	"sync"

	"net"
	"strings"

	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

// validator is shared (thread-safe once warmed up).
var (
	validateOnce sync.Once
	validatorIns *validator.Validate
)

func validate() *validator.Validate {
	validateOnce.Do(func() { validatorIns = validator.New() })
	return validatorIns
}

// bindBody decodes the JSON body into req and runs the validate tags.
func bindBody(c echo.Context, req any) error {
	binder := echo.DefaultBinder{}
	if err := binder.BindBody(c, req); err != nil {
		return verrors.BadRequestError(err.Error())
	}
	if err := validate().Struct(req); err != nil {
		return verrors.BadRequestError(err.Error())
	}
	return nil
}

// Handlers bundles every endpoint group over the shared services.
type Handlers struct {
	c container.Container

	Auth       service.AuthService
	Me         service.MeService
	Invitation service.InvitationService
	Authz      service.AuthzService
	AdminOrg   service.AdminOrgService
	AdminApp   service.AdminAppService
	AdminUser  service.AdminUserService
	AdminAcc   service.AdminAccountService
	AdminInv   service.AdminInvitationService
	AdminRes   service.AdminResourceService
	AdminRole  service.AdminRoleService
	AdminAudit service.AdminAuditService
	// M6 services.
	AdminCustomRule service.AdminCustomRuleService
	OAuth           service.OAuthService
	AdminOAuth      service.AdminOAuthClientService
	// M5 social login.
	Social service.SocialService
}

// NewHandlers wires all services on top of the container.
func NewHandlers(c container.Container) *Handlers {
	return &Handlers{
		c:          c,
		Auth:       service.NewAuthService(c),
		Me:         service.NewMeService(c),
		Invitation: service.NewInvitationService(c),
		Authz:      service.NewAuthzService(c),
		AdminOrg:   service.NewAdminOrgService(c),
		AdminApp:   service.NewAdminAppService(c),
		AdminUser:  service.NewAdminUserService(c),
		AdminAcc:   service.NewAdminAccountService(c),
		AdminInv:   service.NewAdminInvitationService(c),
		AdminRes:   service.NewAdminResourceService(c),
		AdminRole:  service.NewAdminRoleService(c),
		AdminAudit: service.NewAdminAuditService(c),
		// M6 admin custom rules.
		AdminCustomRule: service.NewAdminCustomRuleService(c),
		OAuth:           service.NewOAuthService(c),
		AdminOAuth:      service.NewAdminOAuthClientService(c),
		Social:          service.NewSocialService(c),
	}
}

// requestInfo extracts the device (User-Agent) and the client IP used for
// sessions, rate limits and audit entries. X-Forwarded-For is honored ONLY
// when the direct peer is a configured trusted proxy (auth.trustedProxies):
// an untrusted client must not forge the header to rotate its apparent IP
// past the login/code rate limits.
func requestInfo(c echo.Context) (device, ip string) {
	device = c.Request().UserAgent()
	ip = peerIP(c)
	if forwarded := c.Request().Header.Get("X-Forwarded-For"); forwarded != "" && trustedProxy(c) {
		// Take the first hop (the original client as seen by the proxy).
		first := forwarded
		for i := 0; i < len(forwarded); i++ {
			if forwarded[i] == ',' {
				first = forwarded[:i]
				break
			}
		}
		if parsed := trimSpace(first); parsed != "" {
			ip = parsed
		}
	}
	return device, ip
}

// peerIP returns the direct TCP peer address (host part only).
func peerIP(c echo.Context) string {
	host, _, err := net.SplitHostPort(c.Request().RemoteAddr)
	if err != nil {
		return c.Request().RemoteAddr
	}
	return host
}

// trustedProxies is the configured auth.trustedProxies list (exact IPs and
// CIDRs), set once via SetTrustedProxies during router wiring. Package-level
// because requestInfo is a free function used across handler files.
var trustedProxies []string

// SetTrustedProxies installs the trusted proxy list used by requestInfo.
func SetTrustedProxies(list []string) { trustedProxies = list }

// trustedProxy reports whether the direct peer is a configured proxy.
func trustedProxy(c echo.Context) bool {
	raw := peerIP(c)
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	for _, entry := range trustedProxies {
		if strings.Contains(entry, "/") {
			if _, network, err := net.ParseCIDR(entry); err == nil && network.Contains(ip) {
				return true
			}
			continue
		}
		if allowed := net.ParseIP(entry); allowed != nil && allowed.Equal(ip) {
			return true
		}
	}
	return false
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// okJSON writes a JSON success response with the given status.
func okJSON(c echo.Context, status int, body any) error {
	return c.JSON(status, body)
}

// noContent writes a 204.
func noContent(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

// dtoToMe is a local alias to keep handler imports minimal.
var _ = dto.RoleSummary{}
