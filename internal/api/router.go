// Package api registers the HTTP routes and owns the admin (dogfood)
// resource sync. Route style: /api/v1/... via echo e.Add in App.Router.
package api

import (
	"net/http"

	"github.com/flametest/access-hub/internal/api/handler"
	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/vita/vserver"
)

// App owns the HTTP layer.
type App struct {
	c container.Container
}

// NewApp builds the API application on top of the container.
func NewApp(c container.Container) *App {
	return &App{c: c}
}

// Router registers every route on the vserver Echo server and returns it.
func (a *App) Router(server vserver.Server) vserver.Server {
	srv := server.(*vserver.EchoServer)
	e := srv.GetEchoServer()

	auth := middleware.NewAuth(a.c)
	h := handler.NewHandlers(a.c)

	// ----- public (no auth) -----
	e.Add(http.MethodPost, "/api/v1/auth/register", h.Register)
	e.Add(http.MethodPost, "/api/v1/auth/login", h.Login)
	e.Add(http.MethodPost, "/api/v1/auth/login/2fa", h.Login2FA)
	e.Add(http.MethodPost, "/api/v1/auth/account-login", h.AccountLogin)
	e.Add(http.MethodPost, "/api/v1/auth/email/code", h.SendEmailCode)
	e.Add(http.MethodPost, "/api/v1/auth/email/login", h.EmailLogin)
	e.Add(http.MethodPost, "/api/v1/auth/password/set", h.PasswordSet)
	e.Add(http.MethodPost, "/api/v1/auth/password/reset", h.PasswordReset)
	e.Add(http.MethodPost, "/api/v1/auth/accounts/activate", h.AccountActivate)
	e.Add(http.MethodPost, "/api/v1/auth/token/refresh", h.Refresh)
	e.Add(http.MethodPost, "/api/v1/auth/logout", auth.OptionalAuth()(h.Logout))
	e.Add(http.MethodGet, "/.well-known/jwks.json", h.JWKS)

	// ----- invitations (identity or public-with-auto-provision) -----
	e.Add(http.MethodPost, "/api/v1/invitations/redeem", auth.OptionalAuth()(h.Redeem))
	e.Add(http.MethodPost, "/api/v1/invitations/accept", auth.OptionalAuth()(h.Accept))

	// ----- social login (M5; public browser endpoints) -----
	// start: anonymous for mode=login, identity token for mode=link (the
	// service answers 401 when the link-mode caller is anonymous).
	e.Add(http.MethodGet, "/api/v1/auth/social/:provider/start", auth.OptionalAuth()(h.SocialStart))
	e.Add(http.MethodGet, "/api/v1/auth/social/:provider/callback", h.SocialCallback)
	e.Add(http.MethodPost, "/api/v1/auth/social/apple/callback", h.AppleCallback)
	e.Add(http.MethodPost, "/api/v1/auth/social/complete", h.SocialComplete)
	e.Add(http.MethodGet, "/api/v1/me/social-identities", auth.RequireIdentity()(h.ListSocialIdentities))
	e.Add(http.MethodDelete, "/api/v1/me/social-identities/:id", auth.RequireIdentity()(h.DeleteSocialIdentity))

	// ----- identity-scoped (center token) -----
	e.Add(http.MethodGet, "/api/v1/me", auth.RequireIdentity()(h.GetMe))
	e.Add(http.MethodPatch, "/api/v1/me", auth.RequireIdentity()(h.UpdateMe))
	e.Add(http.MethodGet, "/api/v1/me/orgs", auth.RequireIdentity()(h.ListMyOrgs))
	e.Add(http.MethodGet, "/api/v1/me/workspaces", auth.RequireIdentity()(h.ListWorkspaces))
	e.Add(http.MethodGet, "/api/v1/me/workspaces/:accountId", auth.RequireIdentity()(h.GetWorkspace))
	e.Add(http.MethodPost, "/api/v1/me/workspaces/:accountId/token", auth.RequireIdentity()(h.WorkspaceToken))
	e.Add(http.MethodGet, "/api/v1/me/menus", auth.RequireToken()(h.Menus))
	e.Add(http.MethodGet, "/api/v1/me/permissions", auth.RequireToken()(h.Permissions))
	e.Add(http.MethodGet, "/api/v1/me/signin-methods", auth.RequireIdentity()(h.SigninMethods))
	e.Add(http.MethodGet, "/api/v1/me/2fa/status", auth.RequireIdentity()(h.TwoFAStatus))
	e.Add(http.MethodPost, "/api/v1/me/2fa/enroll", auth.RequireIdentity()(h.TwoFAEnroll))
	e.Add(http.MethodPost, "/api/v1/me/2fa/confirm", auth.RequireIdentity()(h.TwoFAConfirm))
	e.Add(http.MethodPost, "/api/v1/me/2fa/disable", auth.RequireIdentity()(h.TwoFADisable))
	e.Add(http.MethodGet, "/api/v1/me/sessions", auth.RequireIdentity()(h.ListSessions))
	e.Add(http.MethodDelete, "/api/v1/me/sessions/:id", auth.RequireIdentity()(h.RevokeSession))
	e.Add(http.MethodDelete, "/api/v1/me/sessions", auth.RequireIdentity()(h.RevokeOtherSessions))

	// ----- authz (PDP; identity or account token) -----
	e.Add(http.MethodPost, "/api/v1/authz/check", auth.RequireToken()(h.AuthzCheck))

	// ----- admin (RequireAdmin(code) per route, 1:1 with AdminResourceDefs) -----
	e.Add(http.MethodGet, "/api/v1/admin/orgs", auth.RequireAdmin("admin:org:read")(h.AdminListOrgs))
	e.Add(http.MethodPost, "/api/v1/admin/orgs", auth.RequireAdmin("admin:org:manage")(h.AdminCreateOrg))
	e.Add(http.MethodPatch, "/api/v1/admin/orgs/:orgKey", auth.RequireAdmin("admin:org:manage")(h.AdminUpdateOrg))
	e.Add(http.MethodGet, "/api/v1/admin/orgs/:orgKey/members", auth.RequireAdmin("admin:org:read")(h.AdminListOrgMembers))
	e.Add(http.MethodPost, "/api/v1/admin/orgs/:orgKey/members", auth.RequireAdmin("admin:org:member:manage")(h.AdminAddOrgMember))
	e.Add(http.MethodDelete, "/api/v1/admin/orgs/:orgKey/members/:userId", auth.RequireAdmin("admin:org:member:manage")(h.AdminRemoveOrgMember))

	e.Add(http.MethodGet, "/api/v1/admin/apps", auth.RequireAdmin("admin:app:read")(h.AdminListApps))
	e.Add(http.MethodPost, "/api/v1/admin/apps", auth.RequireAdmin("admin:app:manage")(h.AdminCreateApp))
	e.Add(http.MethodPatch, "/api/v1/admin/apps/:appKey", auth.RequireAdmin("admin:app:manage")(h.AdminUpdateApp))
	e.Add(http.MethodDelete, "/api/v1/admin/apps/:appKey", auth.RequireAdmin("admin:app:manage")(h.AdminDeleteApp))

	e.Add(http.MethodGet, "/api/v1/admin/users", auth.RequireAdmin("admin:user:read")(h.AdminListUsers))
	e.Add(http.MethodPatch, "/api/v1/admin/users/:userId", auth.RequireAdmin("admin:user:manage")(h.AdminUpdateUser))
	e.Add(http.MethodPost, "/api/v1/admin/users/:userId/reset-password", auth.RequireAdmin("admin:user:manage")(h.AdminResetUserPassword))

	e.Add(http.MethodGet, "/api/v1/admin/apps/:appKey/accounts", auth.RequireAdmin("admin:account:read")(h.AdminListAccounts))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/accounts", auth.RequireAdmin("admin:account:manage")(h.AdminCreateAccount))
	e.Add(http.MethodPatch, "/api/v1/admin/apps/:appKey/accounts/:accountId", auth.RequireAdmin("admin:account:manage")(h.AdminUpdateAccount))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/accounts/:accountId/reset-password", auth.RequireAdmin("admin:account:manage")(h.AdminResetAccountPassword))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/accounts/:accountId/transfer", auth.RequireAdmin("admin:account:manage")(h.AdminTransferAccount))
	e.Add(http.MethodPut, "/api/v1/admin/apps/:appKey/accounts/:accountId/roles", auth.RequireAdmin("admin:account:manage")(h.AdminSetAccountRoles))
	e.Add(http.MethodGet, "/api/v1/admin/apps/:appKey/accounts/:accountId/grants", auth.RequireAdmin("admin:grant:manage")(h.AdminListGrants))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/accounts/:accountId/grants", auth.RequireAdmin("admin:grant:manage")(h.AdminAddGrant))
	e.Add(http.MethodDelete, "/api/v1/admin/apps/:appKey/accounts/:accountId/grants/:grantId", auth.RequireAdmin("admin:grant:manage")(h.AdminRemoveGrant))

	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/invitations", auth.RequireAdmin("admin:invitation:manage")(h.AdminCreateInvitation))
	e.Add(http.MethodGet, "/api/v1/admin/apps/:appKey/invitations", auth.RequireAdmin("admin:invitation:manage")(h.AdminListInvitations))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/invitations/:invitationId/revoke", auth.RequireAdmin("admin:invitation:manage")(h.AdminRevokeInvitation))

	e.Add(http.MethodGet, "/api/v1/admin/apps/:appKey/resources", auth.RequireAdmin("admin:resource:manage")(h.AdminResourceTree))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/resources", auth.RequireAdmin("admin:resource:manage")(h.AdminCreateResource))
	e.Add(http.MethodPatch, "/api/v1/admin/apps/:appKey/resources/:resourceId", auth.RequireAdmin("admin:resource:manage")(h.AdminUpdateResource))
	e.Add(http.MethodDelete, "/api/v1/admin/apps/:appKey/resources/:resourceId", auth.RequireAdmin("admin:resource:manage")(h.AdminDeleteResource))
	e.Add(http.MethodPut, "/api/v1/admin/apps/:appKey/resources:batch", auth.RequireAdmin("admin:resource:manage")(h.AdminBatchResources))

	e.Add(http.MethodGet, "/api/v1/admin/apps/:appKey/roles", auth.RequireAdmin("admin:role:manage")(h.AdminListRoles))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/roles", auth.RequireAdmin("admin:role:manage")(h.AdminCreateRole))
	e.Add(http.MethodPatch, "/api/v1/admin/apps/:appKey/roles/:roleId", auth.RequireAdmin("admin:role:manage")(h.AdminUpdateRole))
	e.Add(http.MethodDelete, "/api/v1/admin/apps/:appKey/roles/:roleId", auth.RequireAdmin("admin:role:manage")(h.AdminDeleteRole))
	e.Add(http.MethodPut, "/api/v1/admin/apps/:appKey/roles/:roleId/resources", auth.RequireAdmin("admin:role:manage")(h.AdminSetRoleResources))

	e.Add(http.MethodGet, "/api/v1/admin/audit-logs", auth.RequireAdmin("admin:audit:read")(h.AdminListAuditLogs))
	e.Add(http.MethodGet, "/api/v1/admin/audit-logs/summary", auth.RequireAdmin("admin:audit:read")(h.AdminAuditSummary))

	// ----- admin custom rules (M6; app-scoped codes -> org_admin binds) -----
	e.Add(http.MethodGet, "/api/v1/admin/apps/:appKey/custom-rules", auth.RequireAdmin("admin:customrule:read")(h.AdminListCustomRules))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/custom-rules", auth.RequireAdmin("admin:customrule:manage")(h.AdminCreateCustomRule))
	e.Add(http.MethodPatch, "/api/v1/admin/apps/:appKey/custom-rules/:ruleId", auth.RequireAdmin("admin:customrule:manage")(h.AdminUpdateCustomRule))
	e.Add(http.MethodDelete, "/api/v1/admin/apps/:appKey/custom-rules/:ruleId", auth.RequireAdmin("admin:customrule:manage")(h.AdminDeleteCustomRule))
	// Dry-run: evaluates an expression against the caller's own subject
	// without persisting anything (a read-ish op -> :read code).
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/custom-rules/test", auth.RequireAdmin("admin:customrule:read")(h.AdminTestCustomRule))

	// ----- oauth2/oidc provider (M4) -----
	// SPA-friendly JSON authorize (center identity token).
	e.Add(http.MethodPost, "/api/v1/oauth/authorize", auth.RequireIdentity()(h.OAuthAuthorize))
	// Standard browser endpoints (public; the authorize endpoint redirects
	// anonymous users to the portal login).
	e.Add(http.MethodGet, "/oauth2/authorize", h.AuthorizeBrowser)
	e.Add(http.MethodPost, "/oauth2/token", h.OAuthToken)
	e.Add(http.MethodGet, "/oauth2/userinfo", h.OAuthUserinfo)
	e.Add(http.MethodGet, "/.well-known/openid-configuration", h.OAuthDiscovery)

	// ----- admin oauth clients (M4; app-scoped codes -> org_admin binds) -----
	e.Add(http.MethodGet, "/api/v1/admin/apps/:appKey/oauth-clients", auth.RequireAdmin("admin:oauthclient:read")(h.AdminListOAuthClients))
	e.Add(http.MethodPost, "/api/v1/admin/apps/:appKey/oauth-clients", auth.RequireAdmin("admin:oauthclient:manage")(h.AdminCreateOAuthClient))
	e.Add(http.MethodPatch, "/api/v1/admin/apps/:appKey/oauth-clients/:clientId", auth.RequireAdmin("admin:oauthclient:manage")(h.AdminUpdateOAuthClient))
	e.Add(http.MethodDelete, "/api/v1/admin/apps/:appKey/oauth-clients/:clientId", auth.RequireAdmin("admin:oauthclient:manage")(h.AdminDeleteOAuthClient))

	return srv
}
