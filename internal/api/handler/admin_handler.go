package handler

import (
	"net/http"

	"strconv"

	"github.com/flametest/access-hub/internal/api/middleware"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/access-hub/pkg/dto"
	"github.com/flametest/vita/verrors"
	"github.com/labstack/echo/v4"
)

// adminActor converts the middleware AdminContext into the service view.
func adminActor(c echo.Context) (*service.AdminActor, error) {
	admin, ok := middleware.AdminOf(c)
	if !ok {
		return nil, verrors.ForbiddenError("admin context missing")
	}
	return &service.AdminActor{
		AccountID:  admin.AccountID,
		IdentityID: admin.IdentityID,
		Platform:   admin.Platform,
		OrgIDs:     admin.OrgIDs,
	}, nil
}

// ---------- orgs ----------

// AdminListOrgs handles GET /api/v1/admin/orgs.
func (h *Handlers) AdminListOrgs(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	orgs, err := h.AdminOrg.List(c.Request().Context(), actor)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, orgs)
}

// AdminCreateOrg handles POST /api/v1/admin/orgs.
func (h *Handlers) AdminCreateOrg(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateOrgReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	org, err := h.AdminOrg.Create(c.Request().Context(), actor, req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, org)
}

// AdminUpdateOrg handles PATCH /api/v1/admin/orgs/{orgKey}.
func (h *Handlers) AdminUpdateOrg(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateOrgReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	org, err := h.AdminOrg.Update(c.Request().Context(), actor, c.Param("orgKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, org)
}

// AdminListOrgMembers handles GET /api/v1/admin/orgs/{orgKey}/members.
func (h *Handlers) AdminListOrgMembers(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	members, err := h.AdminOrg.ListMembers(c.Request().Context(), actor, c.Param("orgKey"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, members)
}

// AdminAddOrgMember handles POST /api/v1/admin/orgs/{orgKey}/members.
func (h *Handlers) AdminAddOrgMember(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.AddOrgMemberReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	member, err := h.AdminOrg.AddMember(c.Request().Context(), actor, c.Param("orgKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, member)
}

// AdminRemoveOrgMember handles DELETE /api/v1/admin/orgs/{orgKey}/members/{userId}.
func (h *Handlers) AdminRemoveOrgMember(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminOrg.RemoveMember(c.Request().Context(), actor, c.Param("orgKey"), c.Param("userId")); err != nil {
		return err
	}
	return noContent(c)
}

// ---------- apps ----------

// AdminListApps handles GET /api/v1/admin/apps?org={key}.
func (h *Handlers) AdminListApps(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	apps, err := h.AdminApp.List(c.Request().Context(), actor, c.QueryParam("org"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, apps)
}

// AdminCreateApp handles POST /api/v1/admin/apps.
func (h *Handlers) AdminCreateApp(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateAppReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	app, err := h.AdminApp.Create(c.Request().Context(), actor, req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, app)
}

// AdminUpdateApp handles PATCH /api/v1/admin/apps/{appKey}.
func (h *Handlers) AdminUpdateApp(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateAppReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	app, err := h.AdminApp.Update(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, app)
}

// AdminDeleteApp handles DELETE /api/v1/admin/apps/{appKey}.
func (h *Handlers) AdminDeleteApp(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminApp.Delete(c.Request().Context(), actor, c.Param("appKey")); err != nil {
		return err
	}
	return noContent(c)
}

// ---------- users ----------

// AdminListUsers handles GET /api/v1/admin/users?q=&page=&page_size=.
func (h *Handlers) AdminListUsers(c echo.Context) error {
	page := intQuery(c, "page", 1)
	pageSize := intQuery(c, "page_size", 50)
	resp, err := h.AdminUser.List(c.Request().Context(), c.QueryParam("q"), page, pageSize)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// AdminUpdateUser handles PATCH /api/v1/admin/users/{userId}.
func (h *Handlers) AdminUpdateUser(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateUserReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminUser.UpdateStatus(c.Request().Context(), actor, c.Param("userId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, item)
}

// AdminResetUserPassword handles POST /api/v1/admin/users/{userId}/reset-password.
func (h *Handlers) AdminResetUserPassword(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.ResetPasswordReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	if err := h.AdminUser.ResetPassword(c.Request().Context(), actor, c.Param("userId"), req); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "password_reset"})
}

// ---------- accounts ----------

// AdminListAccounts handles GET /api/v1/admin/apps/{appKey}/accounts?q=&status=&page=&page_size=.
func (h *Handlers) AdminListAccounts(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	page, _ := strconv.Atoi(c.QueryParam("page"))
	pageSize, _ := strconv.Atoi(c.QueryParam("page_size"))
	resp, err := h.AdminAcc.List(c.Request().Context(), actor, c.Param("appKey"), c.QueryParam("q"), c.QueryParam("status"), page, pageSize)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// AdminListRoleResources handles GET /api/v1/admin/apps/{appKey}/roles/{roleId}/resources.
func (h *Handlers) AdminListRoleResources(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	resp, err := h.AdminRole.ListResources(c.Request().Context(), actor, c.Param("appKey"), c.Param("roleId"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// AdminCreateAccount handles POST /api/v1/admin/apps/{appKey}/accounts.
func (h *Handlers) AdminCreateAccount(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateAccountReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.AdminAcc.Create(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, resp)
}

// AdminUpdateAccount handles PATCH /api/v1/admin/apps/{appKey}/accounts/{accountId}.
func (h *Handlers) AdminUpdateAccount(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateAccountReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminAcc.Update(c.Request().Context(), actor, c.Param("appKey"), c.Param("accountId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, item)
}

// AdminResetAccountPassword handles POST .../accounts/{accountId}/reset-password.
func (h *Handlers) AdminResetAccountPassword(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.ResetPasswordReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	if err := h.AdminAcc.ResetPassword(c.Request().Context(), actor, c.Param("appKey"), c.Param("accountId"), req); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "password_reset"})
}

// AdminTransferAccount handles POST .../accounts/{accountId}/transfer.
func (h *Handlers) AdminTransferAccount(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.TransferAccountReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	if err := h.AdminAcc.Transfer(c.Request().Context(), actor, c.Param("appKey"), c.Param("accountId"), req); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "transferred"})
}

// AdminSetAccountRoles handles PUT .../accounts/{accountId}/roles.
func (h *Handlers) AdminSetAccountRoles(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.SetAccountRolesReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	roles, err := h.AdminAcc.SetRoles(c.Request().Context(), actor, c.Param("appKey"), c.Param("accountId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, roles)
}

// ---------- grants ----------

// AdminListGrants handles GET .../accounts/{accountId}/grants.
func (h *Handlers) AdminListGrants(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	grants, err := h.AdminAcc.ListGrants(c.Request().Context(), actor, c.Param("appKey"), c.Param("accountId"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, grants)
}

// AdminAddGrant handles POST .../accounts/{accountId}/grants.
func (h *Handlers) AdminAddGrant(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.AddGrantReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	grant, err := h.AdminAcc.AddGrant(c.Request().Context(), actor, c.Param("appKey"), c.Param("accountId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, grant)
}

// AdminRemoveGrant handles DELETE .../accounts/{accountId}/grants/{grantId}.
func (h *Handlers) AdminRemoveGrant(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminAcc.RemoveGrant(c.Request().Context(), actor, c.Param("appKey"), c.Param("accountId"), c.Param("grantId")); err != nil {
		return err
	}
	return noContent(c)
}

// ---------- invitations (admin) ----------

// AdminCreateInvitation handles POST /api/v1/admin/apps/{appKey}/invitations.
func (h *Handlers) AdminCreateInvitation(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateInvitationReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminInv.Create(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, item)
}

// AdminListInvitations handles GET /api/v1/admin/apps/{appKey}/invitations?status=.
func (h *Handlers) AdminListInvitations(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	items, err := h.AdminInv.List(c.Request().Context(), actor, c.Param("appKey"), c.QueryParam("status"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, items)
}

// AdminRevokeInvitation handles POST .../invitations/{invitationId}/revoke.
func (h *Handlers) AdminRevokeInvitation(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminInv.Revoke(c.Request().Context(), actor, c.Param("appKey"), c.Param("invitationId")); err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, map[string]string{"status": "revoked"})
}

// ---------- resources ----------

// AdminResourceTree handles GET /api/v1/admin/apps/{appKey}/resources.
func (h *Handlers) AdminResourceTree(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	tree, err := h.AdminRes.Tree(c.Request().Context(), actor, c.Param("appKey"))
	if err != nil {
		return err
	}
	if tree == nil {
		tree = []*dto.AdminResourceItem{}
	}
	return okJSON(c, http.StatusOK, tree)
}

// AdminCreateResource handles POST /api/v1/admin/apps/{appKey}/resources.
func (h *Handlers) AdminCreateResource(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateResourceReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminRes.Create(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, item)
}

// AdminUpdateResource handles PATCH .../resources/{resourceId}.
func (h *Handlers) AdminUpdateResource(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateResourceReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminRes.Update(c.Request().Context(), actor, c.Param("appKey"), c.Param("resourceId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, item)
}

// AdminDeleteResource handles DELETE .../resources/{resourceId}.
func (h *Handlers) AdminDeleteResource(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminRes.Delete(c.Request().Context(), actor, c.Param("appKey"), c.Param("resourceId")); err != nil {
		return err
	}
	return noContent(c)
}

// AdminBatchResources handles PUT /api/v1/admin/apps/{appKey}/resources:batch.
func (h *Handlers) AdminBatchResources(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.BatchResourcesReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.AdminRes.Batch(c.Request().Context(), actor, c.Param("appKey"), req, c.QueryParam("mode"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// ---------- roles ----------

// AdminListRoles handles GET /api/v1/admin/apps/{appKey}/roles.
func (h *Handlers) AdminListRoles(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	roles, err := h.AdminRole.List(c.Request().Context(), actor, c.Param("appKey"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, roles)
}

// AdminCreateRole handles POST /api/v1/admin/apps/{appKey}/roles.
func (h *Handlers) AdminCreateRole(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateRoleReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	role, err := h.AdminRole.Create(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, role)
}

// AdminUpdateRole handles PATCH .../roles/{roleId}.
func (h *Handlers) AdminUpdateRole(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateRoleReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	role, err := h.AdminRole.Update(c.Request().Context(), actor, c.Param("appKey"), c.Param("roleId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, role)
}

// AdminDeleteRole handles DELETE .../roles/{roleId}.
func (h *Handlers) AdminDeleteRole(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminRole.Delete(c.Request().Context(), actor, c.Param("appKey"), c.Param("roleId")); err != nil {
		return err
	}
	return noContent(c)
}

// AdminSetRoleResources handles PUT .../roles/{roleId}/resources.
func (h *Handlers) AdminSetRoleResources(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.SetRoleResourcesReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	codes, err := h.AdminRole.SetResources(c.Request().Context(), actor, c.Param("appKey"), c.Param("roleId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, codes)
}

// ---------- audit logs ----------

// AdminListAuditLogs handles GET /api/v1/admin/audit-logs?action=&org_key=&page=&page_size=.
func (h *Handlers) AdminListAuditLogs(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	page := intQuery(c, "page", 1)
	pageSize := intQuery(c, "page_size", 50)
	resp, err := h.AdminAudit.List(c.Request().Context(), actor, c.QueryParam("action"), c.QueryParam("org_key"), page, pageSize)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// AdminAuditSummary handles GET /api/v1/admin/audit-logs/summary?days=7 (M6).
func (h *Handlers) AdminAuditSummary(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	resp, err := h.AdminAudit.Summary(c.Request().Context(), actor, intQuery(c, "days", 7))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// ---------- custom rules (M6) ----------

// AdminListCustomRules handles GET /api/v1/admin/apps/{appKey}/custom-rules.
func (h *Handlers) AdminListCustomRules(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	items, err := h.AdminCustomRule.List(c.Request().Context(), actor, c.Param("appKey"))
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, items)
}

// AdminCreateCustomRule handles POST /api/v1/admin/apps/{appKey}/custom-rules.
func (h *Handlers) AdminCreateCustomRule(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.CreateCustomRuleReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminCustomRule.Create(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusCreated, item)
}

// AdminUpdateCustomRule handles PATCH .../custom-rules/{ruleId}.
func (h *Handlers) AdminUpdateCustomRule(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.UpdateCustomRuleReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	item, err := h.AdminCustomRule.Update(c.Request().Context(), actor, c.Param("appKey"), c.Param("ruleId"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, item)
}

// AdminDeleteCustomRule handles DELETE .../custom-rules/{ruleId}.
func (h *Handlers) AdminDeleteCustomRule(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	if err := h.AdminCustomRule.Delete(c.Request().Context(), actor, c.Param("appKey"), c.Param("ruleId")); err != nil {
		return err
	}
	return noContent(c)
}

// AdminTestCustomRule handles POST .../custom-rules/test (dry-run, nothing
// persisted).
func (h *Handlers) AdminTestCustomRule(c echo.Context) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	req := &dto.TestCustomRuleReq{}
	if err := bindBody(c, req); err != nil {
		return err
	}
	resp, err := h.AdminCustomRule.Test(c.Request().Context(), actor, c.Param("appKey"), req)
	if err != nil {
		return err
	}
	return okJSON(c, http.StatusOK, resp)
}

// intQuery reads an int query parameter with a default.
func intQuery(c echo.Context, name string, def int) int {
	raw := c.QueryParam(name)
	if raw == "" {
		return def
	}
	n := 0
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	if n == 0 {
		return def
	}
	return n
}
