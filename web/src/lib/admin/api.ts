import { request } from "@/lib/api";
import {
  toAdminAccountPage,
  toAdminApps,
  toAdminInvitations,
  toAdminRoles,
  toAdminUserPage,
  toAuditLogPage,
  toAuditSummary,
  toBatchResourcesResp,
  toCustomRuleTestResult,
  toCustomRules,
  toGrants,
  toOAuthClientCreateResult,
  toOAuthClients,
  toOrgMembers,
  toOrgs,
  toResourceTree,
} from "@/lib/admin/normalize";
import { flattenResourceTree } from "@/lib/admin/normalize";
import type {
  AddOrgMemberReq,
  AdminAccount,
  AdminApp,
  AdminInvitation,
  AdminRole,
  AdminUser,
  AuditLog,
  AuditSummary,
  BatchResourceItem,
  BatchResourcesResp,
  CreateAppReq,
  CreateOrgReq,
  CustomRule,
  CustomRuleTestResult,
  Grant,
  OAuthClient,
  OAuthClientCreateResult,
  Org,
  OrgMember,
  Paged,
  ProvisionAccountReq,
  ProvisionAccountResp,
  ResourceNode,
  ResourceRow,
  RoleResourceItem,
  UpdateAppReq,
  UpdateOrgReq,
} from "@/lib/admin/types";

/**
 * Admin console API client (docs/design.md §8 admin block + §12 M6). Every
 * call rides the portal access token (`ah.access`): the backend resolves the
 * admin-app account + Casbin codes server-side, so a 403 means "this section
 * isn't available to you" and pages render the ForbiddenCard placeholder.
 *
 * Custom rules + audit summary are M6 contracts; until the backend lands them
 * the queries surface a friendly error card (tolerant normalizers, no crash).
 */

const enc = encodeURIComponent;

export const adminApi = {
  // ---------- orgs ----------

  listOrgs: async (): Promise<Org[]> => toOrgs(await request<unknown>("/admin/orgs")),

  createOrg: (body: CreateOrgReq): Promise<Org> =>
    request<Org>("/admin/orgs", { method: "POST", body }),

  updateOrg: (orgKey: string, body: UpdateOrgReq): Promise<Org> =>
    request<Org>(`/admin/orgs/${enc(orgKey)}`, { method: "PATCH", body }),

  listOrgMembers: async (orgKey: string): Promise<OrgMember[]> =>
    toOrgMembers(await request<unknown>(`/admin/orgs/${enc(orgKey)}/members`)),

  addOrgMember: (orgKey: string, body: AddOrgMemberReq): Promise<OrgMember> =>
    request<OrgMember>(`/admin/orgs/${enc(orgKey)}/members`, {
      method: "POST",
      body,
    }),

  removeOrgMember: (orgKey: string, userId: string): Promise<void> =>
    request<void>(
      `/admin/orgs/${enc(orgKey)}/members/${enc(userId)}`,
      { method: "DELETE" },
    ),

  // ---------- apps ----------

  listApps: async (orgKey?: string): Promise<AdminApp[]> =>
    toAdminApps(
      await request<unknown>(
        orgKey ? `/admin/apps?org=${enc(orgKey)}` : "/admin/apps",
      ),
    ),

  createApp: (body: CreateAppReq): Promise<AdminApp> =>
    request<AdminApp>("/admin/apps", { method: "POST", body }),

  updateApp: (appKey: string, body: UpdateAppReq): Promise<AdminApp> =>
    request<AdminApp>(`/admin/apps/${enc(appKey)}`, { method: "PATCH", body }),

  // ---------- users (primary identities) ----------

  listUsers: async (
    q: string,
    page: number,
    pageSize: number,
  ): Promise<Paged<AdminUser>> =>
    toAdminUserPage(
      await request<unknown>(
        `/admin/users?q=${enc(q)}&page=${page}&page_size=${pageSize}`,
      ),
    ),

  updateUserStatus: (userId: string, status: string): Promise<void> =>
    request<void>(`/admin/users/${enc(userId)}`, {
      method: "PATCH",
      body: { status },
    }),

  resetUserPassword: (userId: string, newPassword: string): Promise<void> =>
    request<void>(`/admin/users/${enc(userId)}/reset-password`, {
      method: "POST",
      body: { new_password: newPassword },
    }),

  // ---------- accounts ----------

  listAccounts: async (
    appKey: string,
    q = "",
    status = "",
  ): Promise<Paged<AdminAccount>> =>
    toAdminAccountPage(
      await request<unknown>(
        `/admin/apps/${enc(appKey)}/accounts?q=${enc(q)}&status=${enc(status)}`,
      ),
    ),

  provisionAccount: (
    appKey: string,
    body: ProvisionAccountReq,
  ): Promise<ProvisionAccountResp> =>
    request<ProvisionAccountResp>(`/admin/apps/${enc(appKey)}/accounts`, {
      method: "POST",
      body,
    }),

  updateAccount: (
    appKey: string,
    accountId: string,
    body: { status?: string; display_name?: string },
  ): Promise<AdminAccount> =>
    request<AdminAccount>(
      `/admin/apps/${enc(appKey)}/accounts/${enc(accountId)}`,
      { method: "PATCH", body },
    ),

  resetAccountPassword: (
    appKey: string,
    accountId: string,
    newPassword: string,
  ): Promise<void> =>
    request<void>(
      `/admin/apps/${enc(appKey)}/accounts/${enc(accountId)}/reset-password`,
      { method: "POST", body: { new_password: newPassword } },
    ),

  transferAccount: (
    appKey: string,
    accountId: string,
    identityEmail: string,
  ): Promise<void> =>
    request<void>(
      `/admin/apps/${enc(appKey)}/accounts/${enc(accountId)}/transfer`,
      { method: "POST", body: { identity_email: identityEmail } },
    ),

  setAccountRoles: (
    appKey: string,
    accountId: string,
    roleIds: string[],
  ): Promise<AdminRole[]> =>
    request<AdminRole[]>(
      `/admin/apps/${enc(appKey)}/accounts/${enc(accountId)}/roles`,
      { method: "PUT", body: { role_ids: roleIds } },
    ),

  listGrants: async (appKey: string, accountId: string): Promise<Grant[]> =>
    toGrants(
      await request<unknown>(
        `/admin/apps/${enc(appKey)}/accounts/${enc(accountId)}/grants`,
      ),
    ),

  /**
   * Adds a direct grant. `effect` follows the M6 contract (backend currently
   * persists allow-only — TODO(backend): drop the field if unaccepted).
   */
  addGrant: (
    appKey: string,
    accountId: string,
    body: { resource_id: string; expires_at?: string; effect?: string },
  ): Promise<Grant> =>
    request<Grant>(
      `/admin/apps/${enc(appKey)}/accounts/${enc(accountId)}/grants`,
      { method: "POST", body },
    ),

  removeGrant: (
    appKey: string,
    accountId: string,
    grantId: string,
  ): Promise<void> =>
    request<void>(
      `/admin/apps/${enc(appKey)}/accounts/${enc(accountId)}/grants/${enc(grantId)}`,
      { method: "DELETE" },
    ),

  // ---------- resources ----------

  listResources: async (appKey: string): Promise<ResourceNode[]> =>
    toResourceTree(
      await request<unknown>(`/admin/apps/${enc(appKey)}/resources`),
    ),

  /** Flattened tree rows for the tree table. */
  listResourceRows: async (appKey: string): Promise<ResourceRow[]> =>
    flattenResourceTree(await adminApi.listResources(appKey)),

  createResource: (
    appKey: string,
    body: Record<string, unknown>,
  ): Promise<unknown> =>
    request<unknown>(`/admin/apps/${enc(appKey)}/resources`, {
      method: "POST",
      body,
    }),

  updateResource: (
    appKey: string,
    resourceId: string,
    body: Record<string, unknown>,
  ): Promise<unknown> =>
    request<unknown>(
      `/admin/apps/${enc(appKey)}/resources/${enc(resourceId)}`,
      { method: "PATCH", body },
    ),

  deleteResource: (appKey: string, resourceId: string): Promise<void> =>
    request<void>(`/admin/apps/${enc(appKey)}/resources/${enc(resourceId)}`, {
      method: "DELETE",
    }),

  batchResources: (
    appKey: string,
    items: BatchResourceItem[],
    mode: "" | "replace",
  ): Promise<BatchResourcesResp> =>
    request<BatchResourcesResp>(
      `/admin/apps/${enc(appKey)}/resources:batch${mode ? `?mode=${enc(mode)}` : ""}`,
      { method: "PUT", body: { items } },
    ).then((raw) => toBatchResourcesResp(raw)),

  // ---------- roles ----------

  listRoles: async (appKey: string): Promise<AdminRole[]> =>
    toAdminRoles(await request<unknown>(`/admin/apps/${enc(appKey)}/roles`)),

  createRole: (
    appKey: string,
    body: { code: string; name: string; scope?: string },
  ): Promise<AdminRole> =>
    request<AdminRole>(`/admin/apps/${enc(appKey)}/roles`, {
      method: "POST",
      body,
    }),

  updateRole: (
    appKey: string,
    roleId: string,
    body: { name?: string },
  ): Promise<AdminRole> =>
    request<AdminRole>(`/admin/apps/${enc(appKey)}/roles/${enc(roleId)}`, {
      method: "PATCH",
      body,
    }),

  deleteRole: (appKey: string, roleId: string): Promise<void> =>
    request<void>(`/admin/apps/${enc(appKey)}/roles/${enc(roleId)}`, {
      method: "DELETE",
    }),

  /**
   * Replaces the role's resource bindings. M6 effect per item; the bare
   * `resource_ids` array stays accepted server-side.
   */
  setRoleResources: (
    appKey: string,
    roleId: string,
    items: RoleResourceItem[],
  ): Promise<string[]> =>
    request<string[]>(
      `/admin/apps/${enc(appKey)}/roles/${enc(roleId)}/resources`,
      { method: "PUT", body: { items } },
    ),

  // ---------- invitations ----------

  listInvitations: async (appKey: string): Promise<AdminInvitation[]> =>
    toAdminInvitations(
      await request<unknown>(`/admin/apps/${enc(appKey)}/invitations`),
    ),

  createInvitation: (
    appKey: string,
    body: { email: string; role_ids: string[]; ttl_hours?: number },
  ): Promise<AdminInvitation> =>
    request<AdminInvitation>(`/admin/apps/${enc(appKey)}/invitations`, {
      method: "POST",
      body,
    }),

  revokeInvitation: (appKey: string, invitationId: string): Promise<void> =>
    request<void>(
      `/admin/apps/${enc(appKey)}/invitations/${enc(invitationId)}/revoke`,
      { method: "POST" },
    ),

  // ---------- oauth clients ----------

  listOAuthClients: async (appKey: string): Promise<OAuthClient[]> =>
    toOAuthClients(
      await request<unknown>(`/admin/apps/${enc(appKey)}/oauth-clients`),
    ),

  createOAuthClient: (
    appKey: string,
    body: {
      name: string;
      client_type: string;
      grant_types: string[];
      redirect_uris?: string[];
      scopes?: string[];
    },
  ): Promise<OAuthClientCreateResult> =>
    request<unknown>(`/admin/apps/${enc(appKey)}/oauth-clients`, {
      method: "POST",
      body,
    }).then((raw) => toOAuthClientCreateResult(raw)),

  updateOAuthClient: (
    appKey: string,
    clientId: string,
    body: {
      name?: string;
      status?: string;
      grant_types?: string[];
      redirect_uris?: string[];
      scopes?: string[];
    },
  ): Promise<OAuthClient> =>
    request<OAuthClient>(
      `/admin/apps/${enc(appKey)}/oauth-clients/${enc(clientId)}`,
      { method: "PATCH", body },
    ),

  deleteOAuthClient: (appKey: string, clientId: string): Promise<void> =>
    request<void>(
      `/admin/apps/${enc(appKey)}/oauth-clients/${enc(clientId)}`,
      { method: "DELETE" },
    ),

  // ---------- custom rules (M6) ----------

  listCustomRules: async (appKey: string): Promise<CustomRule[]> =>
    toCustomRules(
      await request<unknown>(`/admin/apps/${enc(appKey)}/custom-rules`),
    ),

  createCustomRule: (
    appKey: string,
    body: {
      name: string;
      expr: string;
      effect: string;
      priority?: number;
      status?: string;
    },
  ): Promise<CustomRule> =>
    request<CustomRule>(`/admin/apps/${enc(appKey)}/custom-rules`, {
      method: "POST",
      body,
    }),

  updateCustomRule: (
    appKey: string,
    ruleId: string,
    body: {
      name?: string;
      expr?: string;
      effect?: string;
      priority?: number;
      status?: string;
    },
  ): Promise<CustomRule> =>
    request<CustomRule>(
      `/admin/apps/${enc(appKey)}/custom-rules/${enc(ruleId)}`,
      { method: "PATCH", body },
    ),

  deleteCustomRule: (appKey: string, ruleId: string): Promise<void> =>
    request<void>(`/admin/apps/${enc(appKey)}/custom-rules/${enc(ruleId)}`, {
      method: "DELETE",
    }),

  /** Dry-runs an expr without saving (M6): {allowed} or {error}. */
  testCustomRule: (
    appKey: string,
    body: { expr: string; obj?: string; act?: string },
  ): Promise<CustomRuleTestResult> =>
    request<unknown>(`/admin/apps/${enc(appKey)}/custom-rules/test`, {
      method: "POST",
      body,
    }).then((raw) => toCustomRuleTestResult(raw)),

  // ---------- audit logs ----------

  listAuditLogs: (
    filters: { action?: string; org_key?: string },
    page: number,
    pageSize: number,
  ): Promise<Paged<AuditLog>> => {
    const params = new URLSearchParams();
    if (filters.action) params.set("action", filters.action);
    if (filters.org_key) params.set("org_key", filters.org_key);
    params.set("page", String(page));
    params.set("page_size", String(pageSize));
    return request<Paged<AuditLog>>(
      `/admin/audit-logs?${params.toString()}`,
    ).then((raw) => toAuditLogPage(raw));
  },

  /** GET /admin/audit-logs/summary?days=N (M6). */
  auditSummary: (days: number): Promise<AuditSummary> =>
    request<unknown>(`/admin/audit-logs/summary?days=${days}`).then((raw) =>
      toAuditSummary(raw),
    ),
};
