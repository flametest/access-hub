import { asRecord, optStr, pickList, str, strList } from "@/lib/normalize";
import type {
  AdminAccount,
  AdminApp,
  AdminInvitation,
  AdminRole,
  AdminUser,
  AuditActorCount,
  AuditActionCount,
  AuditDailyCount,
  AuditLog,
  AuditSummary,
  CustomRule,
  CustomRuleTestResult,
  Grant,
  OAuthClient,
  OAuthClientCreateResult,
  Org,
  OrgMember,
  Paged,
  ResourceNode,
  ResourceRow,
  RoleSummary,
} from "@/lib/admin/types";

/**
 * Tolerant normalizers for the admin endpoints (same convention as
 * lib/normalize.ts): raw JSON is coerced into the canonical shapes of
 * lib/admin/types.ts so snake_case/camelCase drift and missing fields never
 * crash the console.
 */

function num(...values: unknown[]): number {
  for (const v of values) {
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) {
      return Number(v);
    }
  }
  return 0;
}

function bool(value: unknown, fallback = false): boolean {
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  return fallback;
}

// ---------- orgs ----------

export function toOrg(raw: unknown): Org {
  const r = asRecord(raw);
  return {
    id: str(r.id, r.org_id),
    key: str(r.key, r.org_key),
    name: str(r.name) || str(r.key) || "(unnamed org)",
    status: str(r.status, "unknown").toLowerCase(),
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toOrgs(raw: unknown): Org[] {
  return pickList(raw, ["orgs", "items", "data"]).map(toOrg);
}

export function toOrgMember(raw: unknown): OrgMember {
  const r = asRecord(raw);
  return {
    user_id: str(r.user_id, r.userId, r.id),
    username: str(r.username),
    email: str(r.email),
    nickname: str(r.nickname, r.display_name) || str(r.username, r.email),
    org_role: str(r.org_role, r.orgRole, r.role, "member").toLowerCase(),
  };
}

export function toOrgMembers(raw: unknown): OrgMember[] {
  return pickList(raw, ["members", "items", "data"]).map(toOrgMember);
}

// ---------- apps ----------

export function toAdminApp(raw: unknown): AdminApp {
  const r = asRecord(raw);
  const org = asRecord(r.org);
  return {
    id: str(r.id, r.app_id),
    key: str(r.key, r.app_key, r.appKey),
    org_id: optStr(r.org_id, r.orgId) ?? null,
    org_key: str(r.org_key, r.orgKey, org.key),
    name: str(r.name) || str(r.key) || "(unnamed app)",
    type: str(r.type, "unknown").toLowerCase(),
    description: str(r.description),
    status: str(r.status, "unknown").toLowerCase(),
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toAdminApps(raw: unknown): AdminApp[] {
  return pickList(raw, ["apps", "items", "data"]).map(toAdminApp);
}

// ---------- users ----------

export function toAdminUser(raw: unknown): AdminUser {
  const r = asRecord(raw);
  return {
    id: str(r.id, r.user_id, r.userId),
    username: str(r.username, r.user_name),
    email: str(r.email),
    email_verified: bool(r.email_verified ?? r.emailVerified),
    nickname: str(r.nickname, r.display_name) || str(r.username, r.email),
    status: str(r.status, "unknown").toLowerCase(),
    created_at: optStr(r.created_at, r.createdAt),
    last_login_at: optStr(r.last_login_at, r.lastLoginAt) ?? null,
  };
}

export function toAdminUserPage(raw: unknown): Paged<AdminUser> {
  const r = asRecord(raw);
  const items = pickList(raw, ["items", "users", "data"]).map(toAdminUser);
  return {
    items,
    total: num(r.total, r.total_count, items.length),
    page: num(r.page, 1),
    page_size: num(r.page_size, r.pageSize, items.length || 1),
  };
}

// ---------- accounts ----------

function toRoleSummary(raw: unknown): RoleSummary {
  if (typeof raw === "string") return { code: raw, name: raw };
  const r = asRecord(raw);
  return {
    code: str(r.code, r.id),
    name: str(r.name) || str(r.code),
  };
}

export function toAdminAccount(raw: unknown): AdminAccount {
  const r = asRecord(raw);
  const roles = Array.isArray(r.roles)
    ? r.roles.map(toRoleSummary)
    : strList(r.role_names, r.roleNames, r.roles).map((code) => ({
        code,
        name: code,
      }));
  return {
    id: str(r.id, r.account_id, r.accountId),
    identity_id: str(r.identity_id, r.identityId),
    email: str(r.email),
    username: str(r.username),
    display_name: str(r.display_name, r.displayName) || str(r.username, r.email),
    status: str(r.status, "unknown").toLowerCase(),
    source: str(r.source, "unknown").toLowerCase(),
    roles,
    last_login_at: optStr(r.last_login_at, r.lastLoginAt) ?? null,
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toAdminAccountPage(raw: unknown): Paged<AdminAccount> {
  const r = asRecord(raw);
  const items = pickList(raw, ["items", "accounts", "data"]).map(toAdminAccount);
  return {
    items,
    total: num(r.total, r.total_count, items.length),
    page: 1,
    page_size: items.length || 1,
  };
}

export function toGrant(raw: unknown): Grant {
  const r = asRecord(raw);
  return {
    id: str(r.id, r.grant_id),
    account_id: str(r.account_id, r.accountId),
    resource_id: str(r.resource_id, r.resourceId),
    resource_code: str(r.resource_code, r.resourceCode),
    resource_name: str(r.resource_name, r.resourceName),
    resource_type: str(r.resource_type, r.resourceType).toLowerCase(),
    granted_by: str(r.granted_by, r.grantedBy),
    granted_at: optStr(r.granted_at, r.grantedAt),
    expires_at: optStr(r.expires_at, r.expiresAt, r.expired_at) ?? null,
  };
}

export function toGrants(raw: unknown): Grant[] {
  return pickList(raw, ["grants", "items", "data"]).map(toGrant);
}

// ---------- resources ----------

export function toResourceNode(raw: unknown): ResourceNode {
  const r = asRecord(raw);
  const children = Array.isArray(r.children) ? r.children : [];
  return {
    id: str(r.id, r.resource_id, r.resourceId),
    parent_id: optStr(r.parent_id, r.parentId) ?? null,
    type: str(r.type, "menu").toLowerCase(),
    code: str(r.code),
    name: str(r.name) || str(r.code) || "(unnamed)",
    sort: num(r.sort),
    status: str(r.status, "active").toLowerCase(),
    visible: bool(r.visible, true),
    icon: str(r.icon),
    method: str(r.method).toUpperCase(),
    route_path: str(r.route_path, r.routePath),
    path: str(r.path),
    children: children.map(toResourceNode),
  };
}

export function toResourceTree(raw: unknown): ResourceNode[] {
  return pickList(raw, ["resources", "tree", "items", "data"]).map(toResourceNode);
}

/** Depth-first flatten for the tree table (children keep parent order). */
export function flattenResourceTree(
  nodes: ResourceNode[],
  depth = 0,
): ResourceRow[] {
  const out: ResourceRow[] = [];
  for (const node of nodes) {
    const { children, ...rest } = node;
    out.push({ ...rest, depth });
    out.push(...flattenResourceTree(children, depth + 1));
  }
  return out;
}

export function toBatchResourcesResp(raw: unknown): {
  created: number;
  updated: number;
  disabled: number;
} {
  const r = asRecord(raw);
  return {
    created: num(r.created),
    updated: num(r.updated),
    disabled: num(r.disabled),
  };
}

// ---------- roles ----------

export function toAdminRole(raw: unknown): AdminRole {
  const r = asRecord(raw);
  return {
    id: str(r.id, r.role_id, r.roleId),
    code: str(r.code),
    name: str(r.name) || str(r.code) || "(unnamed role)",
    scope: str(r.scope, "app").toLowerCase(),
    built_in: bool(r.built_in ?? r.builtIn),
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toAdminRoles(raw: unknown): AdminRole[] {
  return pickList(raw, ["roles", "items", "data"]).map(toAdminRole);
}

// ---------- invitations ----------

export function toAdminInvitation(raw: unknown): AdminInvitation {
  const r = asRecord(raw);
  return {
    id: str(r.id, r.invitation_id, r.invitationId),
    email: str(r.email, r.invitee_email),
    role_ids: strList(r.role_ids, r.roleIds, r.roles),
    status: str(r.status, "unknown").toLowerCase(),
    invited_by: str(r.invited_by, r.invitedBy),
    expires_at: optStr(r.expires_at, r.expiresAt, r.expired_at),
    accepted_at: optStr(r.accepted_at, r.acceptedAt) ?? null,
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toAdminInvitations(raw: unknown): AdminInvitation[] {
  return pickList(raw, ["invitations", "items", "data"]).map(toAdminInvitation);
}

// ---------- oauth clients ----------

export function toOAuthClient(raw: unknown): OAuthClient {
  const r = asRecord(raw);
  return {
    client_id: str(r.client_id, r.clientId),
    app_key: str(r.app_key, r.appKey),
    name: str(r.name) || str(r.client_id) || "(unnamed client)",
    client_type: str(r.client_type, r.clientType, "confidential").toLowerCase(),
    grant_types: strList(r.grant_types, r.grantTypes),
    redirect_uris: strList(r.redirect_uris, r.redirectUris),
    scopes: strList(r.scopes),
    status: str(r.status, "unknown").toLowerCase(),
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toOAuthClients(raw: unknown): OAuthClient[] {
  return pickList(raw, ["clients", "oauth_clients", "items", "data"]).map(
    toOAuthClient,
  );
}

export function toOAuthClientCreateResult(
  raw: unknown,
): OAuthClientCreateResult {
  const r = asRecord(raw);
  return {
    client: toOAuthClient(raw),
    client_secret: str(r.client_secret, r.clientSecret),
  };
}

// ---------- custom rules (M6) ----------

export function toCustomRule(raw: unknown): CustomRule {
  const r = asRecord(raw);
  return {
    id: str(r.id, r.rule_id, r.ruleId),
    name: str(r.name) || "(unnamed rule)",
    expr: str(r.expr, r.expression),
    effect: str(r.effect, "deny").toLowerCase(),
    priority: num(r.priority),
    status: str(r.status, "active").toLowerCase(),
    updated_at: optStr(r.updated_at, r.updatedAt),
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toCustomRules(raw: unknown): CustomRule[] {
  return pickList(raw, ["rules", "custom_rules", "items", "data"]).map(
    toCustomRule,
  );
}

export function toCustomRuleTestResult(raw: unknown): CustomRuleTestResult {
  const r = asRecord(raw);
  return {
    allowed: bool(r.allowed),
    error: optStr(r.error, r.message),
  };
}

// ---------- audit logs ----------

export function toAuditLog(raw: unknown): AuditLog {
  const r = asRecord(raw);
  return {
    id: str(r.id),
    actor_type: str(r.actor_type, r.actorType, "unknown").toLowerCase(),
    actor_id: str(r.actor_id, r.actorId),
    action: str(r.action),
    target_type: str(r.target_type, r.targetType),
    target_id: str(r.target_id, r.targetId),
    detail: str(r.detail),
    ip: str(r.ip),
    user_agent: str(r.user_agent, r.userAgent),
    created_at: optStr(r.created_at, r.createdAt),
  };
}

export function toAuditLogPage(raw: unknown): Paged<AuditLog> {
  const r = asRecord(raw);
  const items = pickList(raw, ["items", "logs", "audit_logs", "data"]).map(
    toAuditLog,
  );
  return {
    items,
    total: num(r.total, r.total_count, items.length),
    page: num(r.page, 1),
    page_size: num(r.page_size, r.pageSize, items.length || 1),
  };
}

/** GET /admin/audit-logs/summary?days=N (M6). */
export function toAuditSummary(raw: unknown): AuditSummary {
  const r = asRecord(raw);
  const byAction = Array.isArray(r.by_action) ? r.by_action : [];
  const daily = Array.isArray(r.daily) ? r.daily : [];
  const actors = Array.isArray(r.top_actors) ? r.top_actors : [];
  return {
    days: num(r.days, daily.length),
    by_action: byAction.map((item): AuditActionCount => {
      const a = asRecord(item);
      return { action: str(a.action, a.name), count: num(a.count) };
    }),
    daily: daily.map((item): AuditDailyCount => {
      const a = asRecord(item);
      return { date: str(a.date, a.day), count: num(a.count) };
    }),
    top_actors: actors.map((item): AuditActorCount => {
      const a = asRecord(item);
      return {
        actor_type: str(a.actor_type, a.actorType, "unknown"),
        actor_id: str(a.actor_id, a.actorId),
        count: num(a.count),
      };
    }),
  };
}
