/**
 * Canonical DTO shapes for the admin console (docs/design.md §8 admin block +
 * §12 M6), mirroring pkg/dto/admin.go, pkg/dto/oauth.go and the M6 contracts
 * (custom rules, audit summary). Raw responses are coerced by
 * lib/admin/normalize.ts before reaching the UI.
 */

// ---------- orgs ----------

export interface Org {
  id: string;
  key: string;
  name: string;
  status: string;
  created_at?: string;
}

export interface OrgMember {
  user_id: string;
  username: string;
  email: string;
  nickname: string;
  /** owner | admin | member */
  org_role: string;
}

export interface CreateOrgReq {
  key: string;
  name: string;
}

export interface UpdateOrgReq {
  name?: string;
  status?: string;
}

export interface AddOrgMemberReq {
  email?: string;
  org_role: string;
}

// ---------- apps ----------

export interface AdminApp {
  id: string;
  key: string;
  org_id?: string | null;
  org_key: string;
  name: string;
  /** web | native | service */
  type: string;
  description: string;
  status: string;
  created_at?: string;
}

export interface CreateAppReq {
  key: string;
  org_key?: string;
  name: string;
  type?: string;
  description?: string;
}

export interface UpdateAppReq {
  name?: string;
  description?: string;
  status?: string;
}

// ---------- users (primary identities) ----------

export interface AdminUser {
  id: string;
  username: string;
  email: string;
  email_verified: boolean;
  nickname: string;
  status: string;
  created_at?: string;
  last_login_at?: string | null;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

// ---------- accounts (per-app workspace accounts) ----------

export interface RoleSummary {
  code: string;
  name: string;
}

export interface AdminAccount {
  id: string;
  identity_id: string;
  email: string;
  username: string;
  display_name: string;
  status: string;
  source: string;
  roles: RoleSummary[];
  last_login_at?: string | null;
  created_at?: string;
}

export interface ProvisionAccountReq {
  email: string;
  username?: string;
  display_name?: string;
  role_ids: string[];
  /** Empty → the account starts pending_activation and gets an activation mail. */
  password?: string;
}

export interface ProvisionAccountResp {
  account_id: string;
  activation_sent: boolean;
}

export interface Grant {
  id: string;
  account_id: string;
  resource_id: string;
  resource_code: string;
  resource_name: string;
  resource_type: string;
  granted_by: string;
  granted_at?: string;
  expires_at?: string | null;
}

// ---------- resources ----------

export type ResourceType = "menu" | "api" | "button";

export interface ResourceNode {
  id: string;
  parent_id?: string | null;
  type: string;
  code: string;
  name: string;
  sort: number;
  status: string;
  visible: boolean;
  icon: string;
  method: string;
  route_path: string;
  /** Nav path of menu resources (backend exposes it as "path"). */
  path: string;
  children: ResourceNode[];
}

/** A resource row flattened from the tree for table rendering. */
export interface ResourceRow extends Omit<ResourceNode, "children"> {
  depth: number;
}

export interface BatchResourceItem {
  code: string;
  name: string;
  type: string;
  parent_code?: string;
  path?: string;
  icon?: string;
  sort?: number;
  visible?: boolean;
  method?: string;
  route_path?: string;
  status?: string;
}

export interface BatchResourcesResp {
  created: number;
  updated: number;
  disabled: number;
}

// ---------- roles ----------

export interface AdminRole {
  id: string;
  code: string;
  name: string;
  /** app | global */
  scope: string;
  built_in: boolean;
  created_at?: string;
}

/** One entry of PUT .../roles/{roleId}/resources items[]. */
export interface RoleResourceItem {
  resource_id: string;
  effect: "allow" | "deny";
}

// ---------- invitations (admin) ----------

export interface AdminInvitation {
  id: string;
  email: string;
  role_ids: string[];
  /** pending | accepted | revoked | expired */
  status: string;
  invited_by: string;
  expires_at?: string;
  accepted_at?: string | null;
  created_at?: string;
}

// ---------- oauth clients ----------

export interface OAuthClient {
  client_id: string;
  app_key: string;
  name: string;
  /** confidential | public */
  client_type: string;
  grant_types: string[];
  redirect_uris: string[];
  scopes: string[];
  status: string;
  created_at?: string;
}

/** 201 response of the create endpoint — client_secret is shown exactly once. */
export interface OAuthClientCreateResult {
  client: OAuthClient;
  client_secret: string;
}

// ---------- custom rules (M6, expr-lang ABAC) ----------

export interface CustomRule {
  id: string;
  name: string;
  expr: string;
  /** allow | deny */
  effect: string;
  priority: number;
  status: string;
  updated_at?: string;
  created_at?: string;
}

export interface CustomRuleTestResult {
  allowed: boolean;
  error?: string;
}

// ---------- audit logs ----------

export interface AuditLog {
  id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  /** jsonb as string — pretty-printed in the expandable row when parseable. */
  detail: string;
  ip: string;
  user_agent: string;
  created_at?: string;
}

export interface AuditActionCount {
  action: string;
  count: number;
}

export interface AuditDailyCount {
  date: string;
  count: number;
}

export interface AuditActorCount {
  actor_type: string;
  actor_id: string;
  count: number;
}

/** GET /admin/audit-logs/summary?days=N (M6). */
export interface AuditSummary {
  days: number;
  by_action: AuditActionCount[];
  daily: AuditDailyCount[];
  top_actors: AuditActorCount[];
}
