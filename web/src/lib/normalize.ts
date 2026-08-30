import type {
  InvitationPreview,
  Me,
  SignInMethod,
  TokenPair,
  Workspace,
} from "@/lib/types";

/**
 * Defensive normalizers: the backend DTOs are still settling (design.md §8),
 * so raw responses are coerced into the canonical shapes in lib/types.ts.
 */

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/** First non-empty string among candidates. */
function str(...values: unknown[]): string {
  for (const v of values) {
    if (typeof v === "string" && v.trim()) return v;
    if (typeof v === "number") return String(v);
  }
  return "";
}

function optStr(...values: unknown[]): string | undefined {
  const s = str(...values);
  return s || undefined;
}

/** Accepts string[] or a comma-separated summary string; falls back to .name. */
function strList(...values: unknown[]): string[] {
  for (const v of values) {
    if (Array.isArray(v)) {
      const out = v
        .map((item) =>
          typeof item === "string"
            ? item
            : str(asRecord(item).name) || String(item),
        )
        .filter(Boolean);
      if (out.length > 0) return out;
    }
    if (typeof v === "string" && v.trim()) {
      return v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }
  return [];
}

function pickList(raw: unknown, keys: string[]): unknown[] {
  if (Array.isArray(raw)) return raw;
  const r = asRecord(raw);
  for (const key of keys) {
    const v = r[key];
    if (Array.isArray(v)) return v;
  }
  return [];
}

export function toMe(raw: unknown): Me {
  const r = asRecord(raw);
  return {
    id: str(r.id, r.user_id, r.userId, r.sub),
    username: str(r.username, r.user_name),
    email: str(r.email),
    nickname:
      str(r.nickname, r.display_name, r.name) ||
      str(r.username, r.email) ||
      "there",
    avatar_url: optStr(r.avatar_url, r.avatar) ?? null,
    status: str(r.status, "unknown"),
    must_change_password: Boolean(r.must_change_password),
  };
}

export function toTokenPair(raw: unknown): TokenPair | null {
  const r = asRecord(raw);
  const access = r.access_token ?? r.accessToken ?? r.token;
  if (typeof access !== "string" || !access) return null;
  const refresh = r.refresh_token ?? r.refreshToken;
  return {
    access_token: access,
    refresh_token: typeof refresh === "string" ? refresh : undefined,
    token_type: typeof r.token_type === "string" ? r.token_type : undefined,
  };
}

export function toWorkspace(raw: unknown): Workspace {
  const r = asRecord(raw);
  const app = asRecord(r.app);
  const org = asRecord(r.org);
  return {
    account_id: str(r.account_id, r.accountId, r.id),
    app_key: str(r.app_key, r.appKey, app.key),
    app_name: str(r.app_name, r.appName, app.name, r.workspace_name) || "Workspace",
    email: str(r.email, r.workspace_email, r.workspaceEmail, r.account_email),
    username: optStr(r.username, r.workspace_username),
    display_name: optStr(r.display_name, r.displayName, r.displayname),
    org_name: optStr(r.org_name, org.name),
    roles: strList(r.roles, r.role_names, r.roleNames, r.role_summary, r.role),
    status: str(r.status, "unknown").toLowerCase(),
  };
}

export function toWorkspaces(raw: unknown): Workspace[] {
  return pickList(raw, ["workspaces", "items", "accounts", "data"]).map(
    toWorkspace,
  );
}

const METHOD_LABELS: Record<string, string> = {
  password: "Password",
  email: "Email code",
  google: "Google",
  microsoft: "Microsoft",
  totp: "Authenticator app",
  twofa: "Two-factor authentication",
};

export function toSignInMethods(raw: unknown): SignInMethod[] {
  return pickList(raw, ["methods", "items", "signin_methods", "data"]).map(
    (item): SignInMethod => {
      if (typeof item === "string") {
        const method = item.toLowerCase();
        return {
          method,
          label: METHOD_LABELS[method] ?? titleize(method),
          enabled: true,
        };
      }
      const m = asRecord(item);
      const method = str(m.method, m.type, m.key, "password").toLowerCase();
      return {
        method,
        label: str(m.label, m.name) || METHOD_LABELS[method] || titleize(method),
        detail: optStr(m.detail, m.description, m.email, m.masked, m.masked_hint),
        enabled: m.enabled === undefined ? true : Boolean(m.enabled),
      };
    },
  );
}

export function toInvitationPreview(raw: unknown): InvitationPreview {
  const r = asRecord(raw);
  const app = asRecord(r.app);
  return {
    app_name: str(r.app_name, r.appName, app.name, r.workspace_name) || "Workspace",
    app_key: optStr(r.app_key, r.appKey, app.key),
    email: str(r.email, r.invitee_email, r.invited_email),
    roles: strList(r.roles, r.role_names, r.roleNames),
    invited_by: optStr(r.invited_by, r.invited_by_email, r.inviter),
    expires_at: optStr(r.expires_at, r.expired_at, r.expires),
    auto_provision: Boolean(r.auto_provision ?? r.autoProvision ?? false),
  };
}

function titleize(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}
