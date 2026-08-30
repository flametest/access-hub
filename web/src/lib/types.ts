/**
 * DTOs for the access-hub API (docs/design.md §8) plus the two invitation
 * endpoints. The backend is still landing, so responses are normalized
 * defensively in lib/normalize.ts — these types are the canonical shapes.
 */

/** Token pair from login/register/refresh and workspace token minting. */
export interface TokenPair {
  access_token: string;
  refresh_token?: string;
  token_type?: string;
}

export interface RegisterReq {
  username: string;
  email: string;
  password: string;
  nickname: string;
}

export interface LoginReq {
  identifier: string; // email or username
  password: string;
}

export interface SendEmailCodeReq {
  email: string;
  purpose: "reset";
}

export interface ResetPasswordReq {
  email: string;
  code: string;
  new_password: string;
}

/**
 * PATCH /me handles profile and password changes (design.md §8).
 * TODO(backend): confirm the change-password fields once the handler lands;
 * we send the new password plus the current one for verification.
 */
export interface UpdateMeReq {
  password: string;
  current_password?: string;
  nickname?: string;
}

export interface AcceptInvitationReq {
  code: string;
  /** Required when the invite auto-provisions a new Company ID (anonymous). */
  new_password?: string;
}

/** Primary identity (users table) — GET /me. */
export interface Me {
  id: string;
  username: string;
  email: string;
  nickname: string;
  avatar_url?: string | null;
  status: string;
  must_change_password: boolean;
}

/** Workspace account row — GET /me/workspaces and GET /me/workspaces/{id}. */
export interface Workspace {
  account_id: string;
  app_key: string;
  app_name: string;
  /** Workspace (per-app) email — not the primary identity email. */
  email: string;
  username?: string;
  display_name?: string;
  org_name?: string;
  roles: string[];
  /** active | pending_activation | disabled */
  status: string;
}

/** GET /me/signin-methods. */
export interface SignInMethod {
  method: string;
  label: string;
  detail?: string;
  enabled: boolean;
}

/** POST /invitations/redeem response. */
export interface InvitationPreview {
  app_name: string;
  app_key?: string;
  email: string;
  roles: string[];
  invited_by?: string;
  expires_at?: string;
  auto_provision: boolean;
}
