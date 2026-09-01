import {
  toBackupCodes,
  toInvitationPreview,
  toMe,
  toMfaChallenge,
  toSignInMethods,
  toSocialComplete,
  toSocialIdentities,
  toTokenPair,
  toTwoFaEnroll,
  toTwoFaStatus,
  toWorkspace,
  toWorkspaces,
} from "@/lib/normalize";
import { clearSessionCookie, setSessionCookie } from "@/lib/session";
import { clearSession, getAccessToken, getRefreshToken, setTokens } from "@/lib/tokens";
import type {
  AcceptInvitationReq,
  InvitationPreview,
  Login2FaReq,
  LoginReq,
  Me,
  MfaChallenge,
  RegisterReq,
  ResetPasswordReq,
  SendEmailCodeReq,
  SignInMethod,
  SocialCompleteResult,
  SocialIdentity,
  TokenPair,
  TwoFaDisableReq,
  TwoFaEnroll,
  TwoFaStatus,
  UpdateMeReq,
  Workspace,
} from "@/lib/types";

const BASE = "/api/v1";

/**
 * Friendly copy for the error envelope codes (docs/design.md: verrors —
 * 1400 bad request, 1401 unauthorized, 1403 forbidden, 1404 not found,
 * 1409 conflict, 1500 internal).
 */
const CODE_MESSAGES: Record<number, string> = {
  1400: "That request wasn't valid. Please check the input and try again.",
  1401: "Your session has expired. Please sign in again.",
  1403: "You don't have permission to do that.",
  1404: "We couldn't find what you were looking for.",
  1409: "That value is already taken. Try a different one.",
  1500: "Something went wrong on our side. Please try again later.",
};

const STATUS_FALLBACKS: Record<number, string> = {
  400: "That request wasn't valid. Please check the input and try again.",
  401: "Your session has expired. Please sign in again.",
  403: "You don't have permission to do that.",
  404: "We couldn't find what you were looking for.",
  409: "That value is already taken. Try a different one.",
};

const NETWORK_ERROR_MESSAGE =
  "Can't reach the access-hub server. Check that the backend is running on :8080.";

export class ApiError extends Error {
  readonly status: number;
  readonly code?: number;
  readonly service?: string;

  constructor(message: string, status: number, code?: number, service?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.service = service;
  }
}

/** Backend message → code map → status fallback. */
function toMessage(
  status: number,
  code?: number,
  backendMessage?: string,
): string {
  if (backendMessage && status >= 400 && status < 500) return backendMessage;
  if (code !== undefined && CODE_MESSAGES[code]) return CODE_MESSAGES[code];
  if (STATUS_FALLBACKS[status]) return STATUS_FALLBACKS[status];
  return "Something went wrong. Please try again.";
}

const PUBLIC_PATHS = [
  "/login",
  "/register",
  "/forgot-password",
  "/invite",
  "/social/complete",
];

/** Clears the session; redirects to /login unless we're already on a public page. */
function sessionExpired(): void {
  clearSession();
  clearSessionCookie();
  if (typeof window === "undefined") return;
  const { pathname } = window.location;
  const isPublic = PUBLIC_PATHS.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );
  if (!isPublic) window.location.assign("/login");
}

interface Options {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  /** Attach the portal access token (default true). */
  auth?: boolean;
}

async function parseError(res: Response): Promise<ApiError> {
  let code: number | undefined;
  let service: string | undefined;
  let message: string | undefined;
  try {
    const env = (await res.json()) as Record<string, unknown>;
    const rawCode = env.code;
    if (typeof rawCode === "number") code = rawCode;
    else if (typeof rawCode === "string" && /^\d+$/.test(rawCode)) {
      code = Number(rawCode);
    }
    if (typeof env.service === "string") service = env.service;
    if (typeof env.message === "string") message = env.message;
  } catch {
    // Non-JSON error body — fall back to generic wording below.
  }
  return new ApiError(toMessage(res.status, code, message), res.status, code, service);
}

async function fetchOnce(
  path: string,
  opts: Options,
  accessToken?: string | null,
): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (opts.auth !== false && accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  return fetch(`${BASE}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

async function fetchOnceOrThrow(
  path: string,
  opts: Options,
  accessToken?: string | null,
): Promise<Response> {
  try {
    return await fetchOnce(path, opts, accessToken);
  } catch {
    throw new ApiError(NETWORK_ERROR_MESSAGE, 0);
  }
}

let refreshInFlight: Promise<boolean> | null = null;

/**
 * One in-flight refresh at a time. POST /auth/token/refresh rotates the pair
 * in place; on failure the caller treats the session as expired.
 */
function refreshTokens(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      const refreshToken = getRefreshToken();
      if (!refreshToken) return false;
      try {
        const res = await fetch(`${BASE}/auth/token/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        if (!res.ok) return false;
        const pair = toTokenPair(await res.json());
        if (!pair) return false;
        setTokens(pair.access_token, pair.refresh_token ?? null);
        // Keep the browser-flow session cookie in sync with the rotation.
        setSessionCookie(pair.access_token);
        return true;
      } catch {
        return false;
      } finally {
        refreshInFlight = null;
      }
    })();
  }
  return refreshInFlight;
}

/**
 * Global fetch wrapper: attaches the Bearer token, transparently refreshes
 * once on 401 (rotating the token pair) and retries, and maps error envelopes
 * to ApiError with friendly messages.
 */
export async function request<T>(path: string, opts: Options = {}): Promise<T> {
  let res = await fetchOnceOrThrow(path, opts, getAccessToken());

  if (res.status === 401 && opts.auth !== false && getRefreshToken()) {
    const refreshed = await refreshTokens();
    if (refreshed) {
      res = await fetchOnceOrThrow(path, opts, getAccessToken());
    }
  }

  if (res.status === 401 && opts.auth !== false) {
    sessionExpired();
    throw new ApiError(toMessage(401), 401, 1401);
  }

  if (!res.ok) throw await parseError(res);

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined as T;
  }
}

/** Best-effort error → user-facing message. */
export function errMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message || fallback;
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}

/**
 * True when the API answered 403 (Casbin admin codes are dogfooded: org_admins
 * only hold the app-scoped codes, platform sections answer 403). Admin pages
 * render a "no permission" placeholder instead of a raw error.
 */
export function isForbidden(err: unknown): boolean {
  return err instanceof ApiError && err.status === 403;
}

export const api = {
  register: (body: RegisterReq): Promise<TokenPair> =>
    request<TokenPair>("/auth/register", { method: "POST", body, auth: false }),

  /**
   * Password login. When the identity has TOTP 2FA enabled the response is a
   * challenge (`mfa_required` + short-lived `mfa_token`) instead of tokens —
   * continue with verify2fa.
   */
  login: async (body: LoginReq): Promise<TokenPair | MfaChallenge> => {
    const raw = await request<unknown>("/auth/login", {
      method: "POST",
      body,
      auth: false,
    });
    const challenge = toMfaChallenge(raw);
    if (challenge) return challenge;
    const pair = toTokenPair(raw);
    if (!pair) {
      throw new ApiError(
        "Signed in, but the server returned no session. Please try again.",
        500,
        1500,
      );
    }
    return pair;
  },

  /** Second login step: TOTP value or a one-time backup code as `code`. */
  verify2fa: async (body: Login2FaReq): Promise<TokenPair> => {
    const pair = toTokenPair(
      await request<unknown>("/auth/login/2fa", {
        method: "POST",
        body,
        auth: false,
      }),
    );
    if (!pair) {
      throw new ApiError(
        "Verified, but the server returned no session. Please try again.",
        500,
        1500,
      );
    }
    return pair;
  },

  /**
   * Exchanges the one-time `login_code` from the provider callback
   * (/social/complete?login_code=…) for a session: either a token pair (plus
   * optional email-matched pending invitations) or the 2FA challenge —
   * continue with verify2fa.
   */
  socialComplete: async (loginCode: string): Promise<SocialCompleteResult> => {
    const result = toSocialComplete(
      await request<unknown>("/auth/social/complete", {
        method: "POST",
        body: { login_code: loginCode },
        auth: false,
      }),
    );
    if (!result.pair && !result.challenge) {
      throw new ApiError(
        "Signed in, but the server returned no session. Please try again.",
        500,
        1500,
      );
    }
    return result;
  },

  /** Social credentials linked to the primary identity. */
  listSocialIdentities: async (): Promise<SocialIdentity[]> =>
    toSocialIdentities(await request<unknown>("/me/social-identities")),

  /** Unlinks a social credential; 409 when it's the last sign-in method. */
  deleteSocialIdentity: (id: string): Promise<void> =>
    request<void>(`/me/social-identities/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),

  /** TOTP enrollment state for the signed-in identity. */
  get2faStatus: async (): Promise<TwoFaStatus> =>
    toTwoFaStatus(await request<unknown>("/me/2fa/status")),

  /** Issues (or re-issues) the TOTP secret + otpauth URI. */
  enroll2fa: async (): Promise<TwoFaEnroll> =>
    toTwoFaEnroll(
      await request<unknown>("/me/2fa/enroll", { method: "POST" }),
    ),

  /** Confirms enrollment; returns the plaintext backup codes (shown once). */
  confirm2fa: async (code: string): Promise<string[]> =>
    toBackupCodes(
      await request<unknown>("/me/2fa/confirm", {
        method: "POST",
        body: { code },
      }),
    ),

  /** Disables 2FA; requires the current password. */
  disable2fa: (body: TwoFaDisableReq): Promise<void> =>
    request<void>("/me/2fa/disable", { method: "POST", body }),

  sendEmailCode: (body: SendEmailCodeReq): Promise<void> =>
    request<void>("/auth/email/code", { method: "POST", body, auth: false }),

  resetPassword: (body: ResetPasswordReq): Promise<void> =>
    request<void>("/auth/password/reset", { method: "POST", body, auth: false }),

  logout: (): Promise<void> => request<void>("/auth/logout", { method: "POST" }),

  getMe: async (): Promise<Me> => toMe(await request<unknown>("/me")),

  updateMe: (body: UpdateMeReq): Promise<Me> =>
    request<Me>("/me", { method: "PATCH", body }),

  listWorkspaces: async (): Promise<Workspace[]> =>
    toWorkspaces(await request<unknown>("/me/workspaces")),

  getWorkspace: async (accountId: string): Promise<Workspace> =>
    toWorkspace(
      await request<unknown>(`/me/workspaces/${encodeURIComponent(accountId)}`),
    ),

  /** Mints an app token (new account-scoped session) for one workspace. */
  mintWorkspaceToken: (accountId: string): Promise<TokenPair> =>
    request<TokenPair>(`/me/workspaces/${encodeURIComponent(accountId)}/token`, {
      method: "POST",
    }),

  listSignInMethods: async (): Promise<SignInMethod[]> =>
    toSignInMethods(await request<unknown>("/me/signin-methods")),

  /** Validates a code and returns the invitation preview (no side effects). */
  redeemInvitation: async (code: string): Promise<InvitationPreview> =>
    toInvitationPreview(
      await request<unknown>("/invitations/redeem", {
        method: "POST",
        body: { code },
      }),
    ),

  /**
   * Accepts the invitation; may return a token pair when it auto-provisions a
   * new Company ID for an anonymous user.
   */
  acceptInvitation: (body: AcceptInvitationReq): Promise<unknown> =>
    request<unknown>("/invitations/accept", { method: "POST", body }),
};
