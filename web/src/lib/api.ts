import {
  toInvitationPreview,
  toMe,
  toSignInMethods,
  toTokenPair,
  toWorkspace,
  toWorkspaces,
} from "@/lib/normalize";
import { clearSession, getAccessToken, getRefreshToken, setTokens } from "@/lib/tokens";
import type {
  AcceptInvitationReq,
  InvitationPreview,
  LoginReq,
  Me,
  RegisterReq,
  ResetPasswordReq,
  SendEmailCodeReq,
  SignInMethod,
  TokenPair,
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

const PUBLIC_PATHS = ["/login", "/register", "/forgot-password", "/invite"];

/** Clears the session; redirects to /login unless we're already on a public page. */
function sessionExpired(): void {
  clearSession();
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

export const api = {
  register: (body: RegisterReq): Promise<TokenPair> =>
    request<TokenPair>("/auth/register", { method: "POST", body, auth: false }),

  login: (body: LoginReq): Promise<TokenPair> =>
    request<TokenPair>("/auth/login", { method: "POST", body, auth: false }),

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
