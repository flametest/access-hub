import type { useRouter } from "next/navigation";
import { clearSession, setTokens } from "@/lib/tokens";

/**
 * Session-cookie + post-login redirect helpers.
 *
 * The backend's browser flows (OIDC `GET /oauth2/authorize`) read a lightweight
 * `ah.session` cookie instead of localStorage. JS cannot set HttpOnly, so this
 * is a regular cookie with SameSite=Lax whose value is the portal access token
 * and whose lifetime mirrors the token's `exp` claim.
 */
const SESSION_COOKIE = "ah.session";

/** Fallback when the access token is not a decodable JWT: 15 minutes. */
const FALLBACK_MAX_AGE = 900;

function store(): { cookie: string } | null {
  if (typeof document === "undefined") return null;
  return document;
}

/** `exp - now` from the JWT payload, or FALLBACK_MAX_AGE when undecodable. */
function accessMaxAge(token: string): number {
  const parts = token.split(".");
  if (parts.length !== 3) return FALLBACK_MAX_AGE;
  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(base64)) as { exp?: unknown };
    const exp = Number(payload.exp);
    if (!Number.isFinite(exp)) return FALLBACK_MAX_AGE;
    const seconds = Math.floor(exp - Date.now() / 1000);
    return seconds > 0 ? seconds : FALLBACK_MAX_AGE;
  } catch {
    return FALLBACK_MAX_AGE;
  }
}

/** Writes `ah.session` (access token, SameSite=Lax, path=/, token lifetime). */
export function setSessionCookie(accessToken: string): void {
  const doc = store();
  if (!doc || !accessToken) return;
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  doc.cookie = `${SESSION_COOKIE}=${accessToken}; Path=/; SameSite=Lax; Max-Age=${accessMaxAge(accessToken)}${secure}`;
}

/** Removes `ah.session`. */
export function clearSessionCookie(): void {
  const doc = store();
  if (!doc) return;
  doc.cookie = `${SESSION_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0`;
}

/** Persists a fresh portal session: localStorage tokens + the session cookie. */
export function applySession(accessToken: string, refresh?: string | null): void {
  setTokens(accessToken, refresh);
  setSessionCookie(accessToken);
}

/** Clears every session artifact (localStorage tokens, app tokens, cookie). */
export function endSession(): void {
  clearSession();
  clearSessionCookie();
}

/**
 * API origin as the browser sees it (`ACCESS_HUB_API_URL`, inlined by
 * next.config.ts). Absolute `next` targets are only honored when they point
 * here.
 */
export function apiOrigin(): string {
  const raw =
    process.env.NEXT_PUBLIC_ACCESS_HUB_API_URL ??
    process.env.ACCESS_HUB_API_URL ??
    "http://localhost:8080";
  return raw.replace(/\/+$/, "");
}

/**
 * Validates a post-login `next` target:
 * - same-origin-relative paths (`/foo`, never `//foo` or `/\foo`) pass through;
 * - absolute http(s) URLs pass only when their origin matches the API origin
 *   (the OIDC browser flow hops back to `GET /oauth2/authorize` there);
 * - anything else (off-site redirects, other schemes) is dropped.
 */
export function resolveRedirectTarget(
  raw: string | null | undefined,
): string | null {
  const value = raw?.trim();
  if (!value) return null;

  if (value.startsWith("/")) {
    if (value.startsWith("//") || value.startsWith("/\\")) return null;
    return value;
  }

  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.origin === apiOrigin()) return url.href;
  } catch {
    // Not an absolute URL.
  }
  return null;
}

/**
 * Where to go after a successful sign-in: the validated `next` target when
 * present, otherwise the workspaces picker. Absolute (API-origin) targets need
 * a full browser navigation to leave the portal origin.
 */
export function postLoginRedirect(
  router: ReturnType<typeof useRouter>,
  raw: string | null | undefined,
): void {
  const target = resolveRedirectTarget(raw);
  if (!target) {
    router.replace("/workspaces");
  } else if (target.startsWith("/")) {
    router.replace(target);
  } else {
    window.location.assign(target);
  }
}
