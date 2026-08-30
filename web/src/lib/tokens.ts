const ACCESS_KEY = "ah.access";
const REFRESH_KEY = "ah.refresh";
const APP_PREFIX = "ah.app.";

function store(): Storage | null {
  if (typeof window === "undefined") return null;
  return window.localStorage;
}

export function getAccessToken(): string | null {
  return store()?.getItem(ACCESS_KEY) ?? null;
}

export function getRefreshToken(): string | null {
  return store()?.getItem(REFRESH_KEY) ?? null;
}

/** Persists the portal token pair (refresh optional, e.g. on rotation). */
export function setTokens(access: string, refresh?: string | null): void {
  const s = store();
  if (!s) return;
  if (access) s.setItem(ACCESS_KEY, access);
  if (refresh) s.setItem(REFRESH_KEY, refresh);
}

export function clearTokens(): void {
  const s = store();
  if (!s) return;
  s.removeItem(ACCESS_KEY);
  s.removeItem(REFRESH_KEY);
}

/** Clears the portal session plus every per-workspace app token. */
export function clearSession(): void {
  const s = store();
  if (!s) return;
  clearTokens();
  const appKeys: string[] = [];
  for (let i = 0; i < s.length; i += 1) {
    const key = s.key(i);
    if (key && key.startsWith(APP_PREFIX)) appKeys.push(key);
  }
  for (const key of appKeys) s.removeItem(key);
}

/** App tokens are stored per workspace account: ah.app.{accountId}.* */
export function setAppTokens(
  accountId: string,
  access: string,
  refresh?: string | null,
): void {
  const s = store();
  if (!s) return;
  if (access) s.setItem(`${APP_PREFIX}${accountId}.access`, access);
  if (refresh) s.setItem(`${APP_PREFIX}${accountId}.refresh`, refresh);
}

export function getAppToken(accountId: string): string | null {
  return store()?.getItem(`${APP_PREFIX}${accountId}.access`) ?? null;
}

/**
 * Notifies listeners when tokens may have changed in another tab. Used with
 * useSyncExternalStore so React can read token state as an external store.
 */
export function subscribeToTokenChanges(onChange: () => void): () => void {
  const s = store();
  if (!s) return () => {};
  window.addEventListener("storage", onChange);
  return () => window.removeEventListener("storage", onChange);
}
