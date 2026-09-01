import { apiOrigin } from "@/lib/session";

/**
 * Social login (design.md §12 M5) client-side contract:
 * - `GET /api/v1/auth/social/{provider}/start?redirect=<portal path>&mode=login|link`
 *   is a **browser navigation** (302 chain through the provider), never a fetch;
 * - the provider callback lands back on the portal at `/social/complete` with
 *   `?login_code=<code>` (login success), `?linked=1` (link success) or
 *   `?error=<reason>`.
 */

export const SOCIAL_PROVIDER_IDS = [
  "google",
  "microsoft",
  "facebook",
  "apple",
] as const;

export type SocialProviderId = (typeof SOCIAL_PROVIDER_IDS)[number];

export const SOCIAL_PROVIDERS: ReadonlyArray<{
  id: SocialProviderId;
  label: string;
}> = [
  { id: "google", label: "Google" },
  { id: "microsoft", label: "Microsoft" },
  { id: "facebook", label: "Facebook" },
  { id: "apple", label: "Apple" },
];

/** Friendly provider name for any method key ("google" → "Google"). */
export function socialProviderLabel(provider: string): string {
  const hit = SOCIAL_PROVIDERS.find((p) => p.id === provider.toLowerCase());
  if (hit) return hit.label;
  return provider
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

/**
 * Full URL for the start redirect. Uses the **API origin** (not the portal's
 * same-origin rewrite) because the whole flow is a full-page navigation chain
 * that hops across the provider — same pattern as `apiOrigin()` in
 * lib/session.ts.
 */
export function socialStartUrl(
  provider: string,
  redirect: string,
  mode: "login" | "link",
): string {
  const params = new URLSearchParams({ redirect, mode });
  return `${apiOrigin()}/api/v1/auth/social/${encodeURIComponent(provider)}/start?${params.toString()}`;
}

/** Leaves the portal for the provider's consent screen. */
export function startSocialAuth(
  provider: string,
  redirect: string,
  mode: "login" | "link",
): void {
  window.location.assign(socialStartUrl(provider, redirect, mode));
}

/** Portal path the provider callback returns to. */
export const SOCIAL_COMPLETE_PATH = "/social/complete";
