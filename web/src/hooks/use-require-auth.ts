"use client";

import { useRouter } from "next/navigation";
import { useEffect, useSyncExternalStore } from "react";
import { getAccessToken, subscribeToTokenChanges } from "@/lib/tokens";

const getServerSnapshot = () => null;

/** True once the client snapshot of localStorage carries an access token. */
export function useHasToken(): boolean {
  return Boolean(
    useSyncExternalStore(subscribeToTokenChanges, getAccessToken, getServerSnapshot),
  );
}

/**
 * Client-side gate for portal pages: redirects to /login when there is no
 * portal access token. `authed` is false during SSR/hydration and flips to the
 * real value once the client snapshot of localStorage is read — pages should
 * gate their queries on it.
 */
export function useRequireAuth(): { authed: boolean } {
  const router = useRouter();
  const authed = useHasToken();

  useEffect(() => {
    if (!authed) router.replace("/login");
  }, [authed, router]);

  return { authed };
}
