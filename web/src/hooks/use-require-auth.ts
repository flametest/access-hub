"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getAccessToken } from "@/lib/tokens";

/**
 * Client-side gate for portal pages: once mounted, redirects to /login when
 * there is no portal access token. `ready` lets pages render skeletons while
 * localStorage is being checked.
 */
export function useRequireAuth(): { ready: boolean; authed: boolean } {
  const router = useRouter();
  const [state, setState] = useState({ ready: false, authed: false });

  useEffect(() => {
    const authed = Boolean(getAccessToken());
    setState({ ready: true, authed });
    if (!authed) router.replace("/login");
  }, [router]);

  return state;
}
