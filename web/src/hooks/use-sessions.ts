"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

/**
 * The identity's login sessions (full history, newest first) — shared by the
 * /identity entry card and the /identity/sessions page via one query key.
 */
export function useSessions(enabled = true) {
  return useQuery({
    queryKey: ["me-sessions"],
    queryFn: () => api.listSessions(),
    enabled,
    staleTime: 15_000,
  });
}
