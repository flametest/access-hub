"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

/** TOTP two-factor state for the signed-in identity (GET /me/2fa/status). */
export function use2faStatus(enabled = true) {
  return useQuery({
    queryKey: ["2fa", "status"],
    queryFn: () => api.get2faStatus(),
    enabled,
    staleTime: 15_000,
  });
}
