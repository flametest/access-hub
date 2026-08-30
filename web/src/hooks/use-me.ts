"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

/** Primary identity for the header/avatar and must_change_password banner. */
export function useMe(enabled = true) {
  return useQuery({
    queryKey: ["me"],
    queryFn: () => api.getMe(),
    enabled,
    staleTime: 30_000,
  });
}
