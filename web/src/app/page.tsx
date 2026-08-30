"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { FullPageLoader } from "@/components/portal-shell";
import { getAccessToken } from "@/lib/tokens";

/** Entry point: signed-in users land on /workspaces, everyone else on /login. */
export default function HomePage() {
  const router = useRouter();

  useEffect(() => {
    router.replace(getAccessToken() ? "/workspaces" : "/login");
  }, [router]);

  return <FullPageLoader />;
}
