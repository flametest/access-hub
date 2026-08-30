"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { AppHeader } from "@/components/app-header";
import { Icon } from "@/components/icon";
import { Spinner } from "@/components/spinner";
import { useMe } from "@/hooks/use-me";
import { useRequireAuth } from "@/hooks/use-require-auth";

export function FullPageLoader() {
  return (
    <div className="grid min-h-dvh place-items-center">
      <Spinner className="size-7 text-ah-accent" />
    </div>
  );
}

const WIDTHS = {
  narrow: "max-w-md",
  normal: "max-w-3xl",
  wide: "max-w-5xl",
} as const;

/**
 * Layout for signed-in portal pages: requires a portal token, renders the
 * header, the must-change-password banner, and a centered container.
 */
export function PortalShell({
  children,
  width = "normal",
}: {
  children: ReactNode;
  width?: keyof typeof WIDTHS;
}) {
  const { ready, authed } = useRequireAuth();
  const { data: me } = useMe(authed);

  if (!ready || !authed) return <FullPageLoader />;

  return (
    <div className="min-h-dvh">
      <AppHeader me={me} />
      {me?.must_change_password && (
        <div className="border-b border-[#FFAB00]/25 bg-[#FFAB00]/10">
          <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-x-4 gap-y-1 px-4 py-2.5 text-sm text-[#FFC96B]">
            <span className="flex items-center gap-2">
              <Icon name="alert" className="size-4 flex-none" />
              Please change your password.
            </span>
            <Link
              href="/me/password"
              className="font-semibold underline underline-offset-2 hover:text-[#FFDF9E]"
            >
              Change password
            </Link>
          </div>
        </div>
      )}
      <main className={`mx-auto w-full px-4 py-8 sm:py-10 ${WIDTHS[width]}`}>
        {children}
      </main>
    </div>
  );
}
