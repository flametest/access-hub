"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState } from "react";
import { Icon } from "@/components/icon";
import { Initials } from "@/components/initials";
import { Spinner } from "@/components/spinner";
import { api } from "@/lib/api";
import type { Me } from "@/lib/types";
import { endSession } from "@/lib/session";

const NAV = [
  { href: "/workspaces", label: "Workspaces", icon: "grid" as const },
  { href: "/identity", label: "Identity", icon: "id" as const },
];

export function AppHeader({ me }: { me?: Me }) {
  const router = useRouter();
  const pathname = usePathname();
  const [loggingOut, setLoggingOut] = useState(false);

  async function signOut() {
    setLoggingOut(true);
    try {
      await api.logout();
    } catch {
      // Session is already dead server-side or unreachable — clear locally anyway.
    }
    endSession();
    router.replace("/login");
  }

  return (
    <header className="sticky top-0 z-30 border-b border-white/10 bg-[#093F3F]/85 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-5xl items-center justify-between gap-3 px-4">
        <Link
          href="/workspaces"
          className="flex flex-none items-center gap-2.5"
          aria-label="access-hub home"
        >
          <span className="grid size-9 place-items-center rounded-xl bg-ah-accent/15 text-ah-accent">
            <Icon name="shield" className="size-5" />
          </span>
          <span className="text-lg font-extrabold tracking-tight">
            access-hub
          </span>
        </Link>

        <nav className="flex items-center gap-1" aria-label="Main">
          {NAV.map((item) => {
            const active =
              pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-bold transition-colors ${
                  active
                    ? "bg-white/10 text-white"
                    : "text-white/60 hover:bg-white/[0.06] hover:text-white"
                }`}
              >
                <Icon name={item.icon} className="size-4.5" />
                <span className="hidden sm:inline">{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="flex flex-none items-center gap-2">
          {me && (
            <Link
              href="/identity"
              className="flex items-center gap-2.5 rounded-full bg-white/[0.07] py-1.5 pl-1.5 pr-3.5 transition-colors hover:bg-white/[0.12]"
              title="Manage your identity"
            >
              <Initials name={me.nickname || me.email} size="xs" />
              <span className="hidden leading-tight min-[420px]:block">
                <span className="block max-w-[140px] truncate text-[13px] font-bold">
                  {me.nickname}
                </span>
                <span className="block max-w-[160px] truncate text-[11px] text-white/50">
                  {me.email}
                </span>
              </span>
            </Link>
          )}
          <button
            type="button"
            onClick={signOut}
            disabled={loggingOut}
            title="Sign out"
            aria-label="Sign out"
            className="grid size-10 place-items-center rounded-lg text-white/60 transition-colors hover:bg-white/[0.08] hover:text-white disabled:opacity-50"
          >
            {loggingOut ? (
              <Spinner className="size-4.5" />
            ) : (
              <Icon name="logout" className="size-5" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
