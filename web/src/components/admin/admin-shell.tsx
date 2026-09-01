"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { Icon, type IconName } from "@/components/icon";
import { Initials } from "@/components/initials";
import { Spinner } from "@/components/spinner";
import { useMe } from "@/hooks/use-me";
import { useRequireAuth } from "@/hooks/use-require-auth";
import { api } from "@/lib/api";
import { endSession } from "@/lib/session";

/**
 * Admin console shell (lives under the same portal app at /admin/*): fixed
 * left sidebar on desktop, a horizontal nav strip below lg. Nav items are
 * always rendered — pages degrade to a ForbiddenCard on 403 because admin
 * permissions are dogfooded via Casbin (org_admins see fewer sections).
 */
const NAV: { href: string; label: string; icon: IconName }[] = [
  { href: "/admin", label: "Overview", icon: "grid" },
  { href: "/admin/orgs", label: "Organizations", icon: "building" },
  { href: "/admin/apps", label: "Apps", icon: "layers" },
  { href: "/admin/users", label: "Users", icon: "users" },
  { href: "/admin/audit", label: "Audit log", icon: "log" },
];

function NavLinks({ pathname }: { pathname: string }) {
  return (
    <nav aria-label="Admin">
      <ul className="flex flex-col gap-1">
        {NAV.map((item) => {
          const active =
            item.href === "/admin"
              ? pathname === "/admin"
              : pathname === item.href || pathname.startsWith(`${item.href}/`);
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-bold transition-colors ${
                  active
                    ? "bg-white/10 text-white"
                    : "text-white/60 hover:bg-white/[0.06] hover:text-white"
                }`}
              >
                <Icon name={item.icon} className="size-4.5 flex-none" />
                {item.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

export function AdminShell({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { authed } = useRequireAuth();
  const { data: me } = useMe(authed);
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

  if (!authed) {
    return (
      <div className="grid min-h-dvh place-items-center">
        <Spinner className="size-7 text-ah-accent" />
      </div>
    );
  }

  const userChip = (
    <div className="flex items-center gap-2.5 rounded-xl bg-white/[0.06] p-2">
      <Initials name={me?.nickname || me?.email || "?"} size="xs" />
      <span className="min-w-0 leading-tight">
        <span className="block max-w-[130px] truncate text-[13px] font-bold">
          {me?.nickname || "Admin"}
        </span>
        <span className="block max-w-[150px] truncate text-[11px] text-white/50">
          {me?.email}
        </span>
      </span>
    </div>
  );

  return (
    <div className="min-h-dvh lg:flex">
      {/* Sidebar (desktop) */}
      <aside className="sticky top-0 hidden h-dvh w-60 flex-none flex-col border-r border-white/10 bg-[#06302F]/60 px-3 py-5 lg:flex">
        <Link
          href="/admin"
          className="mb-6 flex items-center gap-2.5 px-2"
          aria-label="access-hub admin"
        >
          <span className="grid size-9 place-items-center rounded-xl bg-ah-accent/15 text-ah-accent">
            <Icon name="shield" className="size-5" />
          </span>
          <span className="leading-tight">
            <span className="block text-[15px] font-extrabold tracking-tight">
              access-hub
            </span>
            <span className="block text-[11px] font-bold uppercase tracking-wide text-ah-accent">
              Admin console
            </span>
          </span>
        </Link>

        <NavLinks pathname={pathname} />

        <div className="mt-auto flex flex-col gap-2 pt-4">
          <Link
            href="/workspaces"
            className="flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-bold text-white/60 transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <Icon name="arrow-left" className="size-4.5 flex-none" />
            Back to portal
          </Link>
          {userChip}
        </div>
      </aside>

      {/* Top bar + horizontal nav (mobile/tablet) + content */}
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-30 border-b border-white/10 bg-[#093F3F]/85 backdrop-blur">
          <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-3 px-4 lg:hidden">
            <Link
              href="/admin"
              className="flex items-center gap-2"
              aria-label="access-hub admin"
            >
              <span className="grid size-8 place-items-center rounded-lg bg-ah-accent/15 text-ah-accent">
                <Icon name="shield" className="size-4.5" />
              </span>
              <span className="text-[15px] font-extrabold tracking-tight">
                Admin console
              </span>
            </Link>
            <div className="flex items-center gap-1">
              <Link
                href="/workspaces"
                className="flex items-center gap-1.5 rounded-lg px-2.5 py-2 text-[13px] font-bold text-white/60 transition-colors hover:bg-white/[0.06] hover:text-white"
              >
                <Icon name="arrow-left" className="size-4" /> Portal
              </Link>
              <button
                type="button"
                onClick={signOut}
                disabled={loggingOut}
                title="Sign out"
                aria-label="Sign out"
                className="grid size-9 place-items-center rounded-lg text-white/60 transition-colors hover:bg-white/[0.08] hover:text-white disabled:opacity-50"
              >
                {loggingOut ? (
                  <Spinner className="size-4" />
                ) : (
                  <Icon name="logout" className="size-4.5" />
                )}
              </button>
            </div>
          </div>
          <div className="mx-auto max-w-6xl px-2 pb-1 lg:hidden">
            <div className="flex overflow-x-auto">
              <NavLinksHorizontal pathname={pathname} />
            </div>
          </div>
        </header>

        {me?.must_change_password && (
          <div className="border-b border-[#FFAB00]/25 bg-[#FFAB00]/10">
            <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-4 gap-y-1 px-4 py-2.5 text-sm text-[#FFC96B]">
              <span className="flex items-center gap-2">
                <Icon name="alert" className="size-4 flex-none" />
                Please change your password — admin actions stay blocked until
                you do.
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

        <main className="mx-auto w-full max-w-6xl px-4 py-8">
          {children}
        </main>
      </div>
    </div>
  );
}

function NavLinksHorizontal({ pathname }: { pathname: string }) {
  return (
    <nav aria-label="Admin" className="flex gap-1">
      {NAV.map((item) => {
        const active =
          item.href === "/admin"
            ? pathname === "/admin"
            : pathname === item.href || pathname.startsWith(`${item.href}/`);
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={`flex flex-none items-center gap-2 whitespace-nowrap rounded-lg px-3 py-2 text-[13px] font-bold transition-colors ${
              active
                ? "bg-white/10 text-white"
                : "text-white/60 hover:bg-white/[0.06] hover:text-white"
            }`}
          >
            <Icon name={item.icon} className="size-4 flex-none" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
