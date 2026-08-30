import Link from "next/link";
import type { ReactNode } from "react";
import { Icon } from "@/components/icon";

/**
 * Centered auth layout (login / register / forgot password / invite):
 * brand on top, one card, and the prototype's footer line.
 */
export function AuthShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center px-4 py-10 sm:py-14">
      <Link
        href="/"
        className="mb-8 flex items-center gap-2.5"
        aria-label="access-hub home"
      >
        <span className="grid size-10 place-items-center rounded-xl bg-ah-accent/15 text-ah-accent">
          <Icon name="shield" className="size-5.5" />
        </span>
        <span className="text-xl font-extrabold tracking-tight">access-hub</span>
      </Link>
      <div className="w-full max-w-[420px]">{children}</div>
      <p className="mt-10 text-center text-xs text-white/40">
        © 2026 access-hub · Secured with 2-factor authentication
      </p>
    </div>
  );
}
