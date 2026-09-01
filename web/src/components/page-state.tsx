"use client";

import type { ReactNode } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Icon, type IconName } from "@/components/icon";

/** Placeholder skeleton for card grids. */
export function SkeletonCards({
  count = 4,
  className = "",
}: {
  count?: number;
  className?: string;
}) {
  return (
    <div className={`grid gap-4 sm:grid-cols-2 ${className}`} aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div
          key={i}
          className="h-[76px] animate-pulse rounded-2xl border border-white/10 bg-white/[0.04]"
        />
      ))}
    </div>
  );
}

export function SkeletonCard({ className = "" }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`h-32 animate-pulse rounded-2xl border border-white/10 bg-white/[0.04] ${className}`}
    />
  );
}

/** Friendly failure card for data fetches, with optional retry. */
export function ErrorCard({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <Card className="flex flex-col items-center gap-3 p-8 text-center">
      <Icon name="alert" className="size-7 text-[#FF9C86]" />
      <p className="max-w-sm text-sm text-white/70">{message}</p>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          <Icon name="refresh" className="size-4" /> Try again
        </Button>
      )}
    </Card>
  );
}

/** Friendly empty state for lists. */
export function EmptyCard({
  title,
  description,
  action,
  icon = "grid",
}: {
  title: string;
  description: string;
  action?: ReactNode;
  icon?: IconName;
}) {
  return (
    <Card className="flex flex-col items-center gap-2 p-10 text-center">
      <Icon name={icon} className="size-7 text-white/30" />
      <p className="mt-1 font-bold">{title}</p>
      <p className="max-w-sm text-sm text-white/55">{description}</p>
      {action && <div className="mt-3">{action}</div>}
    </Card>
  );
}

/**
 * "No permission" placeholder for admin sections: admin APIs are dogfooded
 * via Casbin (org_admins only hold the app-scoped codes), so a 403 renders
 * this instead of a raw error or a blank page.
 */
export function ForbiddenCard({
  message,
}: {
  message?: string;
}) {
  return (
    <Card className="flex flex-col items-center gap-3 p-10 text-center">
      <span className="grid size-12 place-items-center rounded-2xl border border-white/15 bg-white/[0.07] text-white/60">
        <Icon name="lock" className="size-6" />
      </span>
      <p className="mt-1 font-bold">You don&apos;t have access to this section</p>
      <p className="max-w-sm text-sm text-white/55">
        {message ??
          "Admin permissions are managed per code (platform vs org-scoped). Ask a platform administrator for access if you need this."}
      </p>
    </Card>
  );
}
