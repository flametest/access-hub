"use client";

import type { ReactNode } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Icon } from "@/components/icon";

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
  icon?: "grid" | "key" | "ticket";
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
