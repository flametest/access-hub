"use client";

import type { ReactNode } from "react";

function titleize(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

const STATUS_STYLES: Record<string, string> = {
  active: "border-[#22C55E]/30 bg-[#22C55E]/15 text-[#7CE49F]",
  pending_activation: "border-[#FFAB00]/30 bg-[#FFAB00]/15 text-[#FFC96B]",
  pending: "border-[#FFAB00]/30 bg-[#FFAB00]/15 text-[#FFC96B]",
  disabled: "border-[#FF5630]/30 bg-[#FF5630]/15 text-[#FF9C86]",
};

/** Status pill for workspace accounts: active / pending_activation / disabled. */
export function StatusChip({
  status,
  className = "",
}: {
  status: string;
  className?: string;
}) {
  const key = (status || "").toLowerCase();
  const tone =
    STATUS_STYLES[key] ?? "border-white/15 bg-white/[0.07] text-white/60";
  const label =
    key === "active"
      ? "Active"
      : key === "pending_activation"
        ? "Pending activation"
        : key === "pending"
          ? "Pending"
          : key === "disabled"
            ? "Disabled"
            : titleize(status) || "Unknown";
  return (
    <span
      className={`inline-flex flex-none items-center whitespace-nowrap rounded-md border px-2.5 py-0.5 text-xs font-semibold ${tone} ${className}`}
    >
      {label}
    </span>
  );
}

type ChipTone = "neutral" | "accent" | "success";

const CHIP_TONES: Record<ChipTone, string> = {
  neutral: "border-white/15 bg-white/[0.07] text-white/70",
  accent: "border-ah-accent/30 bg-ah-accent/15 text-[#7CD4D4]",
  success: "border-[#22C55E]/30 bg-[#22C55E]/15 text-[#7CE49F]",
};

/** Generic small tag: "Primary identity", "2FA", "Signed in", method chips... */
export function Chip({
  tone = "neutral",
  className = "",
  children,
}: {
  tone?: ChipTone;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2.5 py-0.5 text-xs font-semibold ${CHIP_TONES[tone]} ${className}`}
    >
      {children}
    </span>
  );
}
