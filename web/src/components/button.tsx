"use client";

import type { ButtonHTMLAttributes } from "react";
import { Spinner } from "@/components/spinner";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const VARIANT_CLASSES: Record<Variant, string> = {
  primary:
    "bg-ah-accent text-white font-bold shadow-[0_8px_16px_rgba(84,179,179,0.24)] hover:bg-ah-accent-strong",
  secondary:
    "bg-white/[0.06] text-white font-bold border border-white/15 hover:bg-white/[0.12]",
  ghost:
    "bg-transparent text-white/60 font-bold hover:bg-white/[0.06] hover:text-white",
  danger:
    "bg-white/[0.06] text-[#FF9C86] font-bold border border-[#FF5630]/45 hover:bg-[#FF5630]/10",
};

const SIZE_CLASSES: Record<Size, string> = {
  sm: "px-3.5 py-2 text-[13px]",
  md: "px-4 py-2.5 text-sm",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  /** Shows a spinner and disables interaction while an async action runs. */
  loading?: boolean;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  disabled,
  className = "",
  children,
  type = "button",
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`inline-flex items-center justify-center gap-2 rounded-lg transition-colors duration-150 outline-offset-2 outline-ah-accent/70 focus-visible:outline-2 disabled:cursor-not-allowed disabled:opacity-50 ${VARIANT_CLASSES[variant]} ${SIZE_CLASSES[size]} ${className}`}
      {...rest}
    >
      {loading && <Spinner className="size-4" />}
      {children}
    </button>
  );
}
