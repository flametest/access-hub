"use client";

import type { InputHTMLAttributes } from "react";
import { useId } from "react";

export interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string | null;
  hint?: string;
}

/** Labeled input with accessible error/hint wiring and teal focus ring. */
export function Field({
  label,
  error,
  hint,
  id,
  className = "",
  ...rest
}: FieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;

  return (
    <div className={className}>
      <label
        htmlFor={inputId}
        className="mb-1.5 block text-[13px] font-semibold text-white/90"
      >
        {label}
      </label>
      <input
        id={inputId}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : hint ? hintId : undefined}
        className={`w-full rounded-lg border bg-white/[0.06] px-3.5 py-2.5 text-[15px] text-white transition-colors placeholder:text-white/30 focus:outline-none focus:ring-2 disabled:opacity-50 ${
          error
            ? "border-[#FF5630]/60 focus:border-[#FF5630] focus:ring-[#FF5630]/25"
            : "border-white/15 focus:border-ah-accent focus:ring-ah-accent/30"
        }`}
        {...rest}
      />
      {hint && !error && (
        <p id={hintId} className="mt-1.5 text-xs text-white/45">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} role="alert" className="mt-1.5 text-xs text-[#FF9C86]">
          {error}
        </p>
      )}
    </div>
  );
}
