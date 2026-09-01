"use client";

import type { ChangeEvent, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { useId } from "react";

/**
 * Form primitives matching components/field.tsx styling for the admin dialog
 * forms (selects, textareas, checkbox groups — Field is input-only).
 */

function labelClasses(): string {
  return "mb-1.5 block text-[13px] font-semibold text-white/90";
}

function controlClasses(error?: string | null): string {
  return `w-full rounded-lg border bg-white/[0.06] px-3.5 py-2.5 text-[15px] text-white transition-colors placeholder:text-white/30 focus:outline-none focus:ring-2 disabled:opacity-50 ${
    error
      ? "border-[#FF5630]/60 focus:border-[#FF5630] focus:ring-[#FF5630]/25"
      : "border-white/15 focus:border-ah-accent focus:ring-ah-accent/30"
  }`;
}

export interface SelectFieldProps
  extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "children"> {
  label: string;
  error?: string | null;
  hint?: string;
  children: ReactNode;
}

export function SelectField({
  label,
  error,
  hint,
  id,
  className = "",
  children,
  ...rest
}: SelectFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  return (
    <div className={className}>
      <label htmlFor={inputId} className={labelClasses()}>
        {label}
      </label>
      <select
        id={inputId}
        aria-invalid={error ? true : undefined}
        className={controlClasses(error)}
        {...rest}
      >
        {children}
      </select>
      {hint && !error && <p className="mt-1.5 text-xs text-white/45">{hint}</p>}
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-[#FF9C86]">
          {error}
        </p>
      )}
    </div>
  );
}

export interface TextareaFieldProps
  extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string;
  error?: string | null;
  hint?: string;
  monospace?: boolean;
}

export function TextareaField({
  label,
  error,
  hint,
  monospace = false,
  id,
  className = "",
  ...rest
}: TextareaFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const hintId = `${inputId}-hint`;
  return (
    <div className={className}>
      <label htmlFor={inputId} className={labelClasses()}>
        {label}
      </label>
      <textarea
        id={inputId}
        aria-invalid={error ? true : undefined}
        aria-describedby={hint ? hintId : undefined}
        className={`${controlClasses(error)} ${monospace ? "font-mono text-[13px] leading-relaxed" : ""}`}
        {...rest}
      />
      {hint && !error && (
        <p id={hintId} className="mt-1.5 text-xs text-white/45">
          {hint}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-[#FF9C86]">
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * Checkbox group for multi-selects (role pickers, grant types). Renders a
 * scrollable bordered list; empty state shows a friendly hint.
 */
export function CheckboxList({
  label,
  options,
  selected,
  onToggle,
  error,
  emptyHint = "Nothing to choose from yet.",
  maxH = "max-h-44",
}: {
  label: string;
  options: { value: string; label: string; detail?: string }[];
  selected: string[];
  onToggle: (value: string) => void;
  error?: string | null;
  emptyHint?: string;
  maxH?: string;
}) {
  const toggle = (event: ChangeEvent<HTMLInputElement>) => {
    onToggle(event.target.value);
  };
  return (
    <div>
      <span className={labelClasses()}>{label}</span>
      <div
        className={`${maxH} overflow-y-auto rounded-lg border border-white/15 bg-white/[0.06] p-1.5`}
      >
        {options.length === 0 && (
          <p className="px-2.5 py-2 text-[13px] text-white/45">{emptyHint}</p>
        )}
        {options.map((option) => {
          const checked = selected.includes(option.value);
          return (
            <label
              key={option.value}
              className={`flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors hover:bg-white/[0.06] ${
                checked ? "text-white" : "text-white/70"
              }`}
            >
              <input
                type="checkbox"
                value={option.value}
                checked={checked}
                onChange={toggle}
                className="size-4 flex-none accent-[#54B3B3]"
              />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-semibold">{option.label}</span>
                {option.detail && (
                  <span className="block truncate text-xs text-white/45">
                    {option.detail}
                  </span>
                )}
              </span>
            </label>
          );
        })}
      </div>
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-[#FF9C86]">
          {error}
        </p>
      )}
    </div>
  );
}
