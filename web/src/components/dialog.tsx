"use client";

import { useEffect, type ReactNode } from "react";
import { Icon } from "@/components/icon";

/**
 * Minimal modal dialog (admin create/edit forms): dark overlay + teal card,
 * closes on Escape / backdrop click, locks body scroll while open.
 */
export function Dialog({
  title,
  description,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto" role="dialog" aria-modal="true" aria-label={title}>
      <div
        className="fixed inset-0 bg-black/55 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="relative mx-auto flex min-h-full w-full items-start justify-center px-4 py-10">
        <div
          className={`w-full rounded-2xl border border-white/10 bg-[#0B4343] shadow-[0_24px_48px_-12px_rgba(0,0,0,0.6)] ${
            wide ? "max-w-2xl" : "max-w-md"
          }`}
        >
          <div className="flex items-start justify-between gap-3 border-b border-white/10 px-5 py-4">
            <div className="min-w-0">
              <h2 className="truncate font-bold">{title}</h2>
              {description && (
                <p className="mt-0.5 text-[13px] text-white/50">{description}</p>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="grid size-8 flex-none place-items-center rounded-lg text-white/50 transition-colors hover:bg-white/[0.08] hover:text-white"
            >
              <Icon name="x" className="size-4.5" />
            </button>
          </div>
          <div className="px-5 py-4">{children}</div>
        </div>
      </div>
    </div>
  );
}
