"use client";

import { useEffect, type ReactNode } from "react";
import { Icon } from "@/components/icon";

/**
 * Right-side drawer for admin sub-views (role resource binding, account
 * grants, org members). Wide body, closes on Escape / backdrop click.
 */
export function Drawer({
  title,
  description,
  onClose,
  children,
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
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
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={title}>
      <div
        className="fixed inset-0 bg-black/55 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="fixed inset-y-0 right-0 flex w-full max-w-xl flex-col border-l border-white/10 bg-[#0B4343] shadow-[-24px_0_48px_-12px_rgba(0,0,0,0.6)]">
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
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  );
}
