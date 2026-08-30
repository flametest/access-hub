import type { ReactNode } from "react";
import { Icon } from "@/components/icon";

/** Inline form-level error box. Renders nothing when children are empty. */
export function ErrorAlert({ children }: { children: ReactNode }) {
  if (!children) return null;
  return (
    <div
      role="alert"
      className="flex items-start gap-2.5 rounded-lg border border-[#FF5630]/35 bg-[#FF5630]/10 px-3.5 py-2.5 text-sm text-[#FF9C86]"
    >
      <Icon name="alert" className="mt-0.5 size-4 flex-none" />
      <span>{children}</span>
    </div>
  );
}
