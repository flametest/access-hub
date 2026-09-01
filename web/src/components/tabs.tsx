"use client";

import { Icon, type IconName } from "@/components/icon";

export interface TabItem {
  key: string;
  label: string;
  icon?: IconName;
}

/**
 * Minimal tab bar for the admin app detail page (underline style, matches the
 * portal's quiet white-on-teal look). The parent owns the active state so tabs
 * can live in the URL.
 */
export function Tabs({
  items,
  active,
  onChange,
  className = "",
}: {
  items: TabItem[];
  active: string;
  onChange: (key: string) => void;
  className?: string;
}) {
  return (
    <div
      role="tablist"
      className={`flex gap-1 overflow-x-auto border-b border-white/10 ${className}`}
    >
      {items.map((item) => {
        const isActive = item.key === active;
        return (
          <button
            key={item.key}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(item.key)}
            className={`-mb-px flex flex-none items-center gap-2 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-bold transition-colors ${
              isActive
                ? "border-ah-accent text-white"
                : "border-transparent text-white/55 hover:text-white"
            }`}
          >
            {item.icon && <Icon name={item.icon} className="size-4" />}
            {item.label}
          </button>
        );
      })}
    </div>
  );
}
