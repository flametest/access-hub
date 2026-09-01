import type { ReactNode } from "react";
import { AdminShell } from "@/components/admin/admin-shell";

/**
 * Layout for the admin console section (/admin/*) — same portal app, sidebar
 * shell. Client-side auth gate + queries live in AdminShell and the pages.
 */
export default function AdminLayout({ children }: { children: ReactNode }) {
  return <AdminShell>{children}</AdminShell>;
}
