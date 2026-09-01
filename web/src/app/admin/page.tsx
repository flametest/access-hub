"use client";

import Link from "next/link";
import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { AuditSummaryStrip } from "@/components/admin/audit-summary";
import { Icon } from "@/components/icon";
import { EmptyCard, ForbiddenCard, SkeletonCard } from "@/components/page-state";
import { adminApi } from "@/lib/admin/api";
import { errMessage, isForbidden } from "@/lib/api";

/**
 * Admin overview: stat cards (cheap counts from the list endpoints) + the
 * audit summary strip (M6) with a 1/7/30-day window. Each stat degrades to
 * "—" on 403 — org_admins only hold app-scoped codes, audit is platform-only.
 */

interface Stat {
  key: string;
  label: string;
  value?: number;
  icon: Parameters<typeof Icon>[0]["name"];
  href: string;
  error: unknown;
  loading: boolean;
}

function StatCard({ stat }: { stat: Stat }) {
  const forbidden = isForbidden(stat.error);
  const failed = Boolean(stat.error) && !forbidden;
  return (
    <Link
      href={stat.href}
      className="block rounded-2xl border border-white/10 bg-white/[0.06] p-5 shadow-[0_12px_24px_-8px_rgba(0,0,0,0.35)] transition-colors hover:bg-white/[0.09]"
    >
      <div className="flex items-center justify-between gap-3">
        <span className="text-[13px] font-bold uppercase tracking-wide text-white/50">
          {stat.label}
        </span>
        <span className="grid size-9 place-items-center rounded-xl bg-ah-accent/15 text-ah-accent">
          <Icon name={stat.icon} className="size-4.5" />
        </span>
      </div>
      <div className="mt-2">
        {stat.loading ? (
          <div className="h-8 w-16 animate-pulse rounded-lg bg-white/[0.08]" />
        ) : forbidden ? (
          <span
            className="text-xl font-extrabold text-white/35"
            title="You don't have permission to view this count"
          >
            —
          </span>
        ) : failed ? (
          <span
            className="text-xl font-extrabold text-[#FF9C86]"
            title={errMessage(stat.error, "Load failed")}
          >
            !
          </span>
        ) : (
          <span className="text-3xl font-extrabold tracking-tight">
            {(stat.value ?? 0).toLocaleString("en-US")}
          </span>
        )}
      </div>
    </Link>
  );
}

export default function AdminOverviewPage() {
  const [days, setDays] = useState(7);

  // Counts ride the list endpoints: orgs/apps return plain arrays; users is
  // the only paginated one, so ?page=1&page_size=1 gives the total for free.
  const appsQuery = useQuery({
    queryKey: ["admin", "apps"],
    queryFn: () => adminApi.listApps(),
  });
  const orgsQuery = useQuery({
    queryKey: ["admin", "orgs"],
    queryFn: () => adminApi.listOrgs(),
  });
  const usersQuery = useQuery({
    queryKey: ["admin", "users", "count"],
    queryFn: () => adminApi.listUsers("", 1, 1),
  });
  const summaryQuery = useQuery({
    queryKey: ["admin", "audit-summary", days],
    queryFn: () => adminApi.auditSummary(days),
  });

  const summary = summaryQuery.data;
  const eventsTotal = (summary?.daily ?? []).reduce(
    (sum, day) => sum + day.count,
    0,
  );

  const stats: Stat[] = [
    {
      key: "apps",
      label: "Apps",
      value: appsQuery.data?.length,
      icon: "layers",
      href: "/admin/apps",
      error: appsQuery.error,
      loading: appsQuery.isLoading,
    },
    {
      key: "orgs",
      label: "Organizations",
      value: orgsQuery.data?.length,
      icon: "building",
      href: "/admin/orgs",
      error: orgsQuery.error,
      loading: orgsQuery.isLoading,
    },
    {
      key: "users",
      label: "Users",
      value: usersQuery.data?.total,
      icon: "users",
      href: "/admin/users",
      error: usersQuery.error,
      loading: usersQuery.isLoading,
    },
    {
      key: "events",
      label: `Audit events · ${days}d`,
      value: summaryQuery.isError ? undefined : eventsTotal,
      icon: "log",
      href: "/admin/audit",
      error: summaryQuery.error,
      loading: summaryQuery.isLoading,
    },
  ];

  let summaryBody: ReactNode;
  if (isForbidden(summaryQuery.error)) {
    summaryBody = (
      <ForbiddenCard message="Audit logs are platform-only (admin:audit:read) — org admins can't read them." />
    );
  } else if (summaryQuery.isError) {
    summaryBody = (
      <EmptyCard
        icon="log"
        title="Audit summary unavailable"
        description={errMessage(
          summaryQuery.error,
          "The audit summary endpoint may not be available yet.",
        )}
      />
    );
  } else if (summaryQuery.isLoading && !summary) {
    summaryBody = <SkeletonCard />;
  } else {
    summaryBody = (
      <AuditSummaryStrip
        days={days}
        onDaysChange={setDays}
        summary={summary}
        isLoading={summaryQuery.isLoading}
        error={summaryQuery.error}
        onRetry={() => summaryQuery.refetch()}
      />
    );
  }

  return (
    <div>
      <h1 className="text-2xl font-extrabold tracking-tight">Overview</h1>
      <p className="mt-1 text-sm text-white/55">
        Platform snapshot — apps, orgs, identities and recent audit activity.
      </p>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => (
          <StatCard key={stat.key} stat={stat} />
        ))}
      </div>

      <div className="mt-8">
        <div className="space-y-4">
          {summaryBody}
          <p className="text-xs text-white/40">
            Events per day come from{" "}
            <code className="font-mono">GET /admin/audit-logs/summary</code>{" "}
            (M6). The full log with filters lives under{" "}
            <Link
              href="/admin/audit"
              className="underline underline-offset-2 hover:text-white/70"
            >
              Audit log
            </Link>
            .
          </p>
        </div>
      </div>
    </div>
  );
}
