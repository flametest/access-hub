"use client";

import { Card } from "@/components/card";
import { SkeletonCard } from "@/components/page-state";
import { ErrorCard } from "@/components/page-state";
import type { AuditSummary } from "@/lib/admin/types";

/**
 * Audit summary strip (GET /admin/audit-logs/summary?days=N): CSS-only daily
 * bar chart (no chart lib), a top-10 by-action list, and the top actors list.
 * Shared by the /admin overview and the /admin/audit page.
 */

const SEGMENTS = [1, 7, 30];

export function AuditSummaryStrip({
  days,
  onDaysChange,
  summary,
  isLoading,
  error,
  onRetry,
}: {
  days: number;
  onDaysChange: (days: number) => void;
  summary?: AuditSummary;
  isLoading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-bold">Audit activity</h2>
        <div
          role="radiogroup"
          aria-label="Summary window"
          className="flex flex-none gap-1 rounded-lg border border-white/15 bg-white/[0.06] p-1"
        >
          {SEGMENTS.map((value) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={days === value}
              onClick={() => onDaysChange(value)}
              className={`rounded-md px-2.5 py-1 text-xs font-bold transition-colors ${
                days === value
                  ? "bg-ah-accent text-white"
                  : "text-white/60 hover:bg-white/[0.08] hover:text-white"
              }`}
            >
              {value === 1 ? "24h" : `${value}d`}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-3">
        {isLoading && <SkeletonCard />}
        {Boolean(error) && (
          <ErrorCard
            message="We couldn't load the audit summary. The summary endpoint may not be available yet."
            onRetry={onRetry}
          />
        )}
        {summary && <AuditSummaryCards summary={summary} />}
      </div>
    </div>
  );
}

export function AuditSummaryCards({ summary }: { summary: AuditSummary }) {
  const daily = summary.daily ?? [];
  const maxDaily = Math.max(1, ...daily.map((d) => d.count));
  const total = daily.reduce((sum, d) => sum + d.count, 0);
  const actions = (summary.by_action ?? []).slice(0, 10);
  const maxAction = Math.max(1, ...actions.map((a) => a.count));
  const actors = (summary.top_actors ?? []).slice(0, 5);
  const maxActor = Math.max(1, ...actors.map((a) => a.count));

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {/* Daily counts — pure CSS bars */}
      <Card className="p-5 lg:col-span-2">
        <div className="flex items-baseline justify-between">
          <h3 className="text-sm font-bold text-white/80">Events per day</h3>
          <span className="text-sm font-extrabold text-ah-accent">
            {total.toLocaleString("en-US")} events
          </span>
        </div>
        {daily.length === 0 ? (
          <p className="mt-6 text-sm text-white/45">No events in this window.</p>
        ) : (
          <div className="mt-5 flex h-32 items-end gap-1.5">
            {daily.map((day) => {
              const heightPct = Math.round((day.count / maxDaily) * 100);
              return (
                <div
                  key={day.date}
                  className="group relative flex min-w-4 flex-1 flex-col items-center justify-end"
                  title={`${day.date}: ${day.count}`}
                >
                  <span className="mb-1 text-[10px] font-semibold text-white/55 opacity-0 transition-opacity group-hover:opacity-100">
                    {day.count}
                  </span>
                  <div
                    className="w-full rounded-t bg-ah-accent/70 transition-colors group-hover:bg-ah-accent"
                    style={{ height: `${Math.max(heightPct, day.count > 0 ? 6 : 2)}%` }}
                  />
                  <span className="mt-1.5 w-full truncate text-center text-[10px] text-white/40">
                    {day.date.slice(5)}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Top actions + actors */}
      <div className="flex flex-col gap-4">
        <Card className="p-5">
          <h3 className="text-sm font-bold text-white/80">Top actions</h3>
          {actions.length === 0 ? (
            <p className="mt-3 text-sm text-white/45">No actions recorded.</p>
          ) : (
            <ul className="mt-3 space-y-2">
              {actions.map((action) => (
                <li key={action.action} className="text-[13px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="min-w-0 truncate font-mono text-white/80">
                      {action.action}
                    </span>
                    <span className="flex-none font-bold text-white/60">
                      {action.count.toLocaleString("en-US")}
                    </span>
                  </div>
                  <div className="mt-1 h-1 overflow-hidden rounded-full bg-white/[0.08]">
                    <div
                      className="h-full rounded-full bg-ah-accent/70"
                      style={{
                        width: `${Math.max((action.count / maxAction) * 100, 4)}%`,
                      }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card className="p-5">
          <h3 className="text-sm font-bold text-white/80">Top actors</h3>
          {actors.length === 0 ? (
            <p className="mt-3 text-sm text-white/45">No actors recorded.</p>
          ) : (
            <ul className="mt-3 space-y-2.5">
              {actors.map((actor) => (
                <li key={`${actor.actor_type}-${actor.actor_id}`} className="text-[13px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="min-w-0 flex-1 truncate text-white/80">
                      <span className="font-semibold text-white/55">
                        {actor.actor_type}
                      </span>{" "}
                      <span className="font-mono">{actor.actor_id || "—"}</span>
                    </span>
                    <span className="flex-none font-bold text-white/60">
                      {actor.count.toLocaleString("en-US")}
                    </span>
                  </div>
                  <div className="mt-1 h-1 overflow-hidden rounded-full bg-white/[0.08]">
                    <div
                      className="h-full rounded-full bg-white/30"
                      style={{
                        width: `${Math.max((actor.count / maxActor) * 100, 4)}%`,
                      }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
