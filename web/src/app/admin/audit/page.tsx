"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { AuditSummaryStrip } from "@/components/admin/audit-summary";
import { Button } from "@/components/button";
import { Field } from "@/components/field";
import { ForbiddenCard } from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { adminApi } from "@/lib/admin/api";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

const PAGE_SIZE = 25;

/**
 * Audit log: platform-only (admin:audit:read). Action/org_key filters ride
 * the query string; pagination is server-side (page/page_size from the
 * backend). Detail jsonb is pretty-printed inside the expandable row.
 */
export default function AdminAuditPage() {
  const [days, setDays] = useState(7);

  // Filters (applied on submit so a partial edit doesn't refetch per keystroke)
  const [actionInput, setActionInput] = useState("");
  const [orgKeyInput, setOrgKeyInput] = useState("");
  const [action, setAction] = useState("");
  const [orgKey, setOrgKey] = useState("");
  const [page, setPage] = useState(1);

  const logsQuery = useQuery({
    queryKey: ["admin", "audit-logs", action, orgKey, page],
    queryFn: () => adminApi.listAuditLogs({ action, org_key: orgKey }, page, PAGE_SIZE),
  });
  const summaryQuery = useQuery({
    queryKey: ["admin", "audit-summary", days],
    queryFn: () => adminApi.auditSummary(days),
  });

  // Click-to-expand detail rows (one open at a time).
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (isForbidden(logsQuery.error) && isForbidden(summaryQuery.error)) {
    return (
      <>
        <h1 className="text-2xl font-extrabold tracking-tight">Audit log</h1>
        <div className="mt-6">
          <ForbiddenCard message="Audit logs are platform-only (admin:audit:read)." />
        </div>
      </>
    );
  }

  const data = logsQuery.data;
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <h1 className="text-2xl font-extrabold tracking-tight">Audit log</h1>
      <p className="mt-1 text-sm text-white/55">
        Every admin mutation, sign-in event and policy sync — who did what,
        from where.
      </p>

      {/* Summary strip */}
      <div className="mt-6">
        {isForbidden(summaryQuery.error) ? (
          <ForbiddenCard message="The audit summary endpoint is platform-only." />
        ) : (
          <AuditSummaryStrip
            days={days}
            onDaysChange={setDays}
            summary={summaryQuery.data}
            isLoading={summaryQuery.isLoading}
            error={summaryQuery.error}
            onRetry={() => summaryQuery.refetch()}
          />
        )}
      </div>

      {/* Filters */}
      <form
        className="mt-8 grid max-w-2xl gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
        onSubmit={(event) => {
          event.preventDefault();
          setPage(1);
          setAction(actionInput.trim());
          setOrgKey(orgKeyInput.trim());
        }}
      >
        <Field
          label="Action contains"
          value={actionInput}
          onChange={(event) => setActionInput(event.target.value)}
          placeholder="role.granted"
        />
        <Field
          label="Org key"
          value={orgKeyInput}
          onChange={(event) => setOrgKeyInput(event.target.value)}
          placeholder="acme"
        />
        <div className="flex gap-2">
          <Button type="submit">Apply</Button>
          {(action || orgKey) && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setActionInput("");
                setOrgKeyInput("");
                setAction("");
                setOrgKey("");
                setPage(1);
              }}
            >
              Clear
            </Button>
          )}
        </div>
      </form>

      {/* Log table */}
      <div className="mt-4">
        {logsQuery.isLoading && <TableSkeleton rows={8} />}
        {logsQuery.isError && !isForbidden(logsQuery.error) && (
          <p
            role="alert"
            className="rounded-xl border border-[#FF5630]/30 bg-[#FF5630]/10 px-4 py-3 text-sm text-[#FF9C86]"
          >
            {errMessage(logsQuery.error, "We couldn't load audit logs.")}
          </p>
        )}
        {data && (
          <>
            <Table
              columns={[
                { key: "time", header: "Time", className: "whitespace-nowrap" },
                { key: "actor", header: "Actor", className: "min-w-[180px]" },
                { key: "action", header: "Action", className: "font-mono text-[13px]" },
                { key: "target", header: "Target", className: "min-w-[140px]" },
                { key: "ip", header: "IP" },
                { key: "expand", header: "", className: "w-8 text-right" },
              ]}
              rows={data.items}
              rowKey={(log) => log.id}
              onRowClick={(log) =>
                setExpandedId((current) => (current === log.id ? null : log.id))
              }
              cell={(log, column) => {
                switch (column.key) {
                  case "time":
                    return (
                      <span className="whitespace-nowrap text-white/70">
                        {formatDateTime(log.created_at) ?? "—"}
                      </span>
                    );
                  case "actor":
                    return (
                      <span className="min-w-0">
                        <span className="block text-xs font-bold uppercase tracking-wide text-white/45">
                          {log.actor_type}
                        </span>
                        <span className="block max-w-[180px] truncate font-mono text-[13px] text-white/80">
                          {log.actor_id || "—"}
                        </span>
                      </span>
                    );
                  case "action":
                    return <span className="text-ah-accent">{log.action}</span>;
                  case "target":
                    return (
                      <span className="text-[13px] text-white/60">
                        {log.target_type
                          ? `${log.target_type} ${log.target_id ? `· ${log.target_id}` : ""}`
                          : "—"}
                      </span>
                    );
                  case "ip":
                    return (
                      <span className="font-mono text-[13px] text-white/60">
                        {log.ip || "—"}
                      </span>
                    );
                  case "expand":
                    return log.detail ? (
                      <span className="text-white/35">
                        {expandedId === log.id ? "▾" : "▸"}
                      </span>
                    ) : null;
                  default:
                    return null;
                }
              }}
              expandable={(log) => {
                if (!log.detail || expandedId !== log.id) return null;
                return <DetailBlock detail={log.detail} userAgent={log.user_agent} />;
              }}
            />

            {data.items.length === 0 ? (
              <p className="mt-4 rounded-xl border border-white/10 px-4 py-3.5 text-sm text-white/55">
                No audit entries match these filters.
              </p>
            ) : (
              <div className="mt-3 flex items-center justify-between gap-3 text-[13px] text-white/55">
                <span>
                  {total.toLocaleString("en-US")} entries · page {data.page} of{" "}
                  {pageCount}
                </span>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    Previous
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page >= pageCount}
                    onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/** Pretty-printed detail jsonb + user agent inside the expandable row. */
function DetailBlock({ detail, userAgent }: { detail: string; userAgent: string }) {
  let pretty = detail;
  try {
    pretty = JSON.stringify(JSON.parse(detail), null, 2);
  } catch {
    // detail isn't JSON — show it verbatim.
  }
  return (
    <div className="space-y-2 rounded-xl bg-black/25 p-3">
      <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-white/75">
        {pretty}
      </pre>
      {userAgent && (
        <p className="break-all text-xs text-white/40">UA: {userAgent}</p>
      )}
    </div>
  );
}
