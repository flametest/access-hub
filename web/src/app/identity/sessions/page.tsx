"use client";

import Link from "next/link";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Card } from "@/components/card";
import { Chip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Icon } from "@/components/icon";
import { EmptyCard, ErrorCard, SkeletonCard } from "@/components/page-state";
import { PortalShell } from "@/components/portal-shell";
import { useToast } from "@/components/toast";
import { useRequireAuth } from "@/hooks/use-require-auth";
import { useSessions } from "@/hooks/use-sessions";
import { api, errMessage } from "@/lib/api";
import { formatDateTime, formatRelative } from "@/lib/format";
import { parseUA, uaLabel } from "@/lib/ua";
import type { SessionItem } from "@/lib/types";

const SESSIONS_KEY = ["me-sessions"] as const;

/** monitor for desktop, smartphone for mobile — the icon tile's glyph. */
function deviceIcon(session: SessionItem) {
  return parseUA(session.device).device === "mobile" ? "smartphone" : "monitor";
}

function statusChip(session: SessionItem) {
  if (session.current) {
    return (
      <Chip tone="accent">
        <Icon name="check-circle" className="size-3.5" /> This device
      </Chip>
    );
  }
  if (!session.active) {
    const expired = new Date(session.expires_at) < new Date();
    return <Chip tone="neutral">{expired ? "Expired" : "Revoked"}</Chip>;
  }
  return null;
}

/** Sub-line under the device label: IP, last activity, workspace scope. */
function sessionDetail(session: SessionItem): string {
  const parts = [
    session.ip,
    formatRelative(session.last_used_at ?? session.created_at) &&
      `active ${formatRelative(session.last_used_at ?? session.created_at)}`,
    session.scope === "account" && session.app_key
      ? `workspace ${session.app_key}`
      : "",
  ].filter(Boolean);
  return parts.join(" · ") || "No IP recorded";
}

function SessionRow({
  session,
  busy,
  onRevoke,
}: {
  session: SessionItem;
  busy: boolean;
  onRevoke: (session: SessionItem) => void;
}) {
  const chip = statusChip(session);
  const revocable = session.active && !session.current;
  return (
    <div className="flex flex-wrap items-center gap-3.5 px-2 py-3.5">
      <span className="grid size-10 flex-none place-items-center rounded-lg bg-white/[0.07] text-white/70">
        <Icon name={deviceIcon(session)} className="size-5" />
      </span>
      <div className="min-w-0 flex-1 basis-56" title={session.device || undefined}>
        <div className="truncate text-sm font-bold">
          {uaLabel(session.device) || session.device || "Unknown device"}
        </div>
        <div className="mt-0.5 truncate text-xs text-white/45">
          {sessionDetail(session)}
        </div>
      </div>
      <div className="flex flex-none items-center gap-2.5">
        <span
          className="hidden text-xs text-white/40 sm:inline"
          title={`Signed in ${formatDateTime(session.created_at) ?? ""}`}
        >
          {formatRelative(session.created_at) ?? ""}
        </span>
        {chip}
        {revocable && (
          <ConfirmButton
            size="sm"
            confirmLabel="Confirm revoke"
            disabled={busy}
            loading={busy}
            onConfirm={() => onRevoke(session)}
          >
            Revoke
          </ConfirmButton>
        )}
      </div>
    </div>
  );
}

/**
 * Sessions & devices: every login session of the identity (GET /me/sessions),
 * live ones up top with per-device revoke, the revoked/expired history below.
 * "Sign out other sessions" hits DELETE /me/sessions (all scopes).
 */
export default function SessionsPage() {
  const { authed } = useRequireAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const query = useSessions(authed);
  const sessions = query.data;

  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokingOthers, setRevokingOthers] = useState(false);

  const active = (sessions ?? [])
    .filter((s) => s.active)
    .sort((a, b) => {
      if (a.current !== b.current) return a.current ? -1 : 1;
      const aAt = a.last_used_at ?? a.created_at;
      const bAt = b.last_used_at ?? b.created_at;
      return bAt.localeCompare(aAt);
    });
  const history = (sessions ?? [])
    .filter((s) => !s.active)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  const otherActive = active.filter((s) => !s.current).length;

  async function onRevoke(session: SessionItem) {
    if (revokingId) return;
    setRevokingId(session.id);
    try {
      await api.revokeSession(session.id);
      toast("That session has been signed out.", "success");
      await queryClient.invalidateQueries({ queryKey: SESSIONS_KEY });
    } catch (err) {
      toast(errMessage(err, "We couldn't revoke that session."), "error");
    } finally {
      setRevokingId(null);
    }
  }

  async function onRevokeOthers() {
    if (revokingOthers) return;
    setRevokingOthers(true);
    try {
      await api.revokeOtherSessions();
      toast("Signed out all other devices.", "success");
      await queryClient.invalidateQueries({ queryKey: SESSIONS_KEY });
    } catch (err) {
      toast(errMessage(err, "We couldn't sign out the other sessions."), "error");
    } finally {
      setRevokingOthers(false);
    }
  }

  return (
    <PortalShell width="normal">
      <Link
        href="/identity"
        className="inline-flex items-center gap-1.5 text-sm text-white/55 transition-colors hover:text-white/85"
      >
        <Icon name="arrow-left" className="size-4" /> Back to identity
      </Link>

      <div className="mt-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
            Sessions &amp; devices
          </h1>
          <p className="mt-1 max-w-xl text-sm text-white/55">
            Every device signed in to your Company ID. Revoke anything you
            don&apos;t recognize — that device is signed out on its next
            refresh.
          </p>
        </div>
        <ConfirmButton
          size="sm"
          variant="secondary"
          confirmLabel="Confirm sign out"
          confirmVariant="danger"
          loading={revokingOthers}
          disabled={revokingOthers || revokingId !== null || otherActive === 0}
          onConfirm={() => void onRevokeOthers()}
        >
          Sign out other sessions
        </ConfirmButton>
      </div>

      {query.isLoading && <SkeletonCard className="mt-5" />}

      {query.isError && (
        <div className="mt-5">
          <ErrorCard
            message={errMessage(query.error, "We couldn't load your sessions.")}
            onRetry={() => query.refetch()}
          />
        </div>
      )}

      {sessions && active.length === 0 && (
        <div className="mt-5">
          <EmptyCard
            title="No active sessions"
            description="Sign in again to create one."
            icon="monitor"
          />
        </div>
      )}

      {sessions && active.length > 0 && (
        <Card className="mt-5 divide-y divide-white/[0.08] p-0">
          {active.map((session) => (
            <SessionRow
              key={session.id}
              session={session}
              busy={revokingId !== null}
              onRevoke={(s) => void onRevoke(s)}
            />
          ))}
        </Card>
      )}

      {sessions && history.length > 0 && (
        <>
          <h2 className="mt-8 mb-2 text-sm font-bold text-white/55">
            History
          </h2>
          <Card className="divide-y divide-white/[0.06] p-0 opacity-75">
            {history.map((session) => (
              <SessionRow
                key={session.id}
                session={session}
                busy
                onRevoke={() => {}}
              />
            ))}
          </Card>
        </>
      )}
    </PortalShell>
  );
}
