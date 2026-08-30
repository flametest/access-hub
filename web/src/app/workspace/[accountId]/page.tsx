"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useSyncExternalStore, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip, StatusChip } from "@/components/chips";
import { GoogleIcon, Icon, MicrosoftIcon, methodIcon } from "@/components/icon";
import { Initials } from "@/components/initials";
import { ErrorCard, SkeletonCard } from "@/components/page-state";
import { PortalShell } from "@/components/portal-shell";
import { useToast } from "@/components/toast";
import { useRequireAuth } from "@/hooks/use-require-auth";
import { api, errMessage } from "@/lib/api";
import { getAppToken, subscribeToTokenChanges } from "@/lib/tokens";

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-white/[0.06] py-2.5 text-sm first:pt-0 last:border-0 last:pb-0">
      <span className="text-white/55">{label}</span>
      <span className="min-w-0 truncate text-right font-semibold">
        {children}
      </span>
    </div>
  );
}

export default function WorkspaceDetailPage() {
  const params = useParams<{ accountId: string }>();
  const accountId = params.accountId;
  const toast = useToast();
  const { authed } = useRequireAuth();

  const workspaceQuery = useQuery({
    queryKey: ["workspace", accountId],
    queryFn: () => api.getWorkspace(accountId),
    enabled: authed,
  });
  const methodsQuery = useQuery({
    queryKey: ["signin-methods"],
    queryFn: () => api.listSignInMethods(),
    enabled: authed,
  });

  // App token for this workspace (present when opened from /workspaces).
  const appToken = useSyncExternalStore(
    subscribeToTokenChanges,
    () => getAppToken(accountId),
    () => null,
  );

  const ws = workspaceQuery.data;

  async function copyToken() {
    if (!appToken) return;
    try {
      await navigator.clipboard.writeText(appToken);
      toast("Access token copied to clipboard.", "success");
    } catch {
      toast("Couldn't access the clipboard.", "error");
    }
  }

  if (workspaceQuery.isError) {
    return (
      <PortalShell width="normal">
        <Link
          href="/workspaces"
          className="mb-5 inline-flex items-center gap-2 text-sm font-bold text-white/60 hover:text-white"
        >
          <Icon name="arrow-left" className="size-4" /> Back to workspaces
        </Link>
        <ErrorCard
          message={errMessage(
            workspaceQuery.error,
            "We couldn't load this workspace.",
          )}
          onRetry={() => workspaceQuery.refetch()}
        />
      </PortalShell>
    );
  }

  if (!ws) {
    return (
      <PortalShell width="normal">
        <div className="mb-6 flex items-center gap-4">
          <div className="size-14 animate-pulse rounded-full bg-white/[0.06]" />
          <div className="flex-1 space-y-2">
            <div className="h-5 w-40 animate-pulse rounded bg-white/[0.06]" />
            <div className="h-3.5 w-56 animate-pulse rounded bg-white/[0.04]" />
          </div>
        </div>
        <SkeletonCard className="mb-5" />
        <SkeletonCard />
      </PortalShell>
    );
  }

  return (
    <PortalShell width="normal">
      <Link
        href="/workspaces"
        className="mb-5 inline-flex items-center gap-2 text-sm font-bold text-white/60 hover:text-white"
      >
        <Icon name="arrow-left" className="size-4" /> Back to workspaces
      </Link>

      {/* Header */}
      <div className="mb-6 flex items-center gap-4 sm:gap-5">
        <Initials name={ws.app_name} size="lg" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
              {ws.app_name}
            </h1>
            <StatusChip status={ws.status} />
          </div>
          <p className="mt-1 truncate text-sm text-white/55">
            {[ws.email, ws.roles.join(", ")].filter(Boolean).join(" · ")}
          </p>
        </div>
      </div>

      {/* Signed-in strip (prototype's "You're in X") */}
      {appToken && (
        <div className="mb-6 flex flex-wrap items-center gap-3 rounded-xl border border-ah-accent/25 bg-ah-accent/[0.08] px-4 py-3">
          <Icon name="check-circle" className="size-5 flex-none text-ah-accent" />
          <p className="min-w-0 flex-1 text-sm text-white/75">
            You&apos;re in{" "}
            <span className="font-semibold text-white">{ws.app_name}</span> —
            signed in through your Company ID.
          </p>
          <Chip tone="accent">Signed in</Chip>
          <Button size="sm" variant="secondary" onClick={copyToken}>
            <Icon name="copy" className="size-3.5" /> Copy access token
          </Button>
        </div>
      )}

      {/* Access & role */}
      <Card className="mb-5 p-5 sm:p-6">
        <h2 className="mb-3 font-bold">Access &amp; role</h2>
        <DetailRow label="Role(s)">
          {ws.roles.length > 0 ? ws.roles.join(", ") : "No roles assigned"}
        </DetailRow>
        <DetailRow label="Workspace app">{ws.app_name}</DetailRow>
        {ws.org_name && <DetailRow label="Organization">{ws.org_name}</DetailRow>}
        <DetailRow label="Workspace email">
          {ws.email || "Not set yet"}
        </DetailRow>
        <DetailRow label="Status">
          <StatusChip status={ws.status} />
        </DetailRow>
      </Card>

      {/* Sign-in methods */}
      <Card className="p-5 sm:p-6">
        <h2 className="font-bold">Sign-in methods</h2>
        <p className="mt-0.5 mb-4 text-[13px] text-white/50">
          Ways this account can sign in. More providers are on the roadmap.
        </p>

        {methodsQuery.isLoading && (
          <div
            className="h-[66px] animate-pulse rounded-xl border border-white/10 bg-white/[0.04]"
            aria-hidden="true"
          />
        )}

        {methodsQuery.isError && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#FF5630]/30 bg-[#FF5630]/10 px-4 py-3 text-sm text-[#FF9C86]">
            <span>
              {errMessage(
                methodsQuery.error,
                "We couldn't load your sign-in methods.",
              )}
            </span>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => methodsQuery.refetch()}
            >
              Try again
            </Button>
          </div>
        )}

        {methodsQuery.data && methodsQuery.data.length === 0 && (
          <p className="rounded-xl border border-white/10 px-4 py-3.5 text-sm text-white/55">
            No sign-in methods configured yet.
          </p>
        )}

        {methodsQuery.data && methodsQuery.data.length > 0 && (
          <div className="space-y-2.5">
            {methodsQuery.data.map((m) => (
              <div
                key={m.method}
                className="flex items-center gap-3.5 rounded-xl border border-white/10 px-4 py-3.5"
              >
                <span className="grid size-10 flex-none place-items-center rounded-lg bg-white/[0.07] text-white/70">
                  {m.method === "google" ? (
                    <GoogleIcon className="size-5" />
                  ) : m.method === "microsoft" ? (
                    <MicrosoftIcon className="size-4" />
                  ) : (
                    <Icon name={methodIcon(m.method)} className="size-5" />
                  )}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-bold">{m.label}</div>
                  {m.detail && (
                    <div className="mt-0.5 truncate text-xs text-white/45">
                      {m.detail}
                    </div>
                  )}
                </div>
                <Chip tone={m.enabled ? "success" : "neutral"}>
                  {m.enabled ? "Enabled" : "Off"}
                </Chip>
              </div>
            ))}
          </div>
        )}
      </Card>
    </PortalShell>
  );
}
