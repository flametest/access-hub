"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip, StatusChip } from "@/components/chips";
import { Icon } from "@/components/icon";
import { Initials } from "@/components/initials";
import { EmptyCard, ErrorCard, SkeletonCard } from "@/components/page-state";
import { PortalShell } from "@/components/portal-shell";
import { useMe } from "@/hooks/use-me";
import { use2faStatus } from "@/hooks/use-2fa-status";
import { useRequireAuth } from "@/hooks/use-require-auth";
import { api, errMessage } from "@/lib/api";
import type { Workspace } from "@/lib/types";

function LinkedAccountRow({ ws }: { ws: Workspace }) {
  return (
    <Link
      href={`/workspace/${ws.account_id}`}
      className="flex items-center gap-4 px-4 py-4 transition-colors hover:bg-white/[0.04] sm:px-5"
    >
      <Initials name={ws.app_name} />
      <div className="min-w-0 flex-1">
        <div className="truncate font-bold">{ws.app_name}</div>
        <div className="mt-0.5 truncate text-[13px] text-white/55">
          {ws.email || ws.display_name || "No workspace email"}
        </div>
      </div>
      <div className="flex flex-col items-end gap-1.5">
        <StatusChip status={ws.status} />
        <span className="max-w-[140px] truncate text-xs text-white/45">
          {ws.roles.length > 0 ? ws.roles.join(", ") : "No roles"}
        </span>
      </div>
      <Icon name="chevron-right" className="size-4 flex-none text-white/30" />
    </Link>
  );
}

export default function IdentityPage() {
  const router = useRouter();
  const { authed } = useRequireAuth();
  const meQuery = useMe(authed);
  const me = meQuery.data;

  const twoFaQuery = use2faStatus(authed);
  const status = twoFaQuery.data;
  // GET /me/2fa/status is authoritative; GET /me's two_fa_enabled is the fallback.
  const twoFaEnabled = status ? status.enabled : (me?.two_fa_enabled ?? false);
  const twoFaResolved = Boolean(status) || Boolean(me);

  const workspacesQuery = useQuery({
    queryKey: ["workspaces"],
    queryFn: () => api.listWorkspaces(),
    enabled: authed,
  });
  const workspaces = workspacesQuery.data;

  return (
    <PortalShell width="normal">
      {/* Primary identity */}
      {meQuery.isLoading && <SkeletonCard />}
      {meQuery.isError && (
        <ErrorCard
          message={errMessage(meQuery.error, "We couldn't load your identity.")}
          onRetry={() => meQuery.refetch()}
        />
      )}
      {me && (
        <>
          <Card className="flex flex-wrap items-center gap-5 p-5 sm:p-6">
          <Initials name={me.nickname || me.email || "?"} size="xl" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
                {me.nickname}
              </h1>
              <Chip tone="accent">Primary identity</Chip>
            </div>
            <p className="mt-1 truncate text-sm text-white/55">{me.email}</p>
          </div>
          {twoFaResolved ? (
            twoFaEnabled ? (
              <Chip tone="success">
                <Icon name="shield" className="size-3.5" /> 2FA enabled
              </Chip>
            ) : (
              <Chip tone="neutral">
                <Icon name="shield" className="size-3.5" /> 2FA off
              </Chip>
            )
          ) : (
            <Chip tone="neutral">
              <Icon name="shield" className="size-3.5" /> 2FA
            </Chip>
          )}
        </Card>

        {/* Two-factor authentication */}
        {twoFaResolved && (
          <Card className="mt-4 flex flex-wrap items-center gap-4 p-5 sm:p-6">
            <span
              className={`grid size-11 flex-none place-items-center rounded-xl ${
                twoFaEnabled
                  ? "bg-[#22C55E]/15 text-[#7CE49F]"
                  : "bg-ah-accent/15 text-ah-accent"
              }`}
            >
              <Icon name="shield" className="size-5.5" />
            </span>
            <div className="min-w-0 flex-1 basis-56">
              <h2 className="font-bold">Two-factor authentication</h2>
              <p className="mt-0.5 text-[13px] text-white/55">
                {twoFaEnabled
                  ? "Portal sign-ins require a one-time code from your authenticator app."
                  : "Add a one-time code on top of your password so a leaked password can't sign in as you."}
              </p>
            </div>
            <Button
              size="sm"
              variant={twoFaEnabled ? "secondary" : "primary"}
              onClick={() => router.push("/identity/2fa")}
            >
              {twoFaEnabled ? "Manage" : "Enable"}
            </Button>
          </Card>
        )}
        </>
      )}

      {/* Linked accounts */}
      <div className="mt-9 mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold sm:text-xl">Linked accounts</h2>
          <p className="mt-0.5 text-[13px] text-white/50">
            {workspaces
              ? `${workspaces.length} workspace ${
                  workspaces.length === 1 ? "account" : "accounts"
                } connected to this identity.`
              : "Workspace accounts connected to this identity."}
          </p>
        </div>
        <Button size="sm" onClick={() => router.push("/invite")}>
          <Icon name="plus" className="size-4" /> Link an account
        </Button>
      </div>
      <p className="mb-4 text-xs text-white/40">
        Workspace accounts are linked automatically when you accept an invite.
      </p>

      {workspacesQuery.isLoading && <SkeletonCard />}

      {workspacesQuery.isError && (
        <ErrorCard
          message={errMessage(
            workspacesQuery.error,
            "We couldn't load your linked accounts.",
          )}
          onRetry={() => workspacesQuery.refetch()}
        />
      )}

      {workspaces && workspaces.length === 0 && (
        <EmptyCard
          title="No linked accounts yet"
          description="Accept an invite from a workspace admin and the account will be linked here automatically."
          action={
            <Button size="sm" onClick={() => router.push("/invite")}>
              <Icon name="ticket" className="size-4" /> Redeem an invite
            </Button>
          }
        />
      )}

      {workspaces && workspaces.length > 0 && (
        <Card className="divide-y divide-white/[0.08] overflow-hidden p-0">
          {workspaces.map((ws) => (
            <LinkedAccountRow key={ws.account_id} ws={ws} />
          ))}
        </Card>
      )}
    </PortalShell>
  );
}
