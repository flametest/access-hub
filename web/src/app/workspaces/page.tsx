"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { StatusChip } from "@/components/chips";
import { Icon } from "@/components/icon";
import { Initials } from "@/components/initials";
import {
  EmptyCard,
  ErrorCard,
  SkeletonCards,
} from "@/components/page-state";
import { PortalShell } from "@/components/portal-shell";
import { useToast } from "@/components/toast";
import { useMe } from "@/hooks/use-me";
import { useRequireAuth } from "@/hooks/use-require-auth";
import { api, errMessage } from "@/lib/api";
import { setAppTokens } from "@/lib/tokens";
import type { Workspace } from "@/lib/types";

function roleSummary(ws: Workspace): string {
  return ws.roles.length > 0 ? ws.roles.join(" · ") : "No roles assigned";
}

export default function WorkspacesPage() {
  const router = useRouter();
  const toast = useToast();
  const { authed } = useRequireAuth();
  const { data: me } = useMe(authed);

  const workspacesQuery = useQuery({
    queryKey: ["workspaces"],
    queryFn: () => api.listWorkspaces(),
    enabled: authed,
  });

  const [mintingId, setMintingId] = useState<string | null>(null);

  async function openWorkspace(ws: Workspace) {
    setMintingId(ws.account_id);
    try {
      const tokens = await api.mintWorkspaceToken(ws.account_id);
      // App tokens are stored per account, separate from the portal tokens.
      setAppTokens(ws.account_id, tokens.access_token, tokens.refresh_token);
      router.push(`/workspace/${ws.account_id}`);
    } catch (err) {
      toast(
        errMessage(err, "Could not open this workspace. Please try again."),
        "error",
      );
    } finally {
      setMintingId(null);
    }
  }

  const workspaces = workspacesQuery.data;

  return (
    <PortalShell width="wide">
      <h1 className="text-2xl font-extrabold tracking-tight sm:text-3xl">
        Welcome back, {me?.nickname?.trim() || "there"}
      </h1>
      <p className="mt-1.5 text-sm text-white/55 sm:text-[15px]">
        Open a workspace, or manage the accounts linked to your Company ID.
      </p>

      <div className="mt-7">
        {workspacesQuery.isLoading && <SkeletonCards count={4} />}

        {workspacesQuery.isError && (
          <ErrorCard
            message={errMessage(
              workspacesQuery.error,
              "We couldn't load your workspaces.",
            )}
            onRetry={() => workspacesQuery.refetch()}
          />
        )}

        {workspaces && workspaces.length === 0 && (
          <EmptyCard
            title="No workspaces yet"
            description="Workspaces appear here once an admin invites you. Redeem an invite code to get started."
            action={
              <Button size="sm" onClick={() => router.push("/invite")}>
                <Icon name="ticket" className="size-4" /> Redeem an invite
              </Button>
            }
          />
        )}

        {workspaces && workspaces.length > 0 && (
          <div className="grid gap-4 sm:grid-cols-2">
            {workspaces.map((ws) => (
              <Card key={ws.account_id} className="flex items-center gap-4 p-4 sm:p-5">
                <Initials name={ws.app_name} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-bold">{ws.app_name}</span>
                    <StatusChip status={ws.status} />
                  </div>
                  <div className="mt-0.5 truncate text-[13px] text-white/55">
                    {roleSummary(ws)}
                  </div>
                </div>
                <Button
                  size="sm"
                  disabled={ws.status !== "active" || mintingId !== null}
                  loading={mintingId === ws.account_id}
                  onClick={() => openWorkspace(ws)}
                  title={
                    ws.status !== "active"
                      ? `This workspace is ${ws.status.replace(/_/g, " ")}`
                      : undefined
                  }
                >
                  Open
                </Button>
              </Card>
            ))}
          </div>
        )}
      </div>

      <div className="mt-7">
        <Button
          variant="secondary"
          onClick={() => router.push("/identity")}
        >
          <Icon name="id" className="size-4.5" /> Manage identity &amp; linked
          accounts
        </Button>
      </div>
    </PortalShell>
  );
}
