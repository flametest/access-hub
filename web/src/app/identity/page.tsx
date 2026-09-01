"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip, StatusChip } from "@/components/chips";
import { Icon, ProviderIcon } from "@/components/icon";
import { Initials } from "@/components/initials";
import { EmptyCard, ErrorCard, SkeletonCard } from "@/components/page-state";
import { PortalShell } from "@/components/portal-shell";
import { useToast } from "@/components/toast";
import { useMe } from "@/hooks/use-me";
import { use2faStatus } from "@/hooks/use-2fa-status";
import { useRequireAuth } from "@/hooks/use-require-auth";
import { api, errMessage } from "@/lib/api";
import {
  SOCIAL_COMPLETE_PATH,
  SOCIAL_PROVIDERS,
  socialProviderLabel,
  startSocialAuth,
} from "@/lib/social";
import { getAccessToken } from "@/lib/tokens";
import { formatDate } from "@/lib/format";
import type { SocialIdentity, Workspace } from "@/lib/types";

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

/**
 * "Connected accounts": social providers linked to the Company ID
 * (GET /me/social-identities) with unlink (two-step confirm, DELETE) and
 * connect actions for the providers not linked yet (mode=link).
 */
function ConnectedAccountsCard() {
  const toast = useToast();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["social-identities"],
    queryFn: () => api.listSocialIdentities(),
  });
  const identities = query.data;

  const linkedProviders = new Set(
    identities?.map((identity) => identity.provider.toLowerCase()) ?? [],
  );
  const connectable = SOCIAL_PROVIDERS.filter(
    (provider) => !linkedProviders.has(provider.id),
  );

  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [unlinkingId, setUnlinkingId] = useState<string | null>(null);
  const [connecting, setConnecting] = useState<string | null>(null);

  async function onUnlink(identity: SocialIdentity) {
    if (unlinkingId) return;
    setUnlinkingId(identity.id);
    try {
      await api.deleteSocialIdentity(identity.id);
      toast(
        `${socialProviderLabel(identity.provider)} account unlinked.`,
        "success",
      );
      setConfirmingId(null);
      await queryClient.invalidateQueries({
        queryKey: ["social-identities"],
      });
    } catch (err) {
      // A 409 means this is the last sign-in method — errMessage surfaces the
      // backend's message for that.
      toast(errMessage(err, "We couldn't unlink this account."), "error");
    } finally {
      setUnlinkingId(null);
    }
  }

  async function onConnect(providerId: string) {
    if (connecting) return;
    setConnecting(providerId);
    try {
      // Whether a provider is configured is server-side knowledge — probe the
      // start endpoint through the same-origin rewrite first so a missing
      // provider surfaces as a toast instead of a raw backend error page.
      const params = new URLSearchParams({
        redirect: SOCIAL_COMPLETE_PATH,
        mode: "link",
      });
      const token = getAccessToken();
      const res = await fetch(`/api/v1/auth/social/${providerId}/start?${params}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        redirect: "manual",
      });
      const redirected =
        res.type === "opaqueredirect" ||
        (res.status >= 300 && res.status < 400);
      if (!redirected && !res.ok) {
        let message = "";
        try {
          const body = (await res.json()) as Record<string, unknown>;
          if (typeof body.message === "string") message = body.message;
        } catch {
          // Non-JSON error body — use the fallback copy below.
        }
        toast(
          message ||
            `We couldn't start ${socialProviderLabel(providerId)} linking — it may not be available yet.`,
          "error",
        );
        setConnecting(null);
        return;
      }
      // Configured: leave the portal for the provider's consent screen. The
      // callback returns to /social/complete?linked=1 (or ?error=…).
      startSocialAuth(providerId, SOCIAL_COMPLETE_PATH, "link");
    } catch {
      toast(
        "Can't reach the access-hub server. Check that the backend is running on :8080.",
        "error",
      );
      setConnecting(null);
    }
  }

  return (
    <Card className="mt-4 p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-bold">Connected accounts</h2>
          <p className="mt-0.5 text-[13px] text-white/50">
            Social providers linked to your Company ID — another way to sign in.
          </p>
        </div>
      </div>

      <div className="mt-4">
        {query.isLoading && (
          <div
            className="h-[66px] animate-pulse rounded-xl border border-white/10 bg-white/[0.04]"
            aria-hidden="true"
          />
        )}

        {query.isError && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#FF5630]/30 bg-[#FF5630]/10 px-4 py-3 text-sm text-[#FF9C86]">
            <span>
              {errMessage(
                query.error,
                "We couldn't load your connected accounts.",
              )}
            </span>
            <Button size="sm" variant="secondary" onClick={() => query.refetch()}>
              Try again
            </Button>
          </div>
        )}

        {identities && identities.length === 0 && (
          <p className="rounded-xl border border-white/10 px-4 py-3.5 text-sm text-white/55">
            No social accounts connected yet — connect one below to sign in
            with a single click.
          </p>
        )}

        {identities && identities.length > 0 && (
          <div className="-mx-2 divide-y divide-white/[0.06]">
            {identities.map((identity) => (
              <div
                key={identity.id}
                className="flex flex-wrap items-center gap-3.5 rounded-xl px-2 py-3.5"
              >
                <span className="grid size-10 flex-none place-items-center rounded-lg bg-white/[0.07] text-white/70">
                  <ProviderIcon provider={identity.provider} className="size-5" />
                </span>
                <div className="min-w-0 flex-1 basis-44">
                  <div className="truncate text-sm font-bold">
                    {socialProviderLabel(identity.provider)}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-white/45">
                    {[
                      identity.email || identity.display_name,
                      formatDate(identity.created_at) &&
                        `linked ${formatDate(identity.created_at)}`,
                    ]
                      .filter(Boolean)
                      .join(" · ") || "No email shared"}
                  </div>
                </div>
                <Chip tone={identity.email_verified ? "success" : "neutral"}>
                  {identity.email_verified ? (
                    <>
                      <Icon name="check-circle" className="size-3.5" /> Verified
                    </>
                  ) : (
                    "Unverified"
                  )}
                </Chip>
                {confirmingId === identity.id ? (
                  <div className="flex flex-none gap-2">
                    <Button
                      size="sm"
                      variant="danger"
                      loading={unlinkingId === identity.id}
                      onClick={() => void onUnlink(identity)}
                    >
                      Confirm unlink
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={unlinkingId !== null}
                      onClick={() => setConfirmingId(null)}
                    >
                      Cancel
                    </Button>
                  </div>
                ) : (
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={unlinkingId !== null}
                    onClick={() => setConfirmingId(identity.id)}
                  >
                    Unlink
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {query.isSuccess && connectable.length > 0 && (
        <div className="mt-4 border-t border-white/[0.06] pt-4">
          <p className="mb-3 text-xs text-white/45">
            Add another way to sign in:
          </p>
          <div className="flex flex-wrap gap-2.5">
            {connectable.map((provider) => (
              <Button
                key={provider.id}
                size="sm"
                variant="secondary"
                loading={connecting === provider.id}
                disabled={connecting !== null && connecting !== provider.id}
                onClick={() => void onConnect(provider.id)}
              >
                <ProviderIcon
                  provider={provider.id}
                  className="size-3.5 flex-none"
                />
                Connect {provider.label}
              </Button>
            ))}
          </div>
        </div>
      )}
    </Card>
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

      {/* Connected social accounts */}
      <ConnectedAccountsCard />

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
