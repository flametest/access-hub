"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { AppSecretDialog } from "@/components/admin/app-secret-dialog";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Icon } from "@/components/icon";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { AdminApp } from "@/lib/admin/types";
import { errMessage } from "@/lib/api";

/**
 * Integration tab: the per-app internal-API secret (header X-App-Key) used
 * to self-declare resources against the cluster-internal batch endpoint
 * (PUT /internal/v1/apps/{appKey}/resources/batch). The plaintext is never
 * retrievable — rotate issues a fresh one, shown exactly once.
 */
export function IntegrationTab({ app }: { app?: AdminApp }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [revealed, setRevealed] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const rotateMutation = useMutation({
    mutationFn: () => adminApi.rotateAppSecret(app!.key),
    onSuccess: (result) => {
      setError(null);
      setRevealed(result.secret ?? "");
      void queryClient.invalidateQueries({ queryKey: ["admin", "apps"] });
    },
    onError: (err) => setError(errMessage(err, "Could not rotate the secret.")),
  });

  // Platform apps (org_key empty) never hold an internal secret.
  const isPlatform = Boolean(app && !app.org_key);
  const configured = app?.secret_configured === true;

  return (
    <div className="max-w-3xl space-y-4">
      <Card className="p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Icon name="shield" className="size-4 text-ah-accent" />
            <h2 className="font-bold">Internal API secret</h2>
            {isPlatform ? (
              <Chip tone="neutral">platform app</Chip>
            ) : configured ? (
              <Chip tone="success">configured</Chip>
            ) : (
              <Chip tone="neutral">not configured</Chip>
            )}
          </div>
          {!isPlatform && app && (
            <ConfirmButton
              size="sm"
              confirmLabel={configured ? "Confirm rotate" : "Confirm issue"}
              confirmVariant="primary"
              onConfirm={() => rotateMutation.mutate()}
            >
              <Icon name="refresh" className="size-4" />
              {configured ? "Rotate secret" : "Issue secret"}
            </ConfirmButton>
          )}
        </div>

        <p className="mt-3 text-sm text-white/55">
          Authenticates this app against the cluster-internal API to
          self-declare its resource manifest on deploy. The secret is stored
          hashed — the plaintext is shown exactly once at issue/rotate, then
          never again. Rotating invalidates the previous secret immediately.
        </p>

        {!isPlatform && (
          <pre className="mt-4 overflow-x-auto rounded-lg border border-white/10 bg-black/30 p-3.5 font-mono text-[12.5px] leading-6 text-white/75">
            {`PUT /internal/v1/apps/${app?.key ?? "{appKey}"}/resources/batch?mode=replace\nX-App-Key: ahk_...`}
          </pre>
        )}

        {isPlatform && (
          <p className="mt-3 text-[13px] text-white/45">
            Platform apps are hub-internal (e.g. the admin console) and don&apos;t
            participate in the internal resource-registration API.
          </p>
        )}

        {error && (
          <p role="alert" className="mt-3 text-[13px] text-[#FF9C86]">
            {error}
          </p>
        )}
      </Card>

      <Card className="p-5">
        <h2 className="font-bold">Deploy-time registration</h2>
        <p className="mt-3 text-sm text-white/55">
          Keep the resource manifest in the app&apos;s own repository and sync it
          from the deploy pipeline (idempotent by code;{" "}
          <code className="font-mono text-[12.5px] text-white/75">
            ?mode=replace
          </code>{" "}
          disables resources absent from the payload). Keep{" "}
          <code className="font-mono text-[12.5px] text-white/75">/internal/*</code>{" "}
          unrouted by the public ingress — network isolation is the first line
          of defense, the per-app secret the second.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              void navigator.clipboard?.writeText(
                `PUT /internal/v1/apps/${app?.key ?? "{appKey}"}/resources/batch`,
              );
              toast("Endpoint URL copied.", "success");
            }}
          >
            <Icon name="copy" className="size-3.5" /> Copy endpoint
          </Button>
        </div>
      </Card>

      {revealed !== null && (
        <AppSecretDialog
          appKey={app?.key ?? ""}
          secret={revealed}
          onClose={() => setRevealed(null)}
        />
      )}
    </div>
  );
}
