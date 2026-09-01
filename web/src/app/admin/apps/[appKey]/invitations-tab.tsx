"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/button";
import { StatusChip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Dialog } from "@/components/dialog";
import { Field } from "@/components/field";
import { CheckboxList } from "@/components/form-fields";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { AdminInvitation } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDate } from "@/lib/format";

/**
 * Invitations tab: email invites into this app with role sets and a TTL.
 * Revoking a pending invite is a two-step confirm.
 */
export function InvitationsTab({ appKey }: { appKey: string }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const invitationsQuery = useQuery({
    queryKey: ["admin", "invitations", appKey],
    queryFn: () => adminApi.listInvitations(appKey),
  });
  const rolesQuery = useQuery({
    queryKey: ["admin", "roles", appKey],
    queryFn: () => adminApi.listRoles(appKey),
  });
  const roles = rolesQuery.data ?? [];

  const [creating, setCreating] = useState(false);
  const [email, setEmail] = useState("");
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [ttlHours, setTtlHours] = useState("72");
  const [createError, setCreateError] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "invitations", appKey] });

  const createMutation = useMutation({
    mutationFn: () =>
      adminApi.createInvitation(appKey, {
        email: email.trim(),
        role_ids: roleIds,
        ttl_hours: Number(ttlHours) || undefined,
      }),
    onSuccess: () => {
      toast(`Invitation sent to ${email.trim()}.`, "success");
      setCreating(false);
      setEmail("");
      setRoleIds([]);
      setTtlHours("72");
      setCreateError(null);
      void invalidate();
    },
    onError: (err) =>
      setCreateError(errMessage(err, "Could not create the invitation.")),
  });

  const revokeMutation = useMutation({
    mutationFn: (invitation: AdminInvitation) =>
      adminApi.revokeInvitation(appKey, invitation.id),
    onSuccess: () => {
      toast("Invitation revoked.", "success");
      void invalidate();
    },
    onError: (err) =>
      toast(errMessage(err, "Could not revoke the invitation."), "error"),
  });

  if (isForbidden(invitationsQuery.error)) {
    return (
      <ForbiddenCard message="Invitations need admin:invitation:manage for this app." />
    );
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-white/55">
          Invited people get a one-time code by email; accepting provisions
          their workspace account with the chosen roles.
        </p>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Icon name="plus" className="size-4" /> Invite
        </Button>
      </div>

      <div className="mt-4">
        {invitationsQuery.isLoading && <TableSkeleton rows={4} />}
        {invitationsQuery.isError && (
          <ErrorCard
            message={errMessage(invitationsQuery.error, "We couldn't load invitations.")}
            onRetry={() => invitationsQuery.refetch()}
          />
        )}
        {invitationsQuery.data && invitationsQuery.data.length === 0 && (
          <EmptyCard
            icon="ticket"
            title="No invitations yet"
            description="Invite someone by email with a role set and an expiry window."
          />
        )}
        {invitationsQuery.data && invitationsQuery.data.length > 0 && (
          <Table
            columns={[
              { key: "email", header: "Email", className: "font-mono text-[13px]" },
              { key: "roles", header: "Roles", className: "min-w-[160px]" },
              { key: "status", header: "Status" },
              { key: "expires", header: "Expires" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={invitationsQuery.data}
            rowKey={(invitation) => invitation.id}
            cell={(invitation, column) => {
              switch (column.key) {
                case "email":
                  return invitation.email;
                case "roles":
                  return invitation.role_ids.length > 0 ? (
                    <span className="text-[13px] text-white/70">
                      {renderRoleNames(invitation, roles)}
                    </span>
                  ) : (
                    <span className="text-xs text-white/40">No roles</span>
                  );
                case "status":
                  return <StatusChip status={invitation.status} />;
                case "expires":
                  return (
                    <span className="text-white/55">
                      {formatDate(invitation.expires_at) ?? "—"}
                    </span>
                  );
                case "actions":
                  return invitation.status === "pending" ? (
                    <div className="flex justify-end">
                      <ConfirmButton
                        size="sm"
                        confirmLabel="Confirm revoke"
                        onConfirm={() => revokeMutation.mutateAsync(invitation)}
                      >
                        Revoke
                      </ConfirmButton>
                    </div>
                  ) : (
                    <span className="text-xs text-white/30">—</span>
                  );
                default:
                  return null;
              }
            }}
          />
        )}
      </div>

      {creating && (
        <Dialog
          title="Invite to this app"
          description="The invitee sets a password when accepting; pending invites can be revoked."
          onClose={() => setCreating(false)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setCreateError(null);
              if (!email.trim()) {
                setCreateError("Email is required.");
                return;
              }
              if (roleIds.length === 0) {
                setCreateError("Pick at least one role.");
                return;
              }
              createMutation.mutate();
            }}
          >
            <Field
              label="Email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="person@example.com"
              required
            />
            <CheckboxList
              label="Roles"
              options={roles.map((role) => ({
                value: role.id,
                label: role.name,
                detail: role.code,
              }))}
              selected={roleIds}
              onToggle={(value) =>
                setRoleIds((prev) =>
                  prev.includes(value)
                    ? prev.filter((id) => id !== value)
                    : [...prev, value],
                )
              }
              emptyHint="No roles in this app yet — create some in the Roles tab."
            />
            <Field
              label="Validity (hours)"
              type="number"
              min={1}
              max={720}
              value={ttlHours}
              onChange={(event) => setTtlHours(event.target.value)}
              hint="1–720 hours; empty uses the server default."
            />
            {createError && (
              <p role="alert" className="text-[13px] text-[#FF9C86]">
                {createError}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="ghost" onClick={() => setCreating(false)}>
                Cancel
              </Button>
              <Button type="submit" loading={createMutation.isPending}>
                Send invite
              </Button>
            </div>
          </form>
        </Dialog>
      )}
    </div>
  );
}

/** Invitation rows carry role ids; map them to names for display. */
function renderRoleNames(
  invitation: AdminInvitation,
  roles: { id: string; name: string }[],
): string {
  const byId = new Map(roles.map((role) => [role.id, role.name]));
  return invitation.role_ids
    .map((id) => byId.get(id) ?? id)
    .join(", ");
}
