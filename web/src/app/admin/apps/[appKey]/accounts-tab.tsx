"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { StatusChip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Dialog } from "@/components/dialog";
import { Drawer } from "@/components/drawer";
import { Field } from "@/components/field";
import { CheckboxList, SelectField } from "@/components/form-fields";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { AdminAccount, Grant } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

/**
 * Accounts tab: per-app workspace accounts. Provision (activation email when
 * no password given), enable/disable, reset password, transfer to another
 * identity, set roles, and a per-account direct-grants drawer.
 */
export function AccountsTab({ appKey }: { appKey: string }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const PAGE_SIZE = 20;
  const accountsQuery = useQuery({
    queryKey: ["admin", "accounts", appKey, page],
    queryFn: () => adminApi.listAccounts(appKey, "", "", page, PAGE_SIZE),
  });
  const rolesQuery = useQuery({
    queryKey: ["admin", "roles", appKey],
    queryFn: () => adminApi.listRoles(appKey),
  });
  const roles = rolesQuery.data ?? [];

  const invalidate = () =>
    setPage(1);
    queryClient.invalidateQueries({ queryKey: ["admin", "accounts", appKey] });

  // Provision dialog
  const [provisioning, setProvisioning] = useState(false);
  const [form, setForm] = useState({
    email: "",
    username: "",
    display_name: "",
    password: "",
  });
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [provisionError, setProvisionError] = useState<string | null>(null);

  // Row-action dialogs: exactly one target account at a time.
  const [resetTarget, setResetTarget] = useState<AdminAccount | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [resetError, setResetError] = useState<string | null>(null);

  const [transferTarget, setTransferTarget] = useState<AdminAccount | null>(null);
  const [identityEmail, setIdentityEmail] = useState("");
  const [transferError, setTransferError] = useState<string | null>(null);

  const [rolesTarget, setRolesTarget] = useState<AdminAccount | null>(null);
  const [targetRoleIds, setTargetRoleIds] = useState<string[]>([]);
  const [rolesError, setRolesError] = useState<string | null>(null);

  const [grantsTarget, setGrantsTarget] = useState<AdminAccount | null>(null);

  const provisionMutation = useMutation({
    mutationFn: () =>
      adminApi.provisionAccount(appKey, {
        email: form.email.trim(),
        username: form.username.trim() || undefined,
        display_name: form.display_name.trim() || undefined,
        role_ids: roleIds,
        password: form.password || undefined,
      }),
    onSuccess: (resp) => {
      toast(
        resp.activation_sent
          ? "Account provisioned — an activation email is on its way."
          : "Account provisioned and active.",
        "success",
      );
      setProvisioning(false);
      setForm({ email: "", username: "", display_name: "", password: "" });
      setRoleIds([]);
      setProvisionError(null);
      void invalidate();
    },
    onError: (err) =>
      setProvisionError(errMessage(err, "Could not provision the account.")),
  });

  const statusMutation = useMutation({
    mutationFn: ({ account, status }: { account: AdminAccount; status: string }) =>
      adminApi.updateAccount(appKey, account.id, { status }),
    onSuccess: (_data, vars) => {
      toast(
        vars.status === "disabled"
          ? "Account disabled."
          : "Account enabled.",
        "success",
      );
      void invalidate();
    },
    onError: (err) => toast(errMessage(err, "Could not update the account."), "error"),
  });

  const resetMutation = useMutation({
    mutationFn: () =>
      adminApi.resetAccountPassword(appKey, resetTarget!.id, newPassword),
    onSuccess: () => {
      toast("Password reset — their sessions were signed out.", "success");
      setResetTarget(null);
      setNewPassword("");
      void invalidate();
    },
    onError: (err) => setResetError(errMessage(err, "Could not reset the password.")),
  });

  const transferMutation = useMutation({
    mutationFn: () =>
      adminApi.transferAccount(appKey, transferTarget!.id, identityEmail.trim()),
    onSuccess: () => {
      toast("Account transferred to the new identity.", "success");
      setTransferTarget(null);
      setIdentityEmail("");
      void invalidate();
    },
    onError: (err) => setTransferError(errMessage(err, "Could not transfer the account.")),
  });

  const rolesMutation = useMutation({
    mutationFn: () =>
      adminApi.setAccountRoles(appKey, rolesTarget!.id, targetRoleIds),
    onSuccess: (updated) => {
      toast(
        `${updated.length} role${updated.length === 1 ? "" : "s"} saved.`,
        "success",
      );
      setRolesTarget(null);
      void invalidate();
    },
    onError: (err) => setRolesError(errMessage(err, "Could not set the roles.")),
  });

  if (isForbidden(accountsQuery.error)) {
    return <ForbiddenCard message="Account management needs admin:account:manage for this app." />;
  }

  function openRolesDialog(account: AdminAccount) {
    setRolesTarget(account);
    // Account rows carry role summaries (code+name); the API needs role ids —
    // map through the app's role list, skipping codes that no longer exist.
    const idByCode = new Map(roles.map((role) => [role.code, role.id]));
    setTargetRoleIds(
      account.roles
        .map((role) => idByCode.get(role.code))
        .filter((id): id is string => Boolean(id)),
    );
    setRolesError(null);
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-white/55">
          Workspace accounts are per-app logins bound to a primary identity.
          Each has an independent password, roles and optional direct grants.
        </p>
        <Button size="sm" onClick={() => setProvisioning(true)}>
          <Icon name="plus" className="size-4" /> Provision account
        </Button>
      </div>

      <div className="mt-4">
        {accountsQuery.isLoading && <TableSkeleton rows={5} />}
        {accountsQuery.isError && (
          <ErrorCard
            message={errMessage(accountsQuery.error, "We couldn't load accounts.")}
            onRetry={() => accountsQuery.refetch()}
          />
        )}
        {accountsQuery.data && accountsQuery.data.items.length === 0 && (
          <EmptyCard
            icon="users"
            title="No accounts yet"
            description="Provision the first account (an activation email covers password setup), or invite by email."
          />
        )}
        {accountsQuery.data && accountsQuery.data.items.length > 0 && (
          <Table
            columns={[
              { key: "email", header: "Email", className: "font-mono text-[13px]" },
              { key: "name", header: "Display name" },
              { key: "roles", header: "Roles", className: "min-w-[160px]" },
              { key: "status", header: "Status" },
              { key: "last_login", header: "Last login" },
              { key: "actions", header: "", className: "text-right min-w-[340px]" },
            ]}
            rows={accountsQuery.data.items}
            rowKey={(account) => account.id}
            cell={(account, column) => {
              switch (column.key) {
                case "email":
                  return account.email;
                case "name":
                  return <span className="font-bold">{account.display_name}</span>;
                case "roles":
                  return account.roles.length > 0 ? (
                    <span className="text-[13px] text-white/70">
                      {account.roles.map((role) => role.name).join(", ")}
                    </span>
                  ) : (
                    <span className="text-xs text-white/40">No roles</span>
                  );
                case "status":
                  return <StatusChip status={account.status} />;
                case "last_login":
                  return (
                    <span className="text-white/55">
                      {formatDateTime(account.last_login_at) ?? "Never"}
                    </span>
                  );
                case "actions":
                  return (
                    <RowActions
                      account={account}
                      busy={statusMutation.isPending}
                      onToggleStatus={(status) =>
                        statusMutation.mutate({ account, status })
                      }
                      onReset={() => {
                        setResetTarget(account);
                        setNewPassword("");
                        setResetError(null);
                      }}
                      onTransfer={() => {
                        setTransferTarget(account);
                        setIdentityEmail("");
                        setTransferError(null);
                      }}
                      onRoles={() => openRolesDialog(account)}
                      onGrants={() => setGrantsTarget(account)}
                    />
                  );
                default:
                  return null;
              }
            }}
          />
        )}
        {accountsQuery.data && accountsQuery.data.total > PAGE_SIZE && (
          <div className="mt-3 flex items-center justify-between text-[13px] text-white/60">
            <span>
              page {page} of {Math.max(1, Math.ceil(accountsQuery.data.total / PAGE_SIZE))} ·{" "}
              {accountsQuery.data.total} accounts
            </span>
            <div className="flex gap-2">
              <Button
                variant="ghost"
                size="sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={page >= Math.ceil(accountsQuery.data.total / PAGE_SIZE)}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Provision dialog */}
      {provisioning && (
        <Dialog
          wide
          title="Provision account"
          description="Creates a per-app account; its primary identity is auto-created when the email is new."
          onClose={() => setProvisioning(false)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setProvisionError(null);
              if (!form.email.trim()) {
                setProvisionError("Email is required.");
                return;
              }
              provisionMutation.mutate();
            }}
          >
            <Field
              label="Email"
              type="email"
              value={form.email}
              onChange={(event) => setForm({ ...form, email: event.target.value })}
              placeholder="person@example.com"
              hint="Unique per app. This is the workspace login, not necessarily the identity email."
              required
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label="Username (optional)"
                value={form.username}
                onChange={(event) => setForm({ ...form, username: event.target.value })}
                placeholder="jdoe"
              />
              <Field
                label="Display name (optional)"
                value={form.display_name}
                onChange={(event) => setForm({ ...form, display_name: event.target.value })}
              />
            </div>
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
              label="Initial password (optional)"
              type="password"
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
              hint="Leave empty to start the account pending_activation and send an activation email instead."
              autoComplete="new-password"
            />
            {provisionError && (
              <p role="alert" className="text-[13px] text-[#FF9C86]">
                {provisionError}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="ghost" onClick={() => setProvisioning(false)}>
                Cancel
              </Button>
              <Button type="submit" loading={provisionMutation.isPending}>
                Provision
              </Button>
            </div>
          </form>
        </Dialog>
      )}

      {/* Reset password dialog */}
      {resetTarget && (
        <Dialog
          title={`Reset password · ${resetTarget.email}`}
          description="The new password signs out the account's active sessions."
          onClose={() => setResetTarget(null)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setResetError(null);
              if (newPassword.length < 8) {
                setResetError("Password must be at least 8 characters.");
                return;
              }
              resetMutation.mutate();
            }}
          >
            <Field
              label="New password"
              type="password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              autoComplete="new-password"
              required
            />
            {resetError && (
              <p role="alert" className="text-[13px] text-[#FF9C86]">
                {resetError}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="ghost" onClick={() => setResetTarget(null)}>
                Cancel
              </Button>
              <Button type="submit" loading={resetMutation.isPending}>
                Reset password
              </Button>
            </div>
          </form>
        </Dialog>
      )}

      {/* Transfer dialog */}
      {transferTarget && (
        <Dialog
          title={`Transfer · ${transferTarget.email}`}
          description="Rebinds the account to another primary identity (e.g. offboarding handover)."
          onClose={() => setTransferTarget(null)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setTransferError(null);
              if (!identityEmail.trim()) {
                setTransferError("Identity email is required.");
                return;
              }
              transferMutation.mutate();
            }}
          >
            <Field
              label="New identity email"
              type="email"
              value={identityEmail}
              onChange={(event) => setIdentityEmail(event.target.value)}
              placeholder="successor@example.com"
              hint="The primary identity email to attach this workspace account to."
              required
            />
            {transferError && (
              <p role="alert" className="text-[13px] text-[#FF9C86]">
                {transferError}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="ghost" onClick={() => setTransferTarget(null)}>
                Cancel
              </Button>
              <Button type="submit" loading={transferMutation.isPending}>
                Transfer
              </Button>
            </div>
          </form>
        </Dialog>
      )}

      {/* Set roles dialog */}
      {rolesTarget && (
        <Dialog
          title={`Set roles · ${rolesTarget.email}`}
          description="An empty list revokes every role of this account."
          onClose={() => setRolesTarget(null)}
        >
          <div className="space-y-4">
            <CheckboxList
              label="Roles"
              maxH="max-h-64"
              options={roles.map((role) => ({
                value: role.id,
                label: role.name,
                detail: role.code,
              }))}
              selected={targetRoleIds}
              onToggle={(value) =>
                setTargetRoleIds((prev) =>
                  prev.includes(value)
                    ? prev.filter((id) => id !== value)
                    : [...prev, value],
                )
              }
              emptyHint="No roles in this app yet — create some in the Roles tab."
            />
            {rolesError && (
              <p role="alert" className="text-[13px] text-[#FF9C86]">
                {rolesError}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setRolesTarget(null)}>
                Cancel
              </Button>
              <Button
                loading={rolesMutation.isPending}
                onClick={() => {
                  setRolesError(null);
                  rolesMutation.mutate();
                }}
              >
                Save roles
              </Button>
            </div>
          </div>
        </Dialog>
      )}

      {/* Grants drawer */}
      {grantsTarget && (
        <GrantsDrawer
          appKey={appKey}
          account={grantsTarget}
          onClose={() => setGrantsTarget(null)}
        />
      )}
    </div>
  );
}

function RowActions({
  account,
  busy,
  onToggleStatus,
  onReset,
  onTransfer,
  onRoles,
  onGrants,
}: {
  account: AdminAccount;
  busy: boolean;
  onToggleStatus: (status: string) => void;
  onReset: () => void;
  onTransfer: () => void;
  onRoles: () => void;
  onGrants: () => void;
}) {
  const disabled = account.status === "disabled";
  return (
    <div className="flex flex-wrap justify-end gap-1.5">
      <ConfirmButton
        size="sm"
        confirmLabel={disabled ? "Confirm enable" : "Confirm disable"}
        disabled={busy}
        onConfirm={() => onToggleStatus(disabled ? "active" : "disabled")}
      >
        {disabled ? "Enable" : "Disable"}
      </ConfirmButton>
      <Button size="sm" variant="ghost" onClick={onReset}>
        Reset pw
      </Button>
      <Button size="sm" variant="ghost" onClick={onTransfer}>
        Transfer
      </Button>
      <Button size="sm" variant="ghost" onClick={onRoles}>
        Roles
      </Button>
      <Button size="sm" variant="secondary" onClick={onGrants}>
        <Icon name="key" className="size-4" /> Grants
      </Button>
    </div>
  );
}

function GrantsDrawer({
  appKey,
  account,
  onClose,
}: {
  appKey: string;
  account: AdminAccount;
  onClose: () => void;
}) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const grantsQuery = useQuery({
    queryKey: ["admin", "grants", appKey, account.id],
    queryFn: () => adminApi.listGrants(appKey, account.id),
  });
  const resourcesQuery = useQuery({
    queryKey: ["admin", "resources", appKey],
    queryFn: () => adminApi.listResourceRows(appKey),
  });

  const [resourceId, setResourceId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [effect, setEffect] = useState("allow");
  const [addError, setAddError] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({
      queryKey: ["admin", "grants", appKey, account.id],
    });

  const addMutation = useMutation({
    mutationFn: () => {
      // datetime-local → RFC3339 (undefined stays a permanent grant).
      const expires = expiresAt
        ? new Date(expiresAt).toISOString()
        : undefined;
      return adminApi.addGrant(appKey, account.id, {
        resource_id: resourceId,
        expires_at: expires,
        effect,
      });
    },
    onSuccess: () => {
      toast("Grant added.", "success");
      setResourceId("");
      setExpiresAt("");
      setEffect("allow");
      setAddError(null);
      void invalidate();
    },
    onError: (err) => setAddError(errMessage(err, "Could not add the grant.")),
  });

  const removeMutation = useMutation({
    mutationFn: (grantId: string) => adminApi.removeGrant(appKey, account.id, grantId),
    onSuccess: () => {
      toast("Grant removed.", "success");
      void invalidate();
    },
    onError: (err) => toast(errMessage(err, "Could not remove the grant."), "error"),
  });

  const resourceOptions = (resourcesQuery.data ?? []).map((row) => ({
    value: row.id,
    label: row.name,
    detail: `${row.type} · ${row.code}`,
  }));

  return (
    <Drawer
      title={`Direct grants · ${account.email}`}
      description="Per-account permission codes layered on top of roles."
      onClose={onClose}
    >
      <Card className="p-4">
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            setAddError(null);
            if (!resourceId) {
              setAddError("Pick a resource to grant.");
              return;
            }
            addMutation.mutate();
          }}
        >
          <p className="text-[13px] font-semibold text-white/80">Add grant</p>
          <SelectField
            label="Resource"
            value={resourceId}
            onChange={(event) => setResourceId(event.target.value)}
          >
            <option value="">— pick a resource —</option>
            {resourceOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label} ({option.detail})
              </option>
            ))}
          </SelectField>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label="Expires at (optional)"
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
              hint="Empty = permanent."
            />
            <SelectField
              label="Effect"
              value={effect}
              onChange={(event) => setEffect(event.target.value)}
              hint="Deny takes precedence per the priority ladder (grant deny 20)."
            >
              <option value="allow">allow</option>
              <option value="deny">deny</option>
            </SelectField>
          </div>
          {addError && (
            <p role="alert" className="text-[13px] text-[#FF9C86]">
              {addError}
            </p>
          )}
          <div className="flex justify-end">
            <Button type="submit" size="sm" loading={addMutation.isPending}>
              <Icon name="plus" className="size-4" /> Add grant
            </Button>
          </div>
        </form>
      </Card>

      <div className="mt-4">
        {grantsQuery.isLoading && <TableSkeleton rows={3} />}
        {grantsQuery.isError && (
          <ErrorCard
            message={errMessage(grantsQuery.error, "We couldn't load grants.")}
            onRetry={() => grantsQuery.refetch()}
          />
        )}
        {grantsQuery.data && grantsQuery.data.length === 0 && (
          <p className="rounded-xl border border-white/10 px-4 py-3.5 text-sm text-white/55">
            No direct grants — this account&apos;s access comes from its roles.
          </p>
        )}
        {grantsQuery.data && grantsQuery.data.length > 0 && (
          <Table
            columns={[
              { key: "resource", header: "Resource" },
              { key: "expires", header: "Expires" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={grantsQuery.data}
            rowKey={(grant: Grant) => grant.id}
            cell={(grant, column) => {
              switch (column.key) {
                case "resource":
                  return (
                    <div className="min-w-0">
                      <div className="truncate font-bold">
                        {grant.resource_name || grant.resource_code}
                      </div>
                      <div className="truncate font-mono text-xs text-white/45">
                        {grant.resource_code} · {grant.resource_type}
                      </div>
                    </div>
                  );
                case "expires":
                  return (
                    <span className="text-white/55">
                      {formatDateTime(grant.expires_at) ?? "Permanent"}
                    </span>
                  );
                case "actions":
                  return (
                    <div className="flex justify-end">
                      <ConfirmButton
                        size="sm"
                        confirmLabel="Confirm remove"
                        onConfirm={() => removeMutation.mutateAsync(grant.id)}
                      >
                        Remove
                      </ConfirmButton>
                    </div>
                  );
                default:
                  return null;
              }
            }}
          />
        )}
      </div>
    </Drawer>
  );
}
