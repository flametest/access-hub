"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Dialog } from "@/components/dialog";
import { Drawer } from "@/components/drawer";
import { Field } from "@/components/field";
import { SelectField } from "@/components/form-fields";
import { EffectChip, ResourceTypeChip } from "@/components/admin/chips";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { AdminRole, ResourceRow } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDate } from "@/lib/format";

type Effect = "allow" | "deny";

/**
 * Roles tab: CRUD (built_in roles are protected server-side) plus the
 * per-role "bind resources" drawer — resource tree grouped by type with
 * checkboxes and a per-item allow/deny effect, submitted as
 * `items: [{resource_id, effect}]` (M6).
 */
export function RolesTab({ appKey }: { appKey: string }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const rolesQuery = useQuery({
    queryKey: ["admin", "roles", appKey],
    queryFn: () => adminApi.listRoles(appKey),
  });

  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ code: "", name: "", scope: "app" });
  const [createError, setCreateError] = useState<string | null>(null);

  const [editing, setEditing] = useState<AdminRole | null>(null);
  const [editName, setEditName] = useState("");
  const [editError, setEditError] = useState<string | null>(null);

  const [binding, setBinding] = useState<AdminRole | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "roles", appKey] });

  const createMutation = useMutation({
    mutationFn: () =>
      adminApi.createRole(appKey, {
        code: form.code.trim(),
        name: form.name.trim(),
        scope: form.scope,
      }),
    onSuccess: (role) => {
      toast(`Role "${role.name}" created.`, "success");
      setCreating(false);
      setForm({ code: "", name: "", scope: "app" });
      setCreateError(null);
      void invalidate();
    },
    onError: (err) => setCreateError(errMessage(err, "Could not create the role.")),
  });

  const updateMutation = useMutation({
    mutationFn: () => adminApi.updateRole(appKey, editing!.id, { name: editName.trim() }),
    onSuccess: () => {
      toast("Role saved.", "success");
      setEditing(null);
      void invalidate();
    },
    onError: (err) => setEditError(errMessage(err, "Could not save the role.")),
  });

  const deleteMutation = useMutation({
    mutationFn: (role: AdminRole) => adminApi.deleteRole(appKey, role.id),
    onSuccess: () => {
      toast("Role deleted.", "success");
      void invalidate();
    },
    onError: (err) => toast(errMessage(err, "Could not delete the role."), "error"),
  });

  if (isForbidden(rolesQuery.error)) {
    return <ForbiddenCard message="Role management needs admin:role:manage for this app." />;
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-white/55">
          Roles group permission codes; accounts hold roles, plus optional
          direct grants. Built-in roles (super_admin / org_admin) are
          platform-managed.
        </p>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Icon name="plus" className="size-4" /> New role
        </Button>
      </div>

      <div className="mt-4">
        {rolesQuery.isLoading && <TableSkeleton rows={4} />}
        {rolesQuery.isError && (
          <ErrorCard
            message={errMessage(rolesQuery.error, "We couldn't load roles.")}
            onRetry={() => rolesQuery.refetch()}
          />
        )}
        {rolesQuery.data && rolesQuery.data.length === 0 && (
          <EmptyCard
            icon="key"
            title="No roles yet"
            description="Create an app-scoped role, then bind its resource codes in the tree."
          />
        )}
        {rolesQuery.data && rolesQuery.data.length > 0 && (
          <Table
            columns={[
              { key: "code", header: "Code", className: "font-mono text-[13px]" },
              { key: "name", header: "Name" },
              { key: "scope", header: "Scope" },
              { key: "built_in", header: "Built-in" },
              { key: "created", header: "Created" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={rolesQuery.data}
            rowKey={(role) => role.id}
            cell={(role, column) => {
              switch (column.key) {
                case "code":
                  return role.code;
                case "name":
                  return <span className="font-bold">{role.name}</span>;
                case "scope":
                  return <Chip tone={role.scope === "global" ? "accent" : "neutral"}>{role.scope}</Chip>;
                case "built_in":
                  return role.built_in ? (
                    <Chip tone="accent">Built-in</Chip>
                  ) : (
                    <span className="text-white/40">—</span>
                  );
                case "created":
                  return (
                    <span className="text-white/55">{formatDate(role.created_at) ?? "—"}</span>
                  );
                case "actions":
                  return (
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => setBinding(role)}
                      >
                        <Icon name="key" className="size-4" /> Bind resources
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(role);
                          setEditName(role.name);
                          setEditError(null);
                        }}
                      >
                        Edit
                      </Button>
                      {!role.built_in && (
                        <ConfirmButton
                          size="sm"
                          confirmLabel="Confirm delete"
                          onConfirm={() => deleteMutation.mutateAsync(role)}
                        >
                          Delete
                        </ConfirmButton>
                      )}
                    </div>
                  );
                default:
                  return null;
              }
            }}
          />
        )}
      </div>

      {/* Create dialog */}
      {creating && (
        <Dialog title="New role" onClose={() => setCreating(false)}>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setCreateError(null);
              if (!form.code.trim() || !form.name.trim()) {
                setCreateError("Code and name are both required.");
                return;
              }
              createMutation.mutate();
            }}
          >
            <Field
              label="Code"
              value={form.code}
              onChange={(event) => setForm({ ...form, code: event.target.value })}
              placeholder="app_admin"
              hint="Unique per app, 2–64 chars."
              required
            />
            <Field
              label="Name"
              value={form.name}
              onChange={(event) => setForm({ ...form, name: event.target.value })}
              required
            />
            <SelectField
              label="Scope"
              value={form.scope}
              onChange={(event) => setForm({ ...form, scope: event.target.value })}
              hint="Global roles are platform-managed (org admins can't create them)."
            >
              <option value="app">app</option>
              <option value="global">global</option>
            </SelectField>
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
                Create
              </Button>
            </div>
          </form>
        </Dialog>
      )}

      {/* Edit dialog */}
      {editing && (
        <Dialog
          title={`Edit ${editing.name}`}
          description={`code: ${editing.code}`}
          onClose={() => setEditing(null)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setEditError(null);
              if (!editName.trim()) {
                setEditError("Name is required.");
                return;
              }
              updateMutation.mutate();
            }}
          >
            <Field
              label="Name"
              value={editName}
              onChange={(event) => setEditName(event.target.value)}
              required
            />
            {editError && (
              <p role="alert" className="text-[13px] text-[#FF9C86]">
                {editError}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="ghost" onClick={() => setEditing(null)}>
                Cancel
              </Button>
              <Button type="submit" loading={updateMutation.isPending}>
                Save
              </Button>
            </div>
          </form>
        </Dialog>
      )}

      {/* Bind resources drawer */}
      {binding && (
        <BindResourcesDrawer
          appKey={appKey}
          role={binding}
          onClose={() => setBinding(null)}
        />
      )}
    </div>
  );
}

function BindResourcesDrawer({
  appKey,
  role,
  onClose,
}: {
  appKey: string;
  role: AdminRole;
  onClose: () => void;
}) {
  const toast = useToast();
  const treeQuery = useQuery({
    queryKey: ["admin", "resources", appKey],
    queryFn: () => adminApi.listResourceRows(appKey),
  });
  const rows = useMemo(() => treeQuery.data ?? [], [treeQuery.data]);

  // resource_id -> effect for checked items. The current bindings aren't
  // exposed by the admin API contract (only the replace PUT exists), so the
  // drawer starts empty — saving is authoritative and replaces everything.
  // TODO(frontend): preload bindings when a GET .../roles/{id}/resources lands.
  const [selection, setSelection] = useState<Record<string, Effect>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);

  const grouped = useMemo(() => {
    const groups: { type: string; rows: ResourceRow[] }[] = [
      { type: "menu", rows: [] },
      { type: "api", rows: [] },
      { type: "button", rows: [] },
    ];
    for (const row of rows) {
      const group = groups.find((g) => g.type === row.type);
      if (group) group.rows.push(row);
      else groups.push({ type: row.type, rows: [row] });
    }
    return groups.filter((group) => group.rows.length > 0);
  }, [rows]);

  const saveMutation = useMutation({
    mutationFn: () =>
      adminApi.setRoleResources(
        appKey,
        role.id,
        Object.entries(selection).map(([resource_id, effect]) => ({
          resource_id,
          effect,
        })),
      ),
    onSuccess: (codes) => {
      toast(
        `${codes.length} resource${codes.length === 1 ? "" : "s"} bound to ${role.name}.`,
        "success",
      );
      onClose();
    },
    onError: (err) =>
      setSubmitError(errMessage(err, "Could not bind the resources.")),
  });

  function toggle(id: string) {
    setSelection((prev) => {
      const next = { ...prev };
      if (id in next) delete next[id];
      else next[id] = "allow";
      return next;
    });
  }

  function setEffect(id: string, effect: Effect) {
    setSelection((prev) => ({ ...prev, [id]: effect }));
  }

  const checkedCount = Object.keys(selection).length;

  return (
    <Drawer
      title={`Bind resources · ${role.name}`}
      description="Check the permission codes this role grants; deny entries are evaluated with M6 rules."
      onClose={onClose}
    >
      <Card className="mb-4 border-[#FFAB00]/30 bg-[#FFAB00]/[0.08] p-4">
        <p className="flex items-start gap-2 text-[13px] text-[#FFC96B]">
          <Icon name="alert" className="mt-0.5 size-4 flex-none" />
          Saving replaces <strong>all</strong> resource bindings of this role
          with the selection below (the API exposes binding as a full replace,
          current bindings aren&apos;t listed).
        </p>
      </Card>

      {treeQuery.isLoading && <TableSkeleton rows={5} />}
      {treeQuery.isError && (
        <ErrorCard
          message={errMessage(treeQuery.error, "We couldn't load the resource tree.")}
          onRetry={() => treeQuery.refetch()}
        />
      )}
      {treeQuery.data && rows.length === 0 && (
        <p className="rounded-xl border border-white/10 px-4 py-3.5 text-sm text-white/55">
          This app has no resources yet — create some in the Resources tab
          first.
        </p>
      )}

      {grouped.map((group) => (
        <div key={group.type} className="mb-5">
          <div className="mb-2 flex items-center gap-2">
            <ResourceTypeChip type={group.type} />
            <span className="text-xs font-bold uppercase tracking-wide text-white/45">
              {group.rows.length}
            </span>
          </div>
          <div className="divide-y divide-white/[0.06] rounded-xl border border-white/10 bg-white/[0.04]">
            {group.rows.map((row) => {
              const checked = row.id in selection;
              return (
                <div
                  key={row.id}
                  className="flex flex-wrap items-center gap-2 px-3 py-2.5"
                  style={{ paddingLeft: `${12 + row.depth * 14}px` }}
                >
                  <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2.5">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggle(row.id)}
                      className="size-4 flex-none accent-[#54B3B3]"
                    />
                    <span className="min-w-0 truncate text-sm text-white/85">
                      {row.name}
                    </span>
                    <span className="min-w-0 truncate font-mono text-xs text-white/40">
                      {row.code}
                    </span>
                  </label>
                  {checked ? (
                    <div className="flex flex-none items-center gap-2">
                      <select
                        value={selection[row.id]}
                        onChange={(event) =>
                          setEffect(row.id, event.target.value as Effect)
                        }
                        aria-label={`Effect for ${row.code}`}
                        className="rounded-md border border-white/15 bg-white/[0.06] px-2 py-1 text-xs font-bold text-white focus:outline-none focus:ring-2 focus:ring-ah-accent/30"
                      >
                        <option value="allow">allow</option>
                        <option value="deny">deny</option>
                      </select>
                      <EffectChip effect={selection[row.id]} />
                    </div>
                  ) : (
                    <span className="flex-none text-xs text-white/30">not bound</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}

      {submitError && (
        <p role="alert" className="mb-3 text-[13px] text-[#FF9C86]">
          {submitError}
        </p>
      )}

      <div className="sticky bottom-0 -mx-5 mt-2 flex items-center justify-between gap-3 border-t border-white/10 bg-[#0B4343] px-5 py-4">
        <span className="text-[13px] text-white/55">
          {checkedCount} resource{checkedCount === 1 ? "" : "s"} selected
        </span>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={saveMutation.isPending}
            onClick={() => {
              setSubmitError(null);
              saveMutation.mutate();
            }}
          >
            Save bindings
          </Button>
        </div>
      </div>
    </Drawer>
  );
}
