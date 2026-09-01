"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { StatusChip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Dialog } from "@/components/dialog";
import { Field } from "@/components/field";
import { SelectField, TextareaField } from "@/components/form-fields";
import { ResourceTypeChip } from "@/components/admin/chips";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { BatchResourceItem, ResourceRow } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";

const RESOURCE_TYPES = ["menu", "api", "button"] as const;

/**
 * Resources tab: the single-table resource tree (design.md §2.3) rendered as
 * an indented table, node create/edit (parent select), delete with the
 * children guard surfaced as a toast, and a JSON batch import
 * (PUT .../resources:batch, idempotent by code; ?mode=replace needs confirm).
 */
export function ResourcesTab({ appKey }: { appKey: string }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const treeQuery = useQuery({
    queryKey: ["admin", "resources", appKey],
    queryFn: () => adminApi.listResourceRows(appKey),
  });
  const rows = useMemo(() => treeQuery.data ?? [], [treeQuery.data]);

  // Node dialog
  const [editing, setEditing] = useState<ResourceRow | null>(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    type: "menu",
    code: "",
    name: "",
    parent_id: "",
    path: "",
    icon: "",
    sort: "0",
    visible: true,
    method: "",
    route_path: "",
    status: "active",
  });
  const [nodeError, setNodeError] = useState<string | null>(null);

  // Batch import
  const [showBatch, setShowBatch] = useState(false);
  const [batchText, setBatchText] = useState("");
  const [replaceMode, setReplaceMode] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "resources", appKey] });

  function resetForm(preset?: Partial<typeof form>) {
    setForm({
      type: "menu",
      code: "",
      name: "",
      parent_id: "",
      path: "",
      icon: "",
      sort: "0",
      visible: true,
      method: "",
      route_path: "",
      status: "active",
      ...preset,
    });
    setNodeError(null);
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        type: form.type,
        code: form.code.trim(),
        name: form.name.trim(),
        sort: Number(form.sort) || 0,
        visible: form.visible,
        status: form.status,
      };
      if (form.parent_id) body.parent_id = form.parent_id;
      if (form.type === "menu" && form.path.trim()) body.path = form.path.trim();
      if (form.icon.trim()) body.icon = form.icon.trim();
      if (form.type === "api") {
        body.method = form.method.trim().toUpperCase();
        body.route_path = form.route_path.trim();
      }
      return editing
        ? adminApi.updateResource(appKey, editing.id, body)
        : adminApi.createResource(appKey, body);
    },
    onSuccess: () => {
      toast(editing ? "Resource saved." : "Resource created.", "success");
      setEditing(null);
      setCreating(false);
      void invalidate();
    },
    onError: (err) => setNodeError(errMessage(err, "Could not save the resource.")),
  });

  const deleteMutation = useMutation({
    mutationFn: (row: ResourceRow) => adminApi.deleteResource(appKey, row.id),
    onSuccess: () => {
      toast("Resource deleted.", "success");
      void invalidate();
    },
    onError: (err) =>
      toast(errMessage(err, "Could not delete the resource."), "error"),
  });

  const batchMutation = useMutation({
    mutationFn: (items: BatchResourceItem[]) =>
      adminApi.batchResources(appKey, items, replaceMode ? "replace" : ""),
    onSuccess: (result) => {
      toast(
        `Batch import done — ${result.created} created, ${result.updated} updated, ${result.disabled} disabled.`,
        "success",
      );
      setBatchText("");
      setBatchError(null);
      setReplaceMode(false);
      void invalidate();
    },
    onError: (err) => setBatchError(errMessage(err, "Batch import failed.")),
  });

  /** Client-side validation of the batch JSON per BatchResourceItem. */
  function parseBatch(): BatchResourceItem[] | null {
    setBatchError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(batchText);
    } catch {
      setBatchError("That isn't valid JSON — expected {\"items\": [...]}.");
      return null;
    }
    const itemsRaw =
      parsed !== null &&
      typeof parsed === "object" &&
      Array.isArray((parsed as { items?: unknown }).items)
        ? ((parsed as { items: unknown[] }).items as unknown[])
        : null;
    if (!itemsRaw || itemsRaw.length === 0) {
      setBatchError('Expected a non-empty "items" array: {"items": [{code, name, type}, ...]}.');
      return null;
    }
    const items: BatchResourceItem[] = [];
    for (let i = 0; i < itemsRaw.length; i += 1) {
      const raw = itemsRaw[i] as Record<string, unknown>;
      const code = typeof raw.code === "string" ? raw.code.trim() : "";
      const name = typeof raw.name === "string" ? raw.name.trim() : "";
      const type = typeof raw.type === "string" ? raw.type.trim() : "";
      if (!code || !name) {
        setBatchError(`Item ${i + 1}: "code" and "name" are required.`);
        return null;
      }
      if (!RESOURCE_TYPES.includes(type as (typeof RESOURCE_TYPES)[number])) {
        setBatchError(
          `Item ${i + 1} (${code}): "type" must be one of menu, api, button.`,
        );
        return null;
      }
      items.push({
        code,
        name,
        type,
        parent_code:
          typeof raw.parent_code === "string" && raw.parent_code.trim()
            ? raw.parent_code.trim()
            : undefined,
        path: typeof raw.path === "string" && raw.path.trim() ? raw.path.trim() : undefined,
        icon: typeof raw.icon === "string" && raw.icon.trim() ? raw.icon.trim() : undefined,
        sort: typeof raw.sort === "number" ? raw.sort : undefined,
        visible: typeof raw.visible === "boolean" ? raw.visible : undefined,
        method:
          typeof raw.method === "string" && raw.method.trim()
            ? raw.method.trim().toUpperCase()
            : undefined,
        route_path:
          typeof raw.route_path === "string" && raw.route_path.trim()
            ? raw.route_path.trim()
            : undefined,
        status:
          typeof raw.status === "string" && raw.status.trim()
            ? raw.status.trim()
            : undefined,
      });
    }
    return items;
  }

  if (isForbidden(treeQuery.error)) {
    return (
      <ForbiddenCard message="Resource management needs admin:resource:manage for this app." />
    );
  }

  // Parent options: every row (indented label). When editing, exclude the node
  // itself and its descendants (re-parenting into your own subtree is a cycle).
  const parentOptions = editing
    ? rows.filter((row) => row.id !== editing.id && !isDescendant(rows, editing, row))
    : rows;

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-white/55">
          One resource table, three types: <code className="font-mono">menu</code>{" "}
          (nav tree), <code className="font-mono">api</code> (permission codes
          enforced on routes), <code className="font-mono">button</code>{" "}
          (UI-level permission codes).
        </p>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" onClick={() => setShowBatch((v) => !v)}>
            <Icon name="download" className="size-4" /> Batch import
          </Button>
          <Button
            size="sm"
            onClick={() => {
              resetForm();
              setCreating(true);
            }}
          >
            <Icon name="plus" className="size-4" /> New node
          </Button>
        </div>
      </div>

      {/* Batch import panel */}
      {showBatch && (
        <Card className="mt-4 p-5">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const items = parseBatch();
              if (items) batchMutation.mutate(items);
            }}
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h3 className="font-bold">Batch import resources</h3>
              <label className="flex items-center gap-2 text-[13px] text-white/70">
                <input
                  type="checkbox"
                  checked={replaceMode}
                  onChange={(event) => setReplaceMode(event.target.checked)}
                  className="size-4 accent-[#54B3B3]"
                />
                mode=replace (archive missing codes)
              </label>
            </div>
            <TextareaField
              label="JSON payload"
              monospace
              rows={8}
              className="mt-3"
              placeholder={`{\n  "items": [\n    { "code": "dashboard", "name": "Dashboard", "type": "menu", "path": "/dashboard" },\n    { "code": "order:read", "name": "Read orders", "type": "api", "method": "GET", "route_path": "/api/orders" }\n  ]\n}`}
              value={batchText}
              onChange={(event) => setBatchText(event.target.value)}
              hint="Matched idempotently by (app, code); parent_code links children. mode=replace also archives resources missing from the payload."
            />
            {batchError && (
              <p role="alert" className="mt-2 text-[13px] text-[#FF9C86]">
                {batchError}
              </p>
            )}
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
              <span className="text-[13px] text-white/50">
                {(() => {
                  if (!batchText.trim()) return "Paste JSON above.";
                  try {
                    const parsed = JSON.parse(batchText) as { items?: unknown[] };
                    return Array.isArray(parsed.items)
                      ? `${parsed.items.length} item${parsed.items.length === 1 ? "" : "s"} ready for import.`
                      : "No items array found yet.";
                  } catch {
                    return "Waiting for valid JSON…";
                  }
                })()}
              </span>
              <div className="flex gap-2">
                {replaceMode && (
                  <ConfirmButton
                    size="sm"
                    variant="danger"
                    confirmLabel="Confirm replace import"
                    onConfirm={() => {
                      const items = parseBatch();
                      if (items) batchMutation.mutate(items);
                    }}
                  >
                    Import (replace)
                  </ConfirmButton>
                )}
                <Button type="submit" size="sm" loading={batchMutation.isPending}>
                  Import
                </Button>
              </div>
            </div>
          </form>
        </Card>
      )}

      <div className="mt-4">
        {treeQuery.isLoading && <TableSkeleton rows={6} />}
        {treeQuery.isError && (
          <ErrorCard
            message={errMessage(treeQuery.error, "We couldn't load the resource tree.")}
            onRetry={() => treeQuery.refetch()}
          />
        )}
        {treeQuery.data && rows.length === 0 && (
          <EmptyCard
            icon="layers"
            title="No resources yet"
            description="Add nodes by hand or batch-import a JSON manifest to bootstrap the permission tree."
          />
        )}
        {treeQuery.data && rows.length > 0 && (
          <Table
            columns={[
              { key: "name", header: "Name", className: "min-w-[220px]" },
              { key: "code", header: "Code", className: "font-mono text-[13px]" },
              { key: "route", header: "Method · Route" },
              { key: "status", header: "Status" },
              { key: "visible", header: "Visible" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={rows}
            rowKey={(row) => row.id}
            cell={(row, column) => {
              switch (column.key) {
                case "name":
                  return (
                    <div
                      className="flex items-center gap-2"
                      style={{ paddingLeft: `${row.depth * 18}px` }}
                    >
                      {row.depth > 0 && (
                        <span className="text-white/25" aria-hidden="true">
                          └
                        </span>
                      )}
                      <ResourceTypeChip type={row.type} />
                      <span className="truncate font-bold">{row.name}</span>
                    </div>
                  );
                case "code":
                  return <span className="text-white/70">{row.code}</span>;
                case "route":
                  if (row.type === "api") {
                    return (
                      <span className="font-mono text-[13px] text-white/70">
                        {row.method || "?"} {row.route_path || "—"}
                      </span>
                    );
                  }
                  return (
                    <span className="font-mono text-[13px] text-white/45">
                      {row.path || "—"}
                    </span>
                  );
                case "status":
                  return <StatusChip status={row.status} />;
                case "visible":
                  return row.visible ? (
                    <span className="text-[#7CE49F]">Yes</span>
                  ) : (
                    <span className="text-white/40">No</span>
                  );
                case "actions":
                  return (
                    <div className="flex justify-end gap-1.5">
                      <Button
                        size="sm"
                        variant="ghost"
                        title="Add child node"
                        onClick={() => {
                          resetForm({ parent_id: row.id });
                          setCreating(true);
                        }}
                      >
                        <Icon name="plus" className="size-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(row);
                          resetForm({
                            type: row.type,
                            code: row.code,
                            name: row.name,
                            parent_id: row.parent_id ?? "",
                            path: row.path,
                            icon: row.icon,
                            sort: String(row.sort ?? 0),
                            visible: row.visible,
                            method: row.method,
                            route_path: row.route_path,
                            status: row.status,
                          });
                        }}
                      >
                        Edit
                      </Button>
                      <ConfirmButton
                        size="sm"
                        confirmLabel="Confirm delete"
                        onConfirm={() => deleteMutation.mutateAsync(row)}
                      >
                        Delete
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

      {/* Create / edit node dialog */}
      {(creating || editing) && (
        <Dialog
          wide
          title={editing ? `Edit ${editing.name}` : "New resource node"}
          description={
            editing
              ? `code: ${editing.code}`
              : "Menus shape the nav tree; api/button codes are the permission units."
          }
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setNodeError(null);
              if (!form.code.trim() || !form.name.trim()) {
                setNodeError("Code and name are both required.");
                return;
              }
              if (form.type === "api" && !form.route_path.trim()) {
                setNodeError("API resources need a route path.");
                return;
              }
              saveMutation.mutate();
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <SelectField
                label="Type"
                value={form.type}
                onChange={(event) => setForm({ ...form, type: event.target.value })}
                disabled={Boolean(editing)}
              >
                {RESOURCE_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </SelectField>
              <SelectField
                label="Parent"
                value={form.parent_id}
                onChange={(event) => setForm({ ...form, parent_id: event.target.value })}
              >
                <option value="">— root —</option>
                {parentOptions.map((row) => (
                  <option key={row.id} value={row.id}>
                    {"\u00A0".repeat(row.depth * 2)}
                    {row.name} ({row.type})
                  </option>
                ))}
              </SelectField>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label="Code"
                value={form.code}
                onChange={(event) => setForm({ ...form, code: event.target.value })}
                placeholder="order:read"
                hint="Unique per app — this is the permission code."
                required
              />
              <Field
                label="Name"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
              />
            </div>
            {form.type === "menu" && (
              <Field
                label="Nav path"
                value={form.path}
                onChange={(event) => setForm({ ...form, path: event.target.value })}
                placeholder="/orders"
              />
            )}
            {form.type === "api" && (
              <div className="grid gap-4 sm:grid-cols-3">
                <SelectField
                  label="Method"
                  value={form.method}
                  onChange={(event) => setForm({ ...form, method: event.target.value })}
                >
                  <option value="">—</option>
                  {["GET", "POST", "PUT", "PATCH", "DELETE"].map((method) => (
                    <option key={method} value={method}>
                      {method}
                    </option>
                  ))}
                </SelectField>
                <Field
                  label="Route path"
                  value={form.route_path}
                  onChange={(event) => setForm({ ...form, route_path: event.target.value })}
                  placeholder="/api/v1/orders/:id"
                  className="sm:col-span-2"
                />
              </div>
            )}
            <div className="grid gap-4 sm:grid-cols-3">
              <Field
                label="Icon"
                value={form.icon}
                onChange={(event) => setForm({ ...form, icon: event.target.value })}
                placeholder="grid"
              />
              <Field
                label="Sort"
                type="number"
                value={form.sort}
                onChange={(event) => setForm({ ...form, sort: event.target.value })}
              />
              <SelectField
                label="Status"
                value={form.status}
                onChange={(event) => setForm({ ...form, status: event.target.value })}
              >
                <option value="active">Active</option>
                <option value="disabled">Disabled</option>
              </SelectField>
            </div>
            <label className="flex items-center gap-2 text-sm text-white/75">
              <input
                type="checkbox"
                checked={form.visible}
                onChange={(event) => setForm({ ...form, visible: event.target.checked })}
                className="size-4 accent-[#54B3B3]"
              />
              Visible in menus
            </label>
            {nodeError && (
              <p role="alert" className="text-[13px] text-[#FF9C86]">
                {nodeError}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setCreating(false);
                  setEditing(null);
                }}
              >
                Cancel
              </Button>
              <Button type="submit" loading={saveMutation.isPending}>
                {editing ? "Save" : "Create"}
              </Button>
            </div>
          </form>
        </Dialog>
      )}
    </div>
  );
}

/** True when `candidate` sits in the subtree of `root` (depth-walk on rows). */
function isDescendant(
  rows: ResourceRow[],
  root: ResourceRow,
  candidate: ResourceRow,
): boolean {
  const startIndex = rows.findIndex((row) => row.id === root.id);
  if (startIndex < 0) return false;
  for (let i = startIndex + 1; i < rows.length; i += 1) {
    const row = rows[i];
    if (row.depth <= root.depth) return false;
    if (row.id === candidate.id) return true;
  }
  return false;
}
