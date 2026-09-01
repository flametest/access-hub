"use client";

import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/button";
import { StatusChip } from "@/components/chips";
import { Dialog } from "@/components/dialog";
import { Field } from "@/components/field";
import { SelectField, TextareaField } from "@/components/form-fields";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { AdminApp } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDate } from "@/lib/format";

const APP_TYPES = ["web", "native", "service"] as const;

export default function AdminAppsPage() {
  const router = useRouter();
  const toast = useToast();
  const queryClient = useQueryClient();

  const appsQuery = useQuery({
    queryKey: ["admin", "apps"],
    queryFn: () => adminApi.listApps(),
  });
  const orgsQuery = useQuery({
    queryKey: ["admin", "orgs"],
    queryFn: () => adminApi.listOrgs(),
    // The org picker needs admin:org:read — org_admins may 403 here; the
    // create dialog degrades to a free-text org key field in that case.
    retry: false,
  });

  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    key: "",
    org_key: "",
    name: "",
    type: "web",
    description: "",
  });
  const [createError, setCreateError] = useState<string | null>(null);

  const [editing, setEditing] = useState<AdminApp | null>(null);
  const [editForm, setEditForm] = useState({ name: "", description: "", status: "active" });
  const [editError, setEditError] = useState<string | null>(null);

  const invalidateApps = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "apps"] });

  const createMutation = useMutation({
    mutationFn: () =>
      adminApi.createApp({
        key: form.key.trim(),
        org_key: form.org_key.trim() || undefined,
        name: form.name.trim(),
        type: form.type,
        description: form.description.trim() || undefined,
      }),
    onSuccess: (app) => {
      toast(`App "${app.name}" created.`, "success");
      setCreating(false);
      setForm({ key: "", org_key: "", name: "", type: "web", description: "" });
      setCreateError(null);
      void invalidateApps();
    },
    onError: (err) => setCreateError(errMessage(err, "Could not create the app.")),
  });

  const updateMutation = useMutation({
    mutationFn: () =>
      adminApi.updateApp(editing!.key, {
        name: editForm.name.trim(),
        description: editForm.description.trim(),
        status: editForm.status,
      }),
    onSuccess: () => {
      toast("App saved.", "success");
      setEditing(null);
      void invalidateApps();
    },
    onError: (err) => setEditError(errMessage(err, "Could not save the app.")),
  });

  if (isForbidden(appsQuery.error)) {
    return (
      <>
        <h1 className="text-2xl font-extrabold tracking-tight">Apps</h1>
        <div className="mt-6">
          <ForbiddenCard message="You don't hold admin:app:read — org admins can list their own org's apps." />
        </div>
      </>
    );
  }

  const orgOptions = orgsQuery.data ?? [];

  return (
    <div>
      <h1 className="text-2xl font-extrabold tracking-tight">Apps</h1>
      <p className="mt-1 text-sm text-white/55">
        Registered applications. Open an app to manage its resources, roles,
        accounts, invitations, OAuth clients and custom rules.
      </p>

      <div className="mt-6 flex justify-end">
        <Button size="sm" onClick={() => setCreating(true)}>
          <Icon name="plus" className="size-4" /> New app
        </Button>
      </div>

      <div className="mt-3">
        {appsQuery.isLoading && <TableSkeleton rows={5} />}
        {appsQuery.isError && (
          <ErrorCard
            message={errMessage(appsQuery.error, "We couldn't load apps.")}
            onRetry={() => appsQuery.refetch()}
          />
        )}
        {appsQuery.data && appsQuery.data.length === 0 && (
          <EmptyCard
            icon="layers"
            title="No apps yet"
            description="Create the first app — it becomes a workspace tenants can be invited into."
            action={
              <Button size="sm" onClick={() => setCreating(true)}>
                <Icon name="plus" className="size-4" /> New app
              </Button>
            }
          />
        )}
        {appsQuery.data && appsQuery.data.length > 0 && (
          <Table
            columns={[
              { key: "key", header: "Key", className: "font-mono text-[13px]" },
              { key: "name", header: "Name" },
              { key: "org", header: "Org" },
              { key: "type", header: "Type" },
              { key: "status", header: "Status" },
              { key: "created", header: "Created" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={appsQuery.data}
            rowKey={(app) => app.key}
            onRowClick={(app) => router.push(`/admin/apps/${encodeURIComponent(app.key)}`)}
            cell={(app, column) => {
              switch (column.key) {
                case "key":
                  return app.key;
                case "name":
                  return <span className="font-bold">{app.name}</span>;
                case "org":
                  return app.org_key ? (
                    <span className="font-mono text-[13px] text-white/60">{app.org_key}</span>
                  ) : (
                    <span className="text-xs text-white/40">platform</span>
                  );
                case "type":
                  return (
                    <span className="text-white/70">{app.type}</span>
                  );
                case "status":
                  return <StatusChip status={app.status} />;
                case "created":
                  return (
                    <span className="text-white/55">{formatDate(app.created_at) ?? "—"}</span>
                  );
                case "actions":
                  return (
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={(event) => {
                          event.stopPropagation();
                          router.push(`/admin/apps/${encodeURIComponent(app.key)}`);
                        }}
                      >
                        Open
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(event) => {
                          event.stopPropagation();
                          setEditing(app);
                          setEditForm({
                            name: app.name,
                            description: app.description,
                            status: app.status,
                          });
                          setEditError(null);
                        }}
                      >
                        Edit
                      </Button>
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
        <Dialog
          title="New app"
          description="Apps own resources, roles and per-app workspace accounts."
          onClose={() => setCreating(false)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setCreateError(null);
              if (!form.key.trim() || !form.name.trim()) {
                setCreateError("Key and name are both required.");
                return;
              }
              createMutation.mutate();
            }}
          >
            <Field
              label="Key"
              value={form.key}
              onChange={(event) => setForm({ ...form, key: event.target.value })}
              placeholder="crm"
              hint="Unique app key, 2–64 chars (aud claim of app tokens)."
              required
            />
            {orgOptions.length > 0 ? (
              <SelectField
                label="Organization"
                value={form.org_key}
                onChange={(event) => setForm({ ...form, org_key: event.target.value })}
                hint="Leave empty only for platform apps (the admin console itself)."
              >
                <option value="">— none (platform app) —</option>
                {orgOptions.map((org) => (
                  <option key={org.key} value={org.key}>
                    {org.name} ({org.key})
                  </option>
                ))}
              </SelectField>
            ) : (
              <Field
                label="Organization key"
                value={form.org_key}
                onChange={(event) => setForm({ ...form, org_key: event.target.value })}
                placeholder="acme"
                hint="Optional. Org listing isn't available to you — type the key, or leave empty for a platform app."
              />
            )}
            <Field
              label="Name"
              value={form.name}
              onChange={(event) => setForm({ ...form, name: event.target.value })}
              placeholder="Acme CRM"
              required
            />
            <SelectField
              label="Type"
              value={form.type}
              onChange={(event) => setForm({ ...form, type: event.target.value })}
            >
              {APP_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </SelectField>
            <TextareaField
              label="Description"
              value={form.description}
              onChange={(event) => setForm({ ...form, description: event.target.value })}
              rows={3}
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
          description={`key: ${editing.key}`}
          onClose={() => setEditing(null)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setEditError(null);
              if (!editForm.name.trim()) {
                setEditError("Name is required.");
                return;
              }
              updateMutation.mutate();
            }}
          >
            <Field
              label="Name"
              value={editForm.name}
              onChange={(event) => setEditForm({ ...editForm, name: event.target.value })}
              required
            />
            <TextareaField
              label="Description"
              value={editForm.description}
              onChange={(event) =>
                setEditForm({ ...editForm, description: event.target.value })
              }
              rows={3}
            />
            <SelectField
              label="Status"
              value={editForm.status}
              onChange={(event) => setEditForm({ ...editForm, status: event.target.value })}
              hint="Disabled apps stop issuing tokens and serving authorizations."
            >
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </SelectField>
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
    </div>
  );
}
