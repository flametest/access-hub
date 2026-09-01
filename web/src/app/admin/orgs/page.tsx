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
import { SelectField } from "@/components/form-fields";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { Org, OrgMember } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDate } from "@/lib/format";

const ORG_ROLES = ["owner", "admin", "member"] as const;

export default function AdminOrgsPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const orgsQuery = useQuery({
    queryKey: ["admin", "orgs"],
    queryFn: () => adminApi.listOrgs(),
  });

  // Create dialog state
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newName, setNewName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  // Edit dialog state
  const [editing, setEditing] = useState<Org | null>(null);
  const [editName, setEditName] = useState("");
  const [editStatus, setEditStatus] = useState("active");
  const [editError, setEditError] = useState<string | null>(null);

  // Members sub-view
  const [membersOrg, setMembersOrg] = useState<Org | null>(null);

  const invalidateOrgs = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "orgs"] });

  const createMutation = useMutation({
    mutationFn: () => adminApi.createOrg({ key: newKey.trim(), name: newName.trim() }),
    onSuccess: (org) => {
      toast(`Organization "${org.name}" created.`, "success");
      setCreating(false);
      setNewKey("");
      setNewName("");
      setCreateError(null);
      void invalidateOrgs();
    },
    onError: (err) => setCreateError(errMessage(err, "Could not create the organization.")),
  });

  const updateMutation = useMutation({
    mutationFn: () =>
      adminApi.updateOrg(editing!.key, {
        name: editName.trim(),
        status: editStatus,
      }),
    onSuccess: () => {
      toast("Organization saved.", "success");
      setEditing(null);
      void invalidateOrgs();
    },
    onError: (err) => setEditError(errMessage(err, "Could not save the organization.")),
  });

  if (isForbidden(orgsQuery.error)) {
    return (
      <>
        <PageHeader />
        <ForbiddenCard message="Organizations are platform-only (admin:org:read) — org admins scope to their own org's apps instead." />
      </>
    );
  }

  return (
    <div>
      <PageHeader />

      <div className="mt-6 flex justify-end">
        <Button size="sm" onClick={() => setCreating(true)}>
          <Icon name="plus" className="size-4" /> New organization
        </Button>
      </div>

      <div className="mt-3">
        {orgsQuery.isLoading && <TableSkeleton rows={4} />}
        {orgsQuery.isError && (
          <ErrorCard
            message={errMessage(orgsQuery.error, "We couldn't load organizations.")}
            onRetry={() => orgsQuery.refetch()}
          />
        )}
        {orgsQuery.data && orgsQuery.data.length === 0 && (
          <EmptyCard
            icon="building"
            title="No organizations yet"
            description="Create the first organization to start scoping apps to tenants."
            action={
              <Button size="sm" onClick={() => setCreating(true)}>
                <Icon name="plus" className="size-4" /> New organization
              </Button>
            }
          />
        )}
        {orgsQuery.data && orgsQuery.data.length > 0 && (
          <Table
            columns={[
              { key: "key", header: "Key", className: "font-mono text-[13px]" },
              { key: "name", header: "Name" },
              { key: "status", header: "Status" },
              { key: "created", header: "Created" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={orgsQuery.data}
            rowKey={(org) => org.key}
            cell={(org, column) => {
              switch (column.key) {
                case "key":
                  return org.key;
                case "name":
                  return <span className="font-bold">{org.name}</span>;
                case "status":
                  return <StatusChip status={org.status} />;
                case "created":
                  return (
                    <span className="text-white/55">{formatDate(org.created_at) ?? "—"}</span>
                  );
                case "actions":
                  return (
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => setMembersOrg(org)}
                      >
                        <Icon name="users" className="size-4" /> Members
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(org);
                          setEditName(org.name);
                          setEditStatus(org.status);
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
          title="New organization"
          description="Orgs are tenant containers: apps belong to one, org_members decide who governs it."
          onClose={() => setCreating(false)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setCreateError(null);
              if (!newKey.trim() || !newName.trim()) {
                setCreateError("Key and name are both required.");
                return;
              }
              createMutation.mutate();
            }}
          >
            <Field
              label="Key"
              value={newKey}
              onChange={(event) => setNewKey(event.target.value)}
              placeholder="acme"
              hint="Unique, 2–64 chars. Shown in URLs and API calls — hard to change later."
              required
            />
            <Field
              label="Name"
              value={newName}
              onChange={(event) => setNewName(event.target.value)}
              placeholder="Acme Inc."
              required
            />
            {createError && <DialogError message={createError} />}
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
            <SelectField
              label="Status"
              value={editStatus}
              onChange={(event) => setEditStatus(event.target.value)}
            >
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </SelectField>
            {editError && <DialogError message={editError} />}
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

      {/* Members sub-view */}
      {membersOrg && (
        <OrgMembersDrawer org={membersOrg} onClose={() => setMembersOrg(null)} />
      )}
    </div>
  );
}

function PageHeader() {
  return (
    <>
      <h1 className="text-2xl font-extrabold tracking-tight">Organizations</h1>
      <p className="mt-1 text-sm text-white/55">
        Tenant containers for apps. Org membership (owner/admin) governs who
        manages the org — it is not an app permission.
      </p>
    </>
  );
}

function DialogError({ message }: { message: string }) {
  return (
    <p
      role="alert"
      className="rounded-lg border border-[#FF5630]/35 bg-[#FF5630]/10 px-3 py-2 text-[13px] text-[#FF9C86]"
    >
      {message}
    </p>
  );
}

function OrgMembersDrawer({ org, onClose }: { org: Org; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const membersQuery = useQuery({
    queryKey: ["admin", "org-members", org.key],
    queryFn: () => adminApi.listOrgMembers(org.key),
  });

  const [email, setEmail] = useState("");
  const [orgRole, setOrgRole] = useState<string>("member");
  const [addError, setAddError] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({
      queryKey: ["admin", "org-members", org.key],
    });

  const addMutation = useMutation({
    mutationFn: () =>
      adminApi.addOrgMember(org.key, { email: email.trim(), org_role: orgRole }),
    onSuccess: (member) => {
      toast(`${member.email || member.username} added as ${member.org_role}.`, "success");
      setEmail("");
      setAddError(null);
      void invalidate();
    },
    onError: (err) => setAddError(errMessage(err, "Could not add the member.")),
  });

  const removeMutation = useMutation({
    mutationFn: (userId: string) => adminApi.removeOrgMember(org.key, userId),
    onSuccess: () => {
      toast("Member removed.", "success");
      void invalidate();
    },
    onError: (err) =>
      toast(errMessage(err, "Could not remove the member."), "error"),
  });

  return (
    <Drawer
      title={`Members · ${org.name}`}
      description="Governance roles for this org (owner / admin / member)."
      onClose={onClose}
    >
      <Card className="p-4">
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            setAddError(null);
            if (!email.trim()) {
              setAddError("Email is required.");
              return;
            }
            addMutation.mutate();
          }}
        >
          <p className="text-[13px] font-semibold text-white/80">Add member</p>
          <Field
            label="Email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="person@example.com"
            hint="The person's primary identity email."
            required
          />
          <SelectField
            label="Org role"
            value={orgRole}
            onChange={(event) => setOrgRole(event.target.value)}
          >
            {ORG_ROLES.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </SelectField>
          {addError && <DialogError message={addError} />}
          <div className="flex justify-end">
            <Button type="submit" size="sm" loading={addMutation.isPending}>
              <Icon name="plus" className="size-4" /> Add
            </Button>
          </div>
        </form>
      </Card>

      <div className="mt-4">
        {membersQuery.isLoading && <TableSkeleton rows={3} />}
        {membersQuery.isError && (
          <ErrorCard
            message={errMessage(membersQuery.error, "We couldn't load the members.")}
            onRetry={() => membersQuery.refetch()}
          />
        )}
        {membersQuery.data && membersQuery.data.length === 0 && (
          <p className="rounded-xl border border-white/10 px-4 py-3.5 text-sm text-white/55">
            No members yet — add the first one above.
          </p>
        )}
        {membersQuery.data && membersQuery.data.length > 0 && (
          <Table
            columns={[
              { key: "member", header: "Member" },
              { key: "role", header: "Org role" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={membersQuery.data}
            rowKey={(member: OrgMember) => member.user_id}
            cell={(member, column) => {
              switch (column.key) {
                case "member":
                  return (
                    <div className="min-w-0">
                      <div className="truncate font-bold">{member.nickname}</div>
                      <div className="truncate text-xs text-white/50">
                        {member.email || member.username}
                      </div>
                    </div>
                  );
                case "role":
                  return (
                    <span className="rounded-md border border-white/15 bg-white/[0.07] px-2 py-0.5 text-xs font-semibold text-white/70">
                      {member.org_role}
                    </span>
                  );
                case "actions":
                  return (
                    <div className="flex justify-end">
                      <ConfirmButton
                        size="sm"
                        confirmLabel="Confirm remove"
                        onConfirm={() => removeMutation.mutateAsync(member.user_id)}
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
