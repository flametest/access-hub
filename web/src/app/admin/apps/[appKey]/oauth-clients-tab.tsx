"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip, StatusChip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Dialog } from "@/components/dialog";
import { Field } from "@/components/field";
import { CheckboxList, SelectField, TextareaField } from "@/components/form-fields";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { OAuthClient, OAuthClientCreateResult } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";

const GRANT_TYPES = [
  { value: "authorization_code", label: "Authorization code (user sign-in)" },
  { value: "refresh_token", label: "Refresh token" },
  { value: "client_credentials", label: "Client credentials (service)" },
] as const;

/** One textarea line per URI. */
function linesToValues(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

/**
 * OAuth clients tab (M4 admin surface): client CRUD with the plaintext secret
 * shown exactly once after create (only its hash is stored server-side).
 */
export function OAuthClientsTab({ appKey }: { appKey: string }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const clientsQuery = useQuery({
    queryKey: ["admin", "oauth-clients", appKey],
    queryFn: () => adminApi.listOAuthClients(appKey),
  });

  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    name: "",
    client_type: "confidential",
    redirectText: "",
    scopesText: "",
  });
  const [grantTypes, setGrantTypes] = useState<string[]>(["authorization_code", "refresh_token"]);
  const [createError, setCreateError] = useState<string | null>(null);
  const [created, setCreated] = useState<OAuthClientCreateResult | null>(null);

  const [editing, setEditing] = useState<OAuthClient | null>(null);
  const [editForm, setEditForm] = useState({
    name: "",
    status: "active",
    redirectText: "",
    scopesText: "",
  });
  const [editGrants, setEditGrants] = useState<string[]>([]);
  const [editError, setEditError] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "oauth-clients", appKey] });

  const createMutation = useMutation({
    mutationFn: () =>
      adminApi.createOAuthClient(appKey, {
        name: form.name.trim(),
        client_type: form.client_type,
        grant_types: grantTypes,
        redirect_uris: linesToValues(form.redirectText),
        scopes: linesToValues(form.scopesText),
      }),
    onSuccess: (result) => {
      setCreating(false);
      setForm({ name: "", client_type: "confidential", redirectText: "", scopesText: "" });
      setGrantTypes(["authorization_code", "refresh_token"]);
      setCreateError(null);
      setCreated(result);
      void invalidate();
    },
    onError: (err) =>
      setCreateError(errMessage(err, "Could not create the OAuth client.")),
  });

  const updateMutation = useMutation({
    mutationFn: () =>
      adminApi.updateOAuthClient(appKey, editing!.client_id, {
        name: editForm.name.trim(),
        status: editForm.status,
        grant_types: editGrants,
        redirect_uris: linesToValues(editForm.redirectText),
        scopes: linesToValues(editForm.scopesText),
      }),
    onSuccess: () => {
      toast("OAuth client saved.", "success");
      setEditing(null);
      void invalidate();
    },
    onError: (err) => setEditError(errMessage(err, "Could not save the client.")),
  });

  const deleteMutation = useMutation({
    mutationFn: (client: OAuthClient) =>
      adminApi.deleteOAuthClient(appKey, client.client_id),
    onSuccess: () => {
      toast("OAuth client deleted.", "success");
      void invalidate();
    },
    onError: (err) =>
      toast(errMessage(err, "Could not delete the client."), "error"),
  });

  if (isForbidden(clientsQuery.error)) {
    return (
      <ForbiddenCard message="OAuth client management needs admin:oauthclient:manage for this app." />
    );
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-white/55">
          OIDC/OAuth2 clients for this app. Secrets are hashed server-side —
          the plaintext is shown exactly once, at creation.
        </p>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Icon name="plus" className="size-4" /> New client
        </Button>
      </div>

      <div className="mt-4">
        {clientsQuery.isLoading && <TableSkeleton rows={3} />}
        {clientsQuery.isError && (
          <ErrorCard
            message={errMessage(clientsQuery.error, "We couldn't load OAuth clients.")}
            onRetry={() => clientsQuery.refetch()}
          />
        )}
        {clientsQuery.data && clientsQuery.data.length === 0 && (
          <EmptyCard
            icon="lock"
            title="No OAuth clients yet"
            description="Register a client to let apps sign users in via OIDC (authorization code + PKCE)."
          />
        )}
        {clientsQuery.data && clientsQuery.data.length > 0 && (
          <Table
            columns={[
              { key: "client_id", header: "Client ID", className: "font-mono text-[13px]" },
              { key: "name", header: "Name" },
              { key: "type", header: "Type" },
              { key: "grants", header: "Grants", className: "min-w-[200px]" },
              { key: "status", header: "Status" },
              { key: "actions", header: "", className: "text-right" },
            ]}
            rows={clientsQuery.data}
            rowKey={(client) => client.client_id}
            cell={(client, column) => {
              switch (column.key) {
                case "client_id":
                  return client.client_id;
                case "name":
                  return <span className="font-bold">{client.name}</span>;
                case "type":
                  return <Chip tone={client.client_type === "public" ? "neutral" : "accent"}>{client.client_type}</Chip>;
                case "grants":
                  return (
                    <span className="text-[13px] text-white/70">
                      {client.grant_types.join(", ") || "—"}
                    </span>
                  );
                case "status":
                  return <StatusChip status={client.status} />;
                case "actions":
                  return (
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(client);
                          setEditForm({
                            name: client.name,
                            status: client.status,
                            redirectText: client.redirect_uris.join("\n"),
                            scopesText: client.scopes.join("\n"),
                          });
                          setEditGrants(client.grant_types);
                          setEditError(null);
                        }}
                      >
                        Edit
                      </Button>
                      <ConfirmButton
                        size="sm"
                        confirmLabel="Confirm delete"
                        onConfirm={() => deleteMutation.mutateAsync(client)}
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

      {/* Create dialog */}
      {creating && (
        <Dialog
          wide
          title="New OAuth client"
          onClose={() => setCreating(false)}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setCreateError(null);
              if (!form.name.trim()) {
                setCreateError("Name is required.");
                return;
              }
              if (grantTypes.length === 0) {
                setCreateError("Pick at least one grant type.");
                return;
              }
              if (
                grantTypes.includes("authorization_code") &&
                form.client_type === "confidential" &&
                linesToValues(form.redirectText).length === 0
              ) {
                setCreateError("Confidential clients need at least one redirect URI.");
                return;
              }
              createMutation.mutate();
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label="Name"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
              />
              <SelectField
                label="Client type"
                value={form.client_type}
                onChange={(event) => setForm({ ...form, client_type: event.target.value })}
                hint="Public clients (SPAs) get no secret and use PKCE."
              >
                <option value="confidential">confidential</option>
                <option value="public">public</option>
              </SelectField>
            </div>
            <CheckboxList
              label="Grant types"
              options={GRANT_TYPES.map((grant) => ({
                value: grant.value,
                label: grant.label,
              }))}
              selected={grantTypes}
              onToggle={(value) =>
                setGrantTypes((prev) =>
                  prev.includes(value)
                    ? prev.filter((g) => g !== value)
                    : [...prev, value],
                )
              }
            />
            <TextareaField
              label="Redirect URIs (one per line)"
              monospace
              rows={3}
              value={form.redirectText}
              onChange={(event) => setForm({ ...form, redirectText: event.target.value })}
              placeholder={"http://localhost:3000/callback"}
            />
            <TextareaField
              label="Scopes (one per line)"
              monospace
              rows={2}
              value={form.scopesText}
              onChange={(event) => setForm({ ...form, scopesText: event.target.value })}
              placeholder={"openid\nprofile"}
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

      {/* Secret-shown-once callout */}
      {created && (
        <Dialog
          title="Client created"
          description="Copy the secret now — it is never shown again."
          onClose={() => setCreated(null)}
        >
          <div className="space-y-4">
            <Card className="border-[#FFAB00]/30 bg-[#FFAB00]/[0.08] p-4">
              <p className="flex items-start gap-2 text-[13px] text-[#FFC96B]">
                <Icon name="alert" className="mt-0.5 size-4 flex-none" />
                This is the only time the client secret is visible. It&apos;s stored
                hashed; losing it means creating a new client.
              </p>
            </Card>
            <Field
              label="Client ID"
              value={created.client.client_id}
              readOnly
              onFocus={(event) => event.currentTarget.select()}
            />
            {created.client_secret ? (
              <Field
                label="Client secret"
                value={created.client_secret}
                readOnly
                onFocus={(event) => event.currentTarget.select()}
              />
            ) : (
              <p className="text-sm text-white/55">
                Public client — no secret issued (PKCE flow).
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button
                variant="secondary"
                onClick={() => {
                  const text = [
                    created.client.client_id,
                    created.client_secret,
                  ]
                    .filter(Boolean)
                    .join("\n");
                  void navigator.clipboard?.writeText(text);
                  toast("Copied to clipboard.", "success");
                }}
              >
                <Icon name="copy" className="size-4" /> Copy
              </Button>
              <Button onClick={() => setCreated(null)}>Done</Button>
            </div>
          </div>
        </Dialog>
      )}

      {/* Edit dialog */}
      {editing && (
        <Dialog
          wide
          title={`Edit ${editing.name}`}
          description={`client_id: ${editing.client_id}`}
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
              if (editGrants.length === 0) {
                setEditError("Pick at least one grant type.");
                return;
              }
              updateMutation.mutate();
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label="Name"
                value={editForm.name}
                onChange={(event) => setEditForm({ ...editForm, name: event.target.value })}
                required
              />
              <SelectField
                label="Status"
                value={editForm.status}
                onChange={(event) => setEditForm({ ...editForm, status: event.target.value })}
                hint="Disabled clients are skipped by the policy loader on next reload."
              >
                <option value="active">Active</option>
                <option value="disabled">Disabled</option>
              </SelectField>
            </div>
            <CheckboxList
              label="Grant types"
              options={GRANT_TYPES.map((grant) => ({
                value: grant.value,
                label: grant.label,
              }))}
              selected={editGrants}
              onToggle={(value) =>
                setEditGrants((prev) =>
                  prev.includes(value)
                    ? prev.filter((g) => g !== value)
                    : [...prev, value],
                )
              }
            />
            <TextareaField
              label="Redirect URIs (one per line)"
              monospace
              rows={3}
              value={editForm.redirectText}
              onChange={(event) => setEditForm({ ...editForm, redirectText: event.target.value })}
            />
            <TextareaField
              label="Scopes (one per line)"
              monospace
              rows={2}
              value={editForm.scopesText}
              onChange={(event) => setEditForm({ ...editForm, scopesText: event.target.value })}
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
    </div>
  );
}
