"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip, StatusChip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Dialog } from "@/components/dialog";
import { Field } from "@/components/field";
import { Icon } from "@/components/icon";
import {
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

const PAGE_SIZE = 25;

/**
 * Users (主账号): primary identities. Searchable + server-paged
 * (GET /admin/users?q=&page=&page_size=), with disable/enable and password
 * reset. The DTO carries no 2FA flag — TODO(backend): surface two_fa_enabled
 * here; email_verified is shown instead.
 */
export default function AdminUsersPage() {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);

  const usersQuery = useQuery({
    queryKey: ["admin", "users", query, page],
    queryFn: () => adminApi.listUsers(query, page, PAGE_SIZE),
  });

  const [resetTarget, setResetTarget] = useState<{ id: string; label: string } | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [resetError, setResetError] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "users"] });

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      adminApi.updateUserStatus(id, status),
    onSuccess: (_data, vars) => {
      toast(vars.status === "disabled" ? "User disabled." : "User enabled.", "success");
      void invalidate();
    },
    onError: (err) => toast(errMessage(err, "Could not update the user."), "error"),
  });

  const resetMutation = useMutation({
    mutationFn: () => adminApi.resetUserPassword(resetTarget!.id, newPassword),
    onSuccess: () => {
      toast("Password reset — the user must change it at next sign-in.", "success");
      setResetTarget(null);
      setNewPassword("");
      void invalidate();
    },
    onError: (err) => setResetError(errMessage(err, "Could not reset the password.")),
  });

  if (isForbidden(usersQuery.error)) {
    return (
      <>
        <h1 className="text-2xl font-extrabold tracking-tight">Users</h1>
        <div className="mt-6">
          <ForbiddenCard message="Primary identities are platform-only (admin:user:read) — org admins manage workspace accounts instead." />
        </div>
      </>
    );
  }

  const data = usersQuery.data;
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <h1 className="text-2xl font-extrabold tracking-tight">Users</h1>
      <p className="mt-1 text-sm text-white/55">
        Primary identities (Company IDs) — they hold portal credentials but no
        app permissions directly.
      </p>

      <form
        className="mt-6 flex max-w-xl gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setPage(1);
          setQuery(search.trim());
        }}
      >
        <div className="flex-1">
          <Field
            label="Search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="username or email"
            aria-label="Search users"
          />
        </div>
        <div className="flex items-end">
          <Button type="submit" size="md">
            <Icon name="log" className="size-4" /> Search
          </Button>
        </div>
      </form>

      <div className="mt-4">
        {usersQuery.isLoading && <TableSkeleton rows={6} />}
        {usersQuery.isError && (
          <ErrorCard
            message={errMessage(usersQuery.error, "We couldn't load users.")}
            onRetry={() => usersQuery.refetch()}
          />
        )}
        {data && (
          <>
            <Table
              columns={[
                { key: "username", header: "Username", className: "font-mono text-[13px]" },
                { key: "email", header: "Email" },
                { key: "status", header: "Status" },
                { key: "verified", header: "Verified" },
                { key: "created", header: "Created" },
                { key: "last_login", header: "Last login" },
                { key: "actions", header: "", className: "text-right" },
              ]}
              rows={data.items}
              rowKey={(user) => user.id}
              cell={(user, column) => {
                switch (column.key) {
                  case "username":
                    return user.username || "—";
                  case "email":
                    return (
                      <div className="min-w-0">
                        <div className="truncate text-white/85">{user.email}</div>
                        <div className="truncate text-xs text-white/45">
                          {user.nickname}
                        </div>
                      </div>
                    );
                  case "status":
                    return <StatusChip status={user.status} />;
                  case "verified":
                    return user.email_verified ? (
                      <Chip tone="success">Verified</Chip>
                    ) : (
                      <Chip>Unverified</Chip>
                    );
                  case "created":
                    return (
                      <span className="text-white/55">
                        {formatDateTime(user.created_at) ?? "—"}
                      </span>
                    );
                  case "last_login":
                    return (
                      <span className="text-white/55">
                        {formatDateTime(user.last_login_at) ?? "Never"}
                      </span>
                    );
                  case "actions":
                    return (
                      <div className="flex justify-end gap-2">
                        <ConfirmButton
                          size="sm"
                          confirmLabel={
                            user.status === "disabled" ? "Confirm enable" : "Confirm disable"
                          }
                          onConfirm={() =>
                            statusMutation.mutateAsync({
                              id: user.id,
                              status: user.status === "disabled" ? "active" : "disabled",
                            })
                          }
                        >
                          {user.status === "disabled" ? "Enable" : "Disable"}
                        </ConfirmButton>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setResetTarget({ id: user.id, label: user.email || user.username });
                            setNewPassword("");
                            setResetError(null);
                          }}
                        >
                          Reset pw
                        </Button>
                      </div>
                    );
                  default:
                    return null;
                }
              }}
            />

            {data.items.length === 0 ? (
              <Card className="mt-4 p-8 text-center">
                <p className="font-bold">No users match</p>
                <p className="mt-1 text-sm text-white/55">
                  {query
                    ? `Nothing found for “${query}”.`
                    : "No primary identities exist yet."}
                </p>
              </Card>
            ) : (
              <div className="mt-3 flex items-center justify-between gap-3 text-[13px] text-white/55">
                <span>
                  {total.toLocaleString("en-US")} user{total === 1 ? "" : "s"} ·
                  page {data.page} of {pageCount}
                </span>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    Previous
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page >= pageCount}
                    onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Reset password dialog */}
      {resetTarget && (
        <Dialog
          title={`Reset password · ${resetTarget.label}`}
          description="The user must change this password at next sign-in."
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
    </div>
  );
}
