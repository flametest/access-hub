"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { StatusChip } from "@/components/chips";
import { ConfirmButton } from "@/components/confirm-button";
import { Dialog } from "@/components/dialog";
import { Field } from "@/components/field";
import { SelectField, TextareaField } from "@/components/form-fields";
import { EffectChip } from "@/components/admin/chips";
import { Icon } from "@/components/icon";
import {
  EmptyCard,
  ErrorCard,
  ForbiddenCard,
} from "@/components/page-state";
import { Table, TableSkeleton } from "@/components/table";
import { useToast } from "@/components/toast";
import { adminApi } from "@/lib/admin/api";
import type { CustomRule, CustomRuleTestResult } from "@/lib/admin/types";
import { errMessage, isForbidden } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

/**
 * Custom rules tab (M6, docs/design.md §12): expr-lang ABAC rules attached to
 * the Casbin matcher — deny + priority evaluation. Includes the inline test
 * panel (POST .../custom-rules/test, dry-run: it never saves) and surfaces
 * the backend's 1400 message inline when an expr fails to compile.
 */
export function CustomRulesTab({ appKey }: { appKey: string }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const rulesQuery = useQuery({
    queryKey: ["admin", "custom-rules", appKey],
    queryFn: () => adminApi.listCustomRules(appKey),
  });

  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<CustomRule | null>(null);
  const [form, setForm] = useState({
    name: "",
    expr: "",
    effect: "deny",
    priority: "100",
    status: "active",
  });
  const [ruleError, setRuleError] = useState<string | null>(null);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "custom-rules", appKey] });

  function resetForm(preset?: Partial<typeof form>) {
    setForm({
      name: "",
      expr: "",
      effect: "deny",
      priority: "100",
      status: "active",
      ...preset,
    });
    setRuleError(null);
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      const body = {
        name: form.name.trim(),
        expr: form.expr.trim(),
        effect: form.effect,
        priority: Number(form.priority) || 0,
        status: form.status,
      };
      return editing
        ? adminApi.updateCustomRule(appKey, editing.id, body)
        : adminApi.createCustomRule(appKey, body);
    },
    onSuccess: () => {
      toast(editing ? "Rule saved." : "Rule created.", "success");
      setCreating(false);
      setEditing(null);
      void invalidate();
    },
    // An invalid expr answers 1400 with the compiler's message — shown inline.
    onError: (err) => setRuleError(errMessage(err, "Could not save the rule.")),
  });

  const deleteMutation = useMutation({
    mutationFn: (rule: CustomRule) => adminApi.deleteCustomRule(appKey, rule.id),
    onSuccess: () => {
      toast("Rule deleted.", "success");
      void invalidate();
    },
    onError: (err) => toast(errMessage(err, "Could not delete the rule."), "error"),
  });

  if (isForbidden(rulesQuery.error)) {
    return (
      <ForbiddenCard message="Custom rules need admin:role:manage (or a dedicated rule code) for this app." />
    );
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-white/55">
          expr-lang ABAC rules evaluated with deny-wins semantics — lower
          priority number = evaluated first. Test expressions without saving
          using the panel on the right.
        </p>
        <Button
          size="sm"
          onClick={() => {
            resetForm();
            setCreating(true);
          }}
        >
          <Icon name="plus" className="size-4" /> New rule
        </Button>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_340px]">
        <div>
          {rulesQuery.isLoading && <TableSkeleton rows={3} />}
          {rulesQuery.isError && (
            <ErrorCard
              message={errMessage(
                rulesQuery.error,
                "We couldn't load custom rules — the M6 endpoints may not be live yet.",
              )}
              onRetry={() => rulesQuery.refetch()}
            />
          )}
          {rulesQuery.data && rulesQuery.data.length === 0 && (
            <EmptyCard
              icon="settings"
              title="No custom rules yet"
              description="Rules add attribute-based conditions (expr-lang) on top of the static RBAC bindings."
            />
          )}
          {rulesQuery.data && rulesQuery.data.length > 0 && (
            <Table
              columns={[
                { key: "name", header: "Name" },
                { key: "effect", header: "Effect" },
                { key: "priority", header: "Priority" },
                { key: "status", header: "Status" },
                { key: "updated", header: "Updated" },
                { key: "actions", header: "", className: "text-right" },
              ]}
              rows={rulesQuery.data}
              rowKey={(rule) => rule.id}
              cell={(rule, column) => {
                switch (column.key) {
                  case "name":
                    return (
                      <div className="min-w-0">
                        <div className="truncate font-bold">{rule.name}</div>
                        <div className="truncate font-mono text-xs text-white/45">
                          {rule.expr}
                        </div>
                      </div>
                    );
                  case "effect":
                    return <EffectChip effect={rule.effect} />;
                  case "priority":
                    return <span className="text-white/70">{rule.priority}</span>;
                  case "status":
                    return <StatusChip status={rule.status} />;
                  case "updated":
                    return (
                      <span className="text-white/55">
                        {formatDateTime(rule.updated_at ?? rule.created_at) ?? "—"}
                      </span>
                    );
                  case "actions":
                    return (
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setEditing(rule);
                            resetForm({
                              name: rule.name,
                              expr: rule.expr,
                              effect: rule.effect,
                              priority: String(rule.priority ?? 0),
                              status: rule.status,
                            });
                          }}
                        >
                          Edit
                        </Button>
                        <ConfirmButton
                          size="sm"
                          confirmLabel="Confirm delete"
                          onConfirm={() => deleteMutation.mutateAsync(rule)}
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

        <TestPanel appKey={appKey} />
      </div>

      {/* Create / edit dialog */}
      {(creating || editing) && (
        <Dialog
          wide
          title={editing ? `Edit ${editing.name}` : "New custom rule"}
          description="expr-lang over the authz request (subject attributes, resource props)."
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
        >
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              setRuleError(null);
              if (!form.name.trim() || !form.expr.trim()) {
                setRuleError("Name and expr are both required.");
                return;
              }
              saveMutation.mutate();
            }}
          >
            <div className="grid gap-4 sm:grid-cols-3">
              <Field
                label="Name"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                className="sm:col-span-2"
                required
              />
              <SelectField
                label="Effect"
                value={form.effect}
                onChange={(event) => setForm({ ...form, effect: event.target.value })}
              >
                <option value="deny">deny</option>
                <option value="allow">allow</option>
              </SelectField>
            </div>
            <TextareaField
              label="Expression"
              monospace
              rows={5}
              value={form.expr}
              onChange={(event) => setForm({ ...form, expr: event.target.value })}
              placeholder={'request.obj == "order:read" && subject.department != null'}
              hint="Invalid expressions are rejected by the backend with its compiler message."
              required
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label="Priority"
                type="number"
                value={form.priority}
                onChange={(event) => setForm({ ...form, priority: event.target.value })}
                hint="Lower runs first."
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
            {ruleError && (
              <p
                role="alert"
                className="rounded-lg border border-[#FF5630]/35 bg-[#FF5630]/10 px-3 py-2 text-[13px] text-[#FF9C86]"
              >
                {ruleError}
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

/** Inline dry-run panel: evaluates an expr against obj/act without saving. */
function TestPanel({ appKey }: { appKey: string }) {
  const [expr, setExpr] = useState("");
  const [obj, setObj] = useState("");
  const [act, setAct] = useState("");
  const [result, setResult] = useState<CustomRuleTestResult | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const testMutation = useMutation({
    mutationFn: () =>
      adminApi.testCustomRule(appKey, {
        expr: expr.trim(),
        obj: obj.trim() || undefined,
        act: act.trim() || undefined,
      }),
    onSuccess: (data) => {
      setResult(data);
      setTestError(null);
    },
    onError: (err) => {
      setResult(null);
      setTestError(errMessage(err, "The test call failed."));
    },
  });

  return (
    <Card className="h-fit p-5">
      <h3 className="font-bold">Test an expression</h3>
      <p className="mt-0.5 text-[13px] text-white/50">
        Dry-run against the rule engine — nothing is saved.
      </p>
      <form
        className="mt-4 space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          setTestError(null);
          setResult(null);
          if (!expr.trim()) {
            setTestError("Write an expression first.");
            return;
          }
          testMutation.mutate();
        }}
      >
        <TextareaField
          label="Expression"
          monospace
          rows={4}
          value={expr}
          onChange={(event) => setExpr(event.target.value)}
          placeholder={'request.obj == "order:read"'}
        />
        <div className="grid grid-cols-2 gap-3">
          <Field
            label="obj (optional)"
            value={obj}
            onChange={(event) => setObj(event.target.value)}
            placeholder="order:read"
          />
          <Field
            label="act (optional)"
            value={act}
            onChange={(event) => setAct(event.target.value)}
            placeholder="GET"
          />
        </div>
        {testError && (
          <p role="alert" className="text-[13px] text-[#FF9C86]">
            {testError}
          </p>
        )}
        {result && (
          <div
            className={`rounded-lg border px-3 py-2.5 text-sm ${
              result.error
                ? "border-[#FF5630]/35 bg-[#FF5630]/10 text-[#FF9C86]"
                : result.allowed
                  ? "border-[#22C55E]/30 bg-[#22C55E]/10 text-[#7CE49F]"
                  : "border-[#FF5630]/35 bg-[#FF5630]/10 text-[#FF9C86]"
            }`}
            role="status"
          >
            {result.error ? (
              <span className="font-mono text-[13px]">{result.error}</span>
            ) : (
              <span className="font-bold">
                {result.allowed ? "Allowed" : "Denied"}
              </span>
            )}
          </div>
        )}
        <Button type="submit" size="sm" loading={testMutation.isPending}>
          <Icon name="refresh" className="size-4" /> Run test
        </Button>
      </form>
    </Card>
  );
}
