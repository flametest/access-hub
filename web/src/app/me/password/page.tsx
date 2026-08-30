"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { Icon } from "@/components/icon";
import { PortalShell } from "@/components/portal-shell";
import { useToast } from "@/components/toast";
import { api, errMessage } from "@/lib/api";
import { clearSession } from "@/lib/tokens";

/**
 * Change the primary identity password. Per design.md §7/§8 this goes through
 * PATCH /me and revokes every identity-scope session, so the user must sign
 * in again afterwards.
 */
export default function ChangePasswordPage() {
  const router = useRouter();
  const toast = useToast();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!current || !next || !confirm) {
      setError("Fill in all three fields.");
      return;
    }
    if (next.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    if (next !== confirm) {
      setError("New passwords don't match.");
      return;
    }
    if (next === current) {
      setError("The new password must be different from the current one.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      // TODO(backend): confirm PATCH /me password fields once the handler lands.
      await api.updateMe({ password: next, current_password: current });
      toast("Password changed.", "success");
      // Password change revokes all identity sessions — force a fresh sign-in.
      clearSession();
      setDone(true);
      window.setTimeout(() => {
        router.replace("/login");
      }, 1800);
    } catch (err) {
      setError(errMessage(err, "We couldn't change your password."));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <PortalShell width="narrow">
      <Card className="p-6 sm:p-8">
        <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
          Change password
        </h1>
        <p className="mt-1.5 text-sm text-white/55">
          Changing your password signs you out of all devices, including this
          portal.
        </p>

        {done ? (
          <div className="mt-6 flex items-start gap-2.5 rounded-lg border border-[#22C55E]/30 bg-[#22C55E]/10 px-3.5 py-3 text-sm text-[#8FE0AC]">
            <Icon name="check-circle" className="mt-0.5 size-4 flex-none" />
            <span>Password changed. Redirecting you to sign in…</span>
          </div>
        ) : (
          <form className="mt-6 space-y-4" onSubmit={onSubmit} noValidate>
            <Field
              label="Current password"
              name="current-password"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              disabled={submitting}
            />
            <Field
              label="New password"
              name="new-password"
              type="password"
              autoComplete="new-password"
              placeholder="At least 8 characters"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              disabled={submitting}
            />
            <Field
              label="Confirm new password"
              name="confirm-password"
              type="password"
              autoComplete="new-password"
              placeholder="Repeat your new password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={submitting}
            />

            {error && <ErrorAlert>{error}</ErrorAlert>}

            <Button
              type="submit"
              className="w-full py-3 text-[15px]"
              loading={submitting}
            >
              Update password
            </Button>
          </form>
        )}
      </Card>
    </PortalShell>
  );
}
