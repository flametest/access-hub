"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip } from "@/components/chips";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { Icon } from "@/components/icon";
import { Initials } from "@/components/initials";
import { useMe } from "@/hooks/use-me";
import { useHasToken } from "@/hooks/use-require-auth";
import { api, errMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { toTokenPair } from "@/lib/normalize";
import { setTokens } from "@/lib/tokens";
import type { AcceptInvitationReq, InvitationPreview } from "@/lib/types";

type Step = "code" | "confirm" | "done";

export default function InvitePage() {
  const router = useRouter();

  const hasToken = useHasToken();
  const { data: me } = useMe(hasToken);

  const [step, setStep] = useState<Step>("code");
  const [code, setCode] = useState("");
  const [preview, setPreview] = useState<InvitationPreview | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [autoSignedIn, setAutoSignedIn] = useState(false);

  /**
   * Anonymous users only need a password when the invite auto-provisions a new
   * Company ID (the API creates the identity and sets this password). Users
   * who are already signed in keep their existing Company ID credentials.
   */
  const needsPassword = Boolean(preview?.auto_provision) && !hasToken;

  async function redeem(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const trimmed = code.trim();
    if (!trimmed) {
      setError("Paste the invitation code from your email.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      setPreview(await api.redeemInvitation(trimmed));
      setStep("confirm");
    } catch (err) {
      setError(
        errMessage(err, "That code didn't work. Double-check it and try again."),
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function accept(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (needsPassword) {
      if (newPassword.length < 8) {
        setError("Choose a password with at least 8 characters.");
        return;
      }
      if (newPassword !== confirmPassword) {
        setError("Passwords don't match.");
        return;
      }
    }
    setError(null);
    setSubmitting(true);
    try {
      const body: AcceptInvitationReq = { code: code.trim() };
      if (needsPassword) body.new_password = newPassword;
      const resp = await api.acceptInvitation(body);
      // Anonymous auto-provision flow may log us in directly.
      const tokens = toTokenPair(resp);
      if (tokens) {
        setTokens(tokens.access_token, tokens.refresh_token);
        setAutoSignedIn(true);
      }
      setStep("done");
    } catch (err) {
      setError(errMessage(err, "We couldn't accept this invitation."));
    } finally {
      setSubmitting(false);
    }
  }

  if (step === "done" && preview) {
    const canGoToWorkspaces = autoSignedIn || hasToken;
    return (
      <AuthShell>
        <Card className="p-8 text-center">
          <div className="mx-auto mb-5 grid size-16 place-items-center rounded-full bg-[#22C55E]/15">
            <Icon name="check-circle" className="size-9 text-[#7CE49F]" />
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight">
            {preview.app_name} is now connected to your Company ID
          </h1>
          <p className="mx-auto mt-2 max-w-sm text-sm text-white/55">
            {canGoToWorkspaces
              ? "Your workspace account is ready. Head to your workspaces to start."
              : "Your Company ID and workspace account were created. Sign in with the password you just set."}
          </p>
          <Button
            className="mt-7 w-full py-3 text-[15px]"
            onClick={() =>
              router.replace(canGoToWorkspaces ? "/workspaces" : "/login")
            }
          >
            {canGoToWorkspaces ? "Go to workspaces" : "Sign in to access-hub"}
          </Button>
        </Card>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <Card className="p-6 sm:p-8">
        {step === "code" ? (
          <>
            <div className="flex items-center gap-3">
              <span className="grid size-10 flex-none place-items-center rounded-xl bg-ah-accent/15 text-ah-accent">
                <Icon name="ticket" className="size-5" />
              </span>
              <div>
                <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
                  Redeem an invitation
                </h1>
                <p className="mt-0.5 text-sm text-white/55">
                  Paste the code from your invite email or link.
                </p>
              </div>
            </div>

            {hasToken && (
              <div className="mt-5 flex items-center gap-2.5 rounded-lg border border-ah-accent/25 bg-ah-accent/[0.08] px-3.5 py-2.5 text-sm text-white/80">
                <Icon name="id" className="size-4 flex-none text-ah-accent" />
                {me ? (
                  <span>
                    Redeeming as{" "}
                    <span className="font-semibold text-white">{me.email}</span>
                  </span>
                ) : (
                  <span>Redeeming with your signed-in Company ID</span>
                )}
              </div>
            )}

            <form className="mt-6 space-y-4" onSubmit={redeem} noValidate>
              <Field
                label="Invitation code"
                name="code"
                type="text"
                placeholder="XXXX-XXXX-XXXX"
                className="[&_input]:text-center [&_input]:text-lg [&_input]:font-bold [&_input]:uppercase [&_input]:tracking-[0.25em]"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                disabled={submitting}
              />
              {error && <ErrorAlert>{error}</ErrorAlert>}
              <Button
                type="submit"
                className="w-full py-3 text-[15px]"
                loading={submitting}
              >
                Continue
              </Button>
            </form>

            <p className="mt-7 text-center text-sm text-white/55">
              No invite yet? Ask a workspace admin to invite you.{" "}
              {!hasToken && (
                <>
                  <br />
                  <button
                    type="button"
                    onClick={() => router.push("/login")}
                    className="mt-1 font-semibold text-ah-accent hover:text-[#7CD4D4]"
                  >
                    Sign in instead
                  </button>
                </>
              )}
            </p>
          </>
        ) : (
          preview && (
            <>
              <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
                Confirm the invitation
              </h1>
              <p className="mt-1.5 text-sm text-white/55">
                {hasToken
                  ? "This invite connects the following workspace to your Company ID."
                  : "Accepting will create your Company ID and link this workspace."}
              </p>

              <div className="mt-5 flex items-center gap-4 rounded-xl border border-white/15 p-4">
                <Initials name={preview.app_name} size="md" />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-bold">{preview.app_name}</div>
                  <div className="mt-0.5 truncate text-[13px] text-white/55">
                    {preview.email || "Workspace email pending"}
                  </div>
                </div>
                <Chip tone="accent">
                  <Icon name="check-circle" className="size-3.5" /> Verified
                </Chip>
              </div>

              <dl className="mt-4 space-y-2 text-sm">
                <div className="flex flex-wrap justify-between gap-2">
                  <dt className="text-white/55">Roles</dt>
                  <dd className="font-semibold">
                    {preview.roles.length > 0
                      ? preview.roles.join(", ")
                      : "To be assigned"}
                  </dd>
                </div>
                {preview.invited_by && (
                  <div className="flex flex-wrap justify-between gap-2">
                    <dt className="text-white/55">Invited by</dt>
                    <dd className="font-semibold">{preview.invited_by}</dd>
                  </div>
                )}
                {formatDate(preview.expires_at) && (
                  <div className="flex flex-wrap justify-between gap-2">
                    <dt className="text-white/55">Valid until</dt>
                    <dd className="font-semibold">
                      {formatDate(preview.expires_at)}
                    </dd>
                  </div>
                )}
              </dl>

              {needsPassword && (
                <div className="mt-6 border-t border-dashed border-white/15 pt-5">
                  <p className="mb-4 text-[13px] text-white/60">
                    Set a password for your new Company ID. You can change it
                    later.
                  </p>
                  <div className="space-y-4">
                    <Field
                      label="New password"
                      name="new-password"
                      type="password"
                      autoComplete="new-password"
                      placeholder="At least 8 characters"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      disabled={submitting}
                    />
                    <Field
                      label="Confirm password"
                      name="confirm-password"
                      type="password"
                      autoComplete="new-password"
                      placeholder="Repeat your password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      disabled={submitting}
                    />
                  </div>
                </div>
              )}

              <div className="mt-6 space-y-3">
                {error && <ErrorAlert>{error}</ErrorAlert>}
                <form onSubmit={accept} noValidate>
                  <Button
                    type="submit"
                    className="w-full py-3 text-[15px]"
                    loading={submitting}
                  >
                    Accept &amp; link account
                  </Button>
                </form>
                <Button
                  variant="ghost"
                  className="w-full"
                  onClick={() => {
                    setError(null);
                    setStep("code");
                  }}
                >
                  Use a different code
                </Button>
              </div>
            </>
          )
        )}
      </Card>
    </AuthShell>
  );
}
