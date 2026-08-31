"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Chip } from "@/components/chips";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { Icon } from "@/components/icon";
import { QrCode } from "@/components/qr-code";
import { ErrorCard, SkeletonCard } from "@/components/page-state";
import { PortalShell } from "@/components/portal-shell";
import { useToast } from "@/components/toast";
import { use2faStatus } from "@/hooks/use-2fa-status";
import { useRequireAuth } from "@/hooks/use-require-auth";
import { api, errMessage } from "@/lib/api";
import type { TwoFaEnroll } from "@/lib/types";

type Step = "intro" | "scan" | "confirm" | "backup";

const STEP_LABELS: Record<Exclude<Step, "intro">, number> = {
  scan: 1,
  confirm: 2,
  backup: 3,
};

function copyText(text: string, notify: ReturnType<typeof useToast>) {
  navigator.clipboard
    .writeText(text)
    .then(() => notify("Copied to clipboard.", "success"))
    .catch(() =>
      notify("Couldn't reach the clipboard. Copy it manually instead.", "error"),
    );
}

/** Groups the secret in chunks of four for manual entry, e.g. JBSW Y3DP … */
function formatSecret(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

function downloadBackupCodes(codes: string[]): void {
  const blob = new Blob(
    [
      "access-hub backup codes\n" +
        `Generated ${new Date().toISOString()}\n` +
        "Each code works once, instead of your authenticator app.\n\n" +
        `${codes.join("\n")}\n`,
    ],
    { type: "text/plain" },
  );
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "access-hub-backup-codes.txt";
  anchor.click();
  URL.revokeObjectURL(url);
}

/** Shown when 2FA is enabled: status + disable (password-confirmed). */
function ManagementView() {
  const router = useRouter();
  const toast = useToast();
  const queryClient = useQueryClient();

  const [confirming, setConfirming] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [disabling, setDisabling] = useState(false);

  async function onDisable(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!password) {
      setError("Enter your password to confirm.");
      return;
    }
    setError(null);
    setDisabling(true);
    try {
      await api.disable2fa({ password });
      toast("Two-factor authentication disabled.", "success");
      setPassword("");
      setConfirming(false);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
      await queryClient.invalidateQueries({ queryKey: ["2fa"] });
    } catch (err) {
      setError(errMessage(err, "We couldn't disable two-factor authentication."));
    } finally {
      setDisabling(false);
    }
  }

  return (
    <Card className="p-6 sm:p-8">
      <div className="flex flex-wrap items-start gap-4">
        <span className="grid size-11 flex-none place-items-center rounded-xl bg-[#22C55E]/15 text-[#7CE49F]">
          <Icon name="shield" className="size-5.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
              Two-factor authentication
            </h1>
            <Chip tone="success">
              <Icon name="check-circle" className="size-3.5" /> Enabled
            </Chip>
          </div>
          <p className="mt-1.5 text-sm text-white/55">
            Signing in to the portal requires a one-time code from your
            authenticator app. Each of your backup codes works exactly once, in
            place of the app.
          </p>
        </div>
      </div>

      <div className="mt-7 border-t border-white/10 pt-6">
        {confirming ? (
          <form className="space-y-4" onSubmit={onDisable} noValidate>
            <div className="flex items-start gap-2.5 rounded-lg border border-[#FFAB00]/30 bg-[#FFAB00]/10 px-3.5 py-2.5 text-sm text-[#FFC96B]">
              <Icon name="alert" className="mt-0.5 size-4 flex-none" />
              <span>
                Turning this off means your password alone protects the account
                again. Backup codes stop working.
              </span>
            </div>
            <Field
              label="Confirm with your password"
              name="disable-2fa-password"
              type="password"
              autoComplete="current-password"
              placeholder="Your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={disabling}
              autoFocus
            />
            {error && <ErrorAlert>{error}</ErrorAlert>}
            <div className="flex flex-wrap gap-3">
              <Button type="submit" variant="danger" loading={disabling}>
                Turn off 2FA
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setConfirming(false);
                  setError(null);
                  setPassword("");
                }}
                disabled={disabling}
              >
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-white/55">
              Lost your authenticator app? Use a backup code to sign in, then
              re-enroll from here.
            </p>
            <Button
              variant="danger"
              size="sm"
              onClick={() => setConfirming(true)}
            >
              Disable 2FA
            </Button>
          </div>
        )}
      </div>

      <p className="mt-6 text-center">
        <button
          type="button"
          onClick={() => router.push("/identity")}
          className="text-[13px] font-semibold text-ah-accent hover:text-[#7CD4D4]"
        >
          Back to identity
        </button>
      </p>
    </Card>
  );
}

/** Three-step TOTP enrollment wizard (intro → scan → confirm → backup codes). */
function EnrollWizard() {
  const router = useRouter();
  const toast = useToast();
  const queryClient = useQueryClient();

  const [step, setStep] = useState<Step>("intro");
  const [enroll, setEnroll] = useState<TwoFaEnroll | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [saved, setSaved] = useState(false);

  async function begin() {
    setError(null);
    setEnrolling(true);
    try {
      setEnroll(await api.enroll2fa());
      setStep("scan");
    } catch (err) {
      setError(errMessage(err, "We couldn't start the enrollment. Try again."));
    } finally {
      setEnrolling(false);
    }
  }

  async function confirm(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const trimmed = code.trim();
    if (!trimmed) {
      setError("Enter the 6-digit code from your authenticator app.");
      return;
    }
    setError(null);
    setConfirming(true);
    try {
      const backup = await api.confirm2fa(trimmed);
      if (backup.length === 0) {
        // Tolerate a response without codes: enrollment itself succeeded.
        await finish();
        return;
      }
      setCodes(backup);
      setStep("backup");
    } catch (err) {
      setError(errMessage(err, "That code didn't work. Try again."));
    } finally {
      setConfirming(false);
    }
  }

  async function finish() {
    await queryClient.invalidateQueries({ queryKey: ["me"] });
    await queryClient.invalidateQueries({ queryKey: ["2fa"] });
    toast("Two-factor authentication enabled.", "success");
    router.push("/identity");
  }

  return (
    <Card className="p-6 sm:p-8">
      {step !== "intro" && (
        <p className="mb-4 text-xs font-semibold uppercase tracking-wider text-white/40">
          Setup · step {STEP_LABELS[step]} of 3
        </p>
      )}

      {step === "intro" && (
        <>
          <div className="flex items-center gap-3">
            <span className="grid size-10 flex-none place-items-center rounded-xl bg-ah-accent/15 text-ah-accent">
              <Icon name="shield" className="size-5" />
            </span>
            <div>
              <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
                Enable two-factor authentication
              </h1>
              <p className="mt-0.5 text-sm text-white/55">
                A one-time code on top of your password.
              </p>
            </div>
          </div>

          <ul className="mt-6 space-y-3 text-sm text-white/70">
            {[
              "You'll need an authenticator app — Google Authenticator, 1Password, Authy, or any TOTP app.",
              "After confirming, portal sign-ins ask for a 6-digit code from the app.",
              "We'll generate one-time backup codes for when you don't have your phone.",
            ].map((line) => (
              <li key={line} className="flex items-start gap-2.5">
                <Icon
                  name="check-circle"
                  className="mt-0.5 size-4 flex-none text-ah-accent"
                />
                <span>{line}</span>
              </li>
            ))}
          </ul>

          {error && (
            <div className="mt-5">
              <ErrorAlert>{error}</ErrorAlert>
            </div>
          )}

          <Button
            className="mt-7 w-full py-3 text-[15px]"
            loading={enrolling}
            onClick={() => void begin()}
          >
            Begin setup
          </Button>
          <Button
            variant="ghost"
            className="mt-3 w-full"
            onClick={() => router.push("/identity")}
            disabled={enrolling}
          >
            Not now
          </Button>
        </>
      )}

      {step === "scan" && enroll && (
        <>
          <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
            Scan with your authenticator app
          </h1>
          <p className="mt-1.5 text-sm text-white/55">
            Point your app at this code, or add the secret key manually.
          </p>

          <div className="mt-6 flex justify-center">
            <QrCode value={enroll.otpauth_uri} />
          </div>

          <div className="mt-6 rounded-xl border border-white/15 bg-white/[0.04] p-4">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[13px] font-semibold text-white/90">
                Can&apos;t scan? Enter this secret
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => copyText(enroll.secret, toast)}
              >
                <Icon name="copy" className="size-4" /> Copy
              </Button>
            </div>
            <p className="mt-2 break-all font-mono text-sm tracking-wider text-ah-accent">
              {formatSecret(enroll.secret) || "—"}
            </p>
          </div>

          <Button
            className="mt-7 w-full py-3 text-[15px]"
            onClick={() => {
              setError(null);
              setStep("confirm");
            }}
          >
            Continue
          </Button>
          <Button
            variant="ghost"
            className="mt-3 w-full"
            onClick={() => router.push("/identity")}
          >
            Cancel setup
          </Button>
        </>
      )}

      {step === "confirm" && (
        <>
          <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
            Confirm the setup
          </h1>
          <p className="mt-1.5 text-sm text-white/55">
            Enter the 6-digit code your authenticator app shows for access-hub.
          </p>

          <form className="mt-7 space-y-4" onSubmit={confirm} noValidate>
            <Field
              label="Verification code"
              name="confirm-2fa-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={16}
              placeholder="000000"
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\s+/g, ""))}
              disabled={confirming}
              className="[&_input]:text-center [&_input]:text-lg [&_input]:font-bold [&_input]:tracking-[0.3em]"
            />

            {error && <ErrorAlert>{error}</ErrorAlert>}

            <Button
              type="submit"
              className="w-full py-3 text-[15px]"
              loading={confirming}
              disabled={!code.trim()}
            >
              Verify &amp; enable
            </Button>
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setError(null);
                setCode("");
                setStep("scan");
              }}
              disabled={confirming}
            >
              <Icon name="arrow-left" className="size-4" /> Back to the QR code
            </Button>
          </form>
        </>
      )}

      {step === "backup" && codes.length > 0 && (
        <>
          <div className="flex items-center gap-3">
            <span className="grid size-10 flex-none place-items-center rounded-xl bg-[#22C55E]/15 text-[#7CE49F]">
              <Icon name="check-circle" className="size-5" />
            </span>
            <div>
              <h1 className="text-xl font-extrabold tracking-tight sm:text-2xl">
                Save your backup codes
              </h1>
              <p className="mt-0.5 text-sm text-white/55">
                Each code works once, instead of your authenticator app.
              </p>
            </div>
          </div>

          <div className="mt-5 flex items-start gap-2.5 rounded-lg border border-[#FFAB00]/30 bg-[#FFAB00]/10 px-3.5 py-2.5 text-sm text-[#FFC96B]">
            <Icon name="alert" className="mt-0.5 size-4 flex-none" />
            <span>
              This is the only time these codes are shown. Store them somewhere
              safe before you continue.
            </span>
          </div>

          <div className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {codes.map((backup) => (
              <div
                key={backup}
                className="rounded-lg border border-white/15 bg-white/[0.06] px-3 py-2 text-center font-mono text-[13px] font-semibold tracking-wider"
              >
                {backup}
              </div>
            ))}
          </div>

          <div className="mt-5 flex flex-wrap gap-3">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => copyText(codes.join("\n"), toast)}
            >
              <Icon name="copy" className="size-4" /> Copy all
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => downloadBackupCodes(codes)}
            >
              <Icon name="download" className="size-4" /> Download .txt
            </Button>
          </div>

          <label className="mt-6 flex items-start gap-2.5 text-sm text-white/80">
            <input
              type="checkbox"
              className="mt-0.5 size-4 flex-none accent-ah-accent"
              checked={saved}
              onChange={(e) => setSaved(e.target.checked)}
            />
            I&apos;ve saved my backup codes somewhere safe.
          </label>

          <Button
            className="mt-6 w-full py-3 text-[15px]"
            disabled={!saved}
            onClick={() => void finish()}
          >
            Done
          </Button>
        </>
      )}
    </Card>
  );
}

/**
 * TOTP two-factor enrollment and management. Doubles as the flow page for
 * "Enable" and the management page for "Manage" — when 2FA is already enabled
 * the enrollment wizard is replaced by the management state.
 */
export default function TwoFaPage() {
  const { authed } = useRequireAuth();
  const statusQuery = use2faStatus(authed);

  return (
    <PortalShell width="narrow">
      {statusQuery.isLoading && <SkeletonCard />}
      {statusQuery.isError && (
        <ErrorCard
          message={errMessage(
            statusQuery.error,
            "We couldn't load your two-factor settings.",
          )}
          onRetry={() => statusQuery.refetch()}
        />
      )}
      {statusQuery.data &&
        (statusQuery.data.enabled ? <ManagementView /> : <EnrollWizard />)}
    </PortalShell>
  );
}
