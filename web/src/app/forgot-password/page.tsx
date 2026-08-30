"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { Icon } from "@/components/icon";
import { api, errMessage } from "@/lib/api";

type Step = "email" | "reset" | "done";

export default function ForgotPasswordPage() {
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [devHintVisible, setDevHintVisible] = useState(true);

  async function sendCode(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!email.trim()) {
      setError("Enter the email on your Company ID.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      await api.sendEmailCode({ email: email.trim(), purpose: "reset" });
      setStep("reset");
    } catch (err) {
      setError(errMessage(err, "We couldn't send the reset code."));
    } finally {
      setSubmitting(false);
    }
  }

  async function resetPassword(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!code.trim()) {
      setError("Enter the code from your email.");
      return;
    }
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      await api.resetPassword({
        email: email.trim(),
        code: code.trim(),
        new_password: newPassword,
      });
      setStep("done");
    } catch (err) {
      setError(errMessage(err, "We couldn't reset your password."));
    } finally {
      setSubmitting(false);
    }
  }

  if (step === "done") {
    return (
      <AuthShell>
        <Card className="p-8 text-center">
          <div className="mx-auto mb-5 grid size-16 place-items-center rounded-full bg-[#22C55E]/15">
            <Icon name="check-circle" className="size-9 text-[#7CE49F]" />
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight">
            Password updated
          </h1>
          <p className="mx-auto mt-2 max-w-xs text-sm text-white/55">
            Your password has been reset. Sign in with your new password.
          </p>
          <Button
            className="mt-7 w-full py-3 text-[15px]"
            onClick={() => {
              window.location.assign("/login");
            }}
          >
            Back to sign in
          </Button>
        </Card>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <Card className="p-6 sm:p-8">
        {step === "email" ? (
          <>
            <h1 className="text-2xl font-extrabold tracking-tight">
              Forgot password?
            </h1>
            <p className="mt-1.5 text-sm text-white/55">
              Enter the email on your Company ID and we&apos;ll send you a reset
              code.
            </p>
            <form className="mt-7 space-y-4" onSubmit={sendCode} noValidate>
              <Field
                label="Email"
                name="email"
                type="email"
                autoComplete="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={submitting}
              />
              {error && <ErrorAlert>{error}</ErrorAlert>}
              <Button
                type="submit"
                className="w-full py-3 text-[15px]"
                loading={submitting}
              >
                Send reset code
              </Button>
            </form>
            <p className="mt-7 text-center text-sm">
              <Link
                href="/login"
                className="font-semibold text-ah-accent hover:text-[#7CD4D4]"
              >
                Back to sign in
              </Link>
            </p>
          </>
        ) : (
          <>
            <h1 className="text-2xl font-extrabold tracking-tight">
              Check your email
            </h1>
            <p className="mt-1.5 text-sm text-white/55">
              We sent a reset code to{" "}
              <span className="font-semibold text-white/80">{email}</span>.
            </p>

            {devHintVisible && (
              <div className="mt-4 flex items-start justify-between gap-3 rounded-lg border border-[#FFAB00]/25 bg-[#FFAB00]/10 px-3.5 py-2.5 text-[13px] text-[#FFC96B]">
                <span>dev mode: the code is printed in the server log</span>
                <button
                  type="button"
                  aria-label="Dismiss hint"
                  onClick={() => setDevHintVisible(false)}
                  className="-m-1 rounded p-1 text-[#FFC96B]/70 hover:bg-[#FFAB00]/15 hover:text-[#FFC96B]"
                >
                  <Icon name="x" className="size-3.5" />
                </button>
              </div>
            )}

            <form className="mt-6 space-y-4" onSubmit={resetPassword} noValidate>
              <Field
                label="Reset code"
                name="code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder="6-digit code"
                className="[&_input]:text-center [&_input]:font-bold [&_input]:tracking-[0.35em]"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                disabled={submitting}
              />
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
                Reset password
              </Button>
            </form>
            <p className="mt-7 text-center text-sm">
              <button
                type="button"
                onClick={() => {
                  setError(null);
                  setStep("email");
                }}
                className="font-semibold text-ah-accent hover:text-[#7CD4D4]"
              >
                Use a different email
              </button>
            </p>
          </>
        )}
      </Card>
    </AuthShell>
  );
}
