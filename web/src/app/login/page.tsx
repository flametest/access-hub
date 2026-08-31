"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState, type FormEvent } from "react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { GoogleIcon, Icon, MicrosoftIcon } from "@/components/icon";
import { Spinner } from "@/components/spinner";
import { api, ApiError, errMessage } from "@/lib/api";
import { applySession, postLoginRedirect } from "@/lib/session";
import { getAccessToken } from "@/lib/tokens";

/** The challenge (5 min JWT) is spent or invalid — the user must re-authenticate. */
function isChallengeInvalid(err: unknown): boolean {
  if (!(err instanceof ApiError)) return false;
  if (err.status !== 400 && err.status !== 401 && err.status !== 403) {
    return false;
  }
  return /expir/i.test(err.message) || /mfa[\s_-]*token|challenge/i.test(err.message);
}

function LoginCard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  // Powers the OIDC browser flow: /oauth2/authorize 302s here with `next`.
  const next = searchParams.get("next");

  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Two-factor step: set once step 1 answers with a challenge.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [codeError, setCodeError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  // Bumped on every wrong code to replay the shake animation (via remount).
  const [shakeCount, setShakeCount] = useState(0);
  // Sync guard: auto-submit + Enter can race before `verifying` re-renders.
  const verifyingRef = useRef(false);

  // Already signed in? Honor the SSO `next` target when it validates.
  useEffect(() => {
    if (getAccessToken()) postLoginRedirect(router, next);
  }, [router, next]);

  async function onVerify(value: string) {
    if (!mfaToken || verifyingRef.current) return;
    const trimmed = value.trim();
    if (!trimmed) {
      setCodeError("Enter the 6-digit code from your authenticator app.");
      return;
    }
    setCodeError(null);
    verifyingRef.current = true;
    setVerifying(true);
    try {
      const pair = await api.verify2fa({ mfa_token: mfaToken, code: trimmed });
      applySession(pair.access_token, pair.refresh_token);
      postLoginRedirect(router, next);
    } catch (err) {
      if (isChallengeInvalid(err)) {
        setMfaToken(null);
        setCode("");
        setError(
          "Your two-factor challenge expired. Please sign in and try again.",
        );
      } else {
        setCodeError(errMessage(err, "That code didn't work. Try again."));
        setShakeCount((c) => c + 1);
      }
    } finally {
      verifyingRef.current = false;
      setVerifying(false);
    }
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!identifier.trim() || !password) {
      setError("Enter your email or username and your password.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const result = await api.login({
        identifier: identifier.trim(),
        password,
      });
      if ("mfa_required" in result) {
        setMfaToken(result.mfa_token);
        setCode("");
        setCodeError(null);
        return;
      }
      applySession(result.access_token, result.refresh_token);
      postLoginRedirect(router, next);
    } catch (err) {
      setError(errMessage(err, "We couldn't sign you in."));
    } finally {
      setSubmitting(false);
    }
  }

  if (mfaToken) {
    return (
      <Card className="p-6 sm:p-8">
        <div className="flex items-center gap-3">
          <span className="grid size-10 flex-none place-items-center rounded-xl bg-ah-accent/15 text-ah-accent">
            <Icon name="shield" className="size-5" />
          </span>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight">
              Two-factor authentication
            </h1>
            <p className="mt-0.5 text-sm text-white/55">
              Enter the 6-digit code from your authenticator app.
            </p>
          </div>
        </div>

        <form
          className="mt-7 space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void onVerify(code);
          }}
          noValidate
        >
          {/* Remounting on a wrong code replays the shake and refocuses. */}
          <div
            key={shakeCount}
            className={shakeCount > 0 ? "animate-shake" : undefined}
          >
            <Field
              label="Verification code"
              name="mfa-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              maxLength={16}
              placeholder="000000"
              error={codeError}
              value={code}
              onChange={(e) => {
                const value = e.target.value.replace(/\s+/g, "");
                setCode(value);
                if (codeError) setCodeError(null);
                // Auto-verify a full TOTP value; backup codes submit manually.
                if (/^\d{6}$/.test(value)) void onVerify(value);
              }}
              disabled={verifying}
              className="[&_input]:text-center [&_input]:text-lg [&_input]:font-bold [&_input]:tracking-[0.3em]"
            />
          </div>

          <p className="text-xs text-white/45">
            Lost your device? Enter a backup code (format{" "}
            <span className="font-mono">XXXX-XXXX</span>) above instead — it
            works in the same field.
          </p>

          <Button
            type="submit"
            className="w-full py-3 text-[15px]"
            loading={verifying}
            disabled={!code.trim()}
          >
            Verify code
          </Button>
          <Button
            type="button"
            variant="ghost"
            className="w-full"
            onClick={() => {
              setMfaToken(null);
              setCode("");
              setCodeError(null);
            }}
            disabled={verifying}
          >
            <Icon name="arrow-left" className="size-4" /> Back to sign in
          </Button>
        </form>
      </Card>
    );
  }

  return (
    <Card className="p-6 sm:p-8">
      <h1 className="text-2xl font-extrabold tracking-tight">Sign in</h1>
      <p className="mt-1.5 text-sm text-white/55">
        Use your Company ID — one identity for every workspace.
      </p>

      <form className="mt-7 space-y-4" onSubmit={onSubmit} noValidate>
        <Field
          label="Email or username"
          name="identifier"
          type="text"
          autoComplete="username"
          placeholder="you@company.com"
          value={identifier}
          onChange={(e) => setIdentifier(e.target.value)}
          disabled={submitting}
        />
        <Field
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          placeholder="Your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={submitting}
        />

        <div className="flex justify-end">
          <Link
            href="/forgot-password"
            className="text-[13px] font-semibold text-ah-accent hover:text-[#7CD4D4]"
          >
            Forgot password?
          </Link>
        </div>

        {error && <ErrorAlert>{error}</ErrorAlert>}

        <Button type="submit" className="w-full py-3 text-[15px]" loading={submitting}>
          Sign in
        </Button>
      </form>

      <div className="my-6 flex items-center gap-3.5" aria-hidden="true">
        <span className="h-px flex-1 bg-white/10" />
        <span className="text-xs text-white/40">or continue with</span>
        <span className="h-px flex-1 bg-white/10" />
      </div>

      {/* TODO(M5): social login (Google/Microsoft) per design.md §12. */}
      <div className="space-y-3">
        <span className="block cursor-not-allowed" title="Coming soon">
          <Button variant="secondary" className="w-full py-2.5" disabled>
            <GoogleIcon className="size-4.5" /> Continue with Google
          </Button>
        </span>
        <span className="block cursor-not-allowed" title="Coming soon">
          <Button variant="secondary" className="w-full py-2.5" disabled>
            <MicrosoftIcon className="size-4" /> Continue with Microsoft
          </Button>
        </span>
      </div>

      <p className="mt-7 text-center text-sm text-white/55">
        New to access-hub?{" "}
        <Link
          href="/register"
          className="font-semibold text-ah-accent hover:text-[#7CD4D4]"
        >
          Create account
        </Link>
      </p>
    </Card>
  );
}

function LoginFallback() {
  return (
    <Card className="grid min-h-[420px] place-items-center p-6 sm:p-8">
      <Spinner className="size-6 text-ah-accent" />
    </Card>
  );
}

export default function LoginPage() {
  return (
    <AuthShell>
      <Suspense fallback={<LoginFallback />}>
        <LoginCard />
      </Suspense>
    </AuthShell>
  );
}
