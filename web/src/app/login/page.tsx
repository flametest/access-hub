"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState, type FormEvent } from "react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { ProviderIcon } from "@/components/icon";
import { MfaCodeStep } from "@/components/mfa-code-step";
import { Spinner } from "@/components/spinner";
import { api, errMessage } from "@/lib/api";
import {
  SOCIAL_PROVIDERS,
  socialProviderLabel,
  startSocialAuth,
} from "@/lib/social";
import { applySession, postLoginRedirect, resolveRedirectTarget } from "@/lib/session";
import { getAccessToken } from "@/lib/tokens";

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

  // Social grid busy state: the provider id being redirected to (full-page
  // navigation, so this mostly shows the pressed state while leaving).
  const [pendingProvider, setPendingProvider] = useState<string | null>(null);

  // Already signed in? Honor the SSO `next` target when it validates.
  useEffect(() => {
    if (getAccessToken()) postLoginRedirect(router, next);
  }, [router, next]);

  function startSocial(provider: string) {
    if (pendingProvider) return;
    setPendingProvider(provider);
    // Carry the SSO target through the redirect: only same-origin relative
    // paths can ride along; anything else falls back to the workspace picker.
    const target = resolveRedirectTarget(next);
    const redirect = target?.startsWith("/") ? target : "/workspaces";
    startSocialAuth(provider, redirect, "login");
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
      <MfaCodeStep
        mfaToken={mfaToken}
        onVerified={() => postLoginRedirect(router, next)}
        onChallengeExpired={() => {
          setMfaToken(null);
          setError(
            "Your two-factor challenge expired. Please sign in and try again.",
          );
        }}
        onBack={() => {
          setMfaToken(null);
          setError(null);
        }}
        backLabel="Back to sign in"
      />
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

      <div className="grid grid-cols-2 gap-3" aria-busy={pendingProvider !== null}>
        {SOCIAL_PROVIDERS.map((provider) => (
          <Button
            key={provider.id}
            variant={
              provider.id === "apple"
                ? "apple"
                : provider.id === "facebook"
                  ? "facebook"
                  : "secondary"
            }
            className="w-full px-2 py-2.5"
            disabled={pendingProvider !== null && pendingProvider !== provider.id}
            loading={pendingProvider === provider.id}
            onClick={() => startSocial(provider.id)}
          >
            <ProviderIcon provider={provider.id} className="size-4 flex-none" />
            {socialProviderLabel(provider.id)}
          </Button>
        ))}
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
