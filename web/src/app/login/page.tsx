"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { GoogleIcon, MicrosoftIcon } from "@/components/icon";
import { api, errMessage } from "@/lib/api";
import { getAccessToken, setTokens } from "@/lib/tokens";

export default function LoginPage() {
  const router = useRouter();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Already signed in? Straight to the workspaces.
  useEffect(() => {
    if (getAccessToken()) router.replace("/workspaces");
  }, [router]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!identifier.trim() || !password) {
      setError("Enter your email or username and your password.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const tokens = await api.login({
        identifier: identifier.trim(),
        password,
      });
      setTokens(tokens.access_token, tokens.refresh_token);
      router.replace("/workspaces");
    } catch (err) {
      setError(errMessage(err, "We couldn't sign you in."));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthShell>
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
    </AuthShell>
  );
}
