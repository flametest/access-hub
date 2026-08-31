"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { ErrorAlert } from "@/components/error-alert";
import { Field } from "@/components/field";
import { api, errMessage } from "@/lib/api";
import { applySession } from "@/lib/session";

export default function RegisterPage() {
  const router = useRouter();
  const [nickname, setNickname] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!nickname.trim() || !username.trim() || !email.trim()) {
      setError("Fill in your nickname, username, and email.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const tokens = await api.register({
        username: username.trim(),
        email: email.trim(),
        password,
        nickname: nickname.trim(),
      });
      // Registration auto-logs in: the response carries the token pair.
      applySession(tokens.access_token, tokens.refresh_token);
      router.replace("/workspaces");
    } catch (err) {
      setError(errMessage(err, "We couldn't create your account."));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthShell>
      <Card className="p-6 sm:p-8">
        <h1 className="text-2xl font-extrabold tracking-tight">
          Create your Company ID
        </h1>
        <p className="mt-1.5 text-sm text-white/55">
          One identity for every workspace you belong to.
        </p>

        <form className="mt-7 space-y-4" onSubmit={onSubmit} noValidate>
          <Field
            label="Nickname"
            name="nickname"
            type="text"
            autoComplete="nickname"
            placeholder="How teammates see you"
            value={nickname}
            onChange={(e) => setNickname(e.target.value)}
            disabled={submitting}
          />
          <Field
            label="Username"
            name="username"
            type="text"
            autoComplete="username"
            placeholder="jia.tan"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={submitting}
          />
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
          <Field
            label="Password"
            name="password"
            type="password"
            autoComplete="new-password"
            placeholder="At least 8 characters"
            hint="At least 8 characters."
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={submitting}
          />
          <Field
            label="Confirm password"
            name="confirm-password"
            type="password"
            autoComplete="new-password"
            placeholder="Repeat your password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            disabled={submitting}
          />

          {error && <ErrorAlert>{error}</ErrorAlert>}

          <Button type="submit" className="w-full py-3 text-[15px]" loading={submitting}>
            Create account
          </Button>
        </form>

        <p className="mt-7 text-center text-sm text-white/55">
          Already have a Company ID?{" "}
          <Link
            href="/login"
            className="font-semibold text-ah-accent hover:text-[#7CD4D4]"
          >
            Sign in
          </Link>
        </p>
      </Card>
    </AuthShell>
  );
}
