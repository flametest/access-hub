"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Icon } from "@/components/icon";
import { MfaCodeStep } from "@/components/mfa-code-step";
import { Spinner } from "@/components/spinner";
import { api, errMessage } from "@/lib/api";
import { applySession, postLoginRedirect } from "@/lib/session";
import type { PendingInvitation } from "@/lib/types";

/**
 * Landing point of the social provider callback (design.md §12 M5). The
 * backend 302s here with exactly one of:
 * - `?login_code=<code>` — login mode success; exchanged (once) for tokens or
 *   a 2FA challenge via `POST /auth/social/complete`;
 * - `?linked=1` — link mode success (started from /identity);
 * - `?error=<reason>` — failure (not_registered | account_disabled |
 *   already_linked | invalid_state | provider_error).
 * The post-login `next` target may ride along as `next` or `redirect`.
 */

const GENERIC_ERROR = {
  title: "Sign-in failed",
  message: "Something went wrong finishing the sign-in. Please try again.",
};

const ERROR_COPY: Record<string, { title: string; message: string }> = {
  not_registered: {
    title: "No account matches this provider",
    message:
      "No workspace account or registered identity matches this provider email — create a Company ID first or ask for an invite.",
  },
  already_linked: {
    title: "Already linked",
    message: "This provider account is already linked to another Company ID.",
  },
  invalid_state: {
    title: "Sign-in session expired",
    message: "Sign-in session expired, please try again.",
  },
  account_disabled: {
    title: "Account disabled",
    message:
      "This Company ID has been disabled. Contact your workspace admin if you think this is a mistake.",
  },
  provider_error: {
    title: "The provider couldn't finish",
    message:
      "The provider sign-in failed or was cancelled on their side. Please try again.",
  },
};

/** Auto-redirect delay once the pending-invitations strip is shown. */
const AUTO_REDIRECT_MS = 1500;

type Phase =
  | { kind: "completing" }
  | { kind: "mfa"; mfaToken: string }
  | { kind: "invitations"; invitations: PendingInvitation[] }
  | { kind: "linked" }
  | { kind: "error"; title: string; message: string };

function SocialCompleteCard() {
  const router = useRouter();
  const params = useSearchParams();
  const loginCode = params.get("login_code");
  const linked = params.get("linked") !== null;
  const errorReason = params.get("error");
  // The SSO/portal target carried through the `redirect` hop.
  const nextTarget = params.get("next") ?? params.get("redirect");

  const [phase, setPhase] = useState<Phase>(() => {
    if (errorReason) {
      const copy = ERROR_COPY[errorReason] ?? GENERIC_ERROR;
      return { kind: "error", title: copy.title, message: copy.message };
    }
    if (loginCode) return { kind: "completing" };
    if (linked) return { kind: "linked" };
    // No recognizable landing shape: the link is invalid or already used.
    return {
      kind: "error",
      title: "This link has expired",
      message:
        "This sign-in link is invalid or has already been used. Please start again from the sign-in page.",
    };
  });

  // One exchange per mounted page — the login_code is single-use, so guard
  // against effect re-runs (dev StrictMode double-invokes effects).
  const exchangedRef = useRef(false);
  const phaseKind = phase.kind;

  useEffect(() => {
    if (!loginCode || phaseKind !== "completing" || exchangedRef.current) return;
    exchangedRef.current = true;
    void (async () => {
      try {
        const result = await api.socialComplete(loginCode);
        if (result.challenge) {
          setPhase({ kind: "mfa", mfaToken: result.challenge.mfa_token });
          return;
        }
        if (result.pair) {
          applySession(result.pair.access_token, result.pair.refresh_token);
          if (result.pending_invitations.length > 0) {
            // Defer the redirect: show the email-matched invitations first.
            setPhase({
              kind: "invitations",
              invitations: result.pending_invitations,
            });
            return;
          }
          postLoginRedirect(router, nextTarget);
          return;
        }
        setPhase({ kind: "error", ...GENERIC_ERROR });
      } catch (err) {
        setPhase({
          kind: "error",
          title: "Sign-in failed",
          message: errMessage(err, GENERIC_ERROR.message),
        });
      }
    })();
  }, [loginCode, phaseKind, router, nextTarget]);

  // Auto-redirect after the strip has been shown — canceled for good as soon
  // as the user interacts with it (then they navigate via its links/buttons).
  const [redirectDeferred, setRedirectDeferred] = useState(false);
  const inInvitations = phase.kind === "invitations";

  useEffect(() => {
    if (!inInvitations || redirectDeferred) return;
    const timer = window.setTimeout(() => {
      postLoginRedirect(router, nextTarget);
    }, AUTO_REDIRECT_MS);
    return () => window.clearTimeout(timer);
  }, [inInvitations, redirectDeferred, router, nextTarget]);

  function deferRedirect() {
    setRedirectDeferred(true);
  }

  if (phase.kind === "mfa") {
    return (
      <MfaCodeStep
        mfaToken={phase.mfaToken}
        onVerified={() => postLoginRedirect(router, nextTarget)}
        onChallengeExpired={() =>
          setPhase({
            kind: "error",
            title: "Sign-in session expired",
            message:
              "Your two-factor challenge expired. Please start again from the sign-in page.",
          })
        }
        onBack={() => router.replace("/login")}
        backLabel="Back to sign in"
      />
    );
  }

  if (phase.kind === "invitations") {
    return (
      <Card className="p-6 sm:p-8">
        <div className="flex items-center gap-3">
          <span className="grid size-10 flex-none place-items-center rounded-xl bg-[#22C55E]/15 text-[#7CE49F]">
            <Icon name="check-circle" className="size-5" />
          </span>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight">Signed in</h1>
            <p className="mt-0.5 text-sm text-white/55">
              You may have pending invitations.
            </p>
          </div>
        </div>

        <div
          className="mt-5 space-y-2"
          onPointerEnter={deferRedirect}
          onPointerDown={deferRedirect}
          onFocusCapture={deferRedirect}
          onTouchStart={deferRedirect}
        >
          {phase.invitations.map((invitation) => (
            <LinkRow
              key={invitation.app_key ?? invitation.app_name}
              invitation={invitation}
            />
          ))}
        </div>

        <Button
          className="mt-6 w-full py-3 text-[15px]"
          onClick={() => postLoginRedirect(router, nextTarget)}
        >
          Continue
        </Button>
      </Card>
    );
  }

  if (phase.kind === "linked") {
    return (
      <Card className="p-6 sm:p-8 text-center">
        <span className="mx-auto grid size-12 place-items-center rounded-xl bg-[#22C55E]/15 text-[#7CE49F]">
          <Icon name="check-circle" className="size-6" />
        </span>
        <h1 className="mt-4 text-2xl font-extrabold tracking-tight">
          Account linked
        </h1>
        <p className="mt-1.5 text-sm text-white/55">
          Your provider account is now connected to your Company ID — you can
          use it to sign in from now on.
        </p>
        <Button
          className="mt-6 w-full py-3 text-[15px]"
          onClick={() => router.push("/identity")}
        >
          Go to identity
        </Button>
      </Card>
    );
  }

  if (phase.kind === "error") {
    return (
      <Card className="p-6 sm:p-8 text-center">
        <span className="mx-auto grid size-12 place-items-center rounded-xl bg-[#FF5630]/15 text-[#FF9C86]">
          <Icon name="alert" className="size-6" />
        </span>
        <h1 className="mt-4 text-2xl font-extrabold tracking-tight">
          {phase.title}
        </h1>
        <p className="mx-auto mt-1.5 max-w-sm text-sm text-white/55">
          {phase.message}
        </p>
        <Button
          variant="secondary"
          className="mt-6 w-full py-3 text-[15px]"
          onClick={() => router.replace("/login")}
        >
          Back to sign in
        </Button>
      </Card>
    );
  }

  return (
    <Card className="grid min-h-[320px] place-items-center p-6 sm:p-8">
      <div className="flex flex-col items-center gap-3 text-center">
        <Spinner className="size-6 text-ah-accent" />
        <p className="text-sm text-white/55">Finishing sign-in…</p>
      </div>
    </Card>
  );
}

function LinkRow({ invitation }: { invitation: PendingInvitation }) {
  return (
    <Link
      href="/invite"
      className="flex items-center gap-3 rounded-xl border border-white/10 px-4 py-3.5 transition-colors hover:bg-white/[0.04]"
    >
      <span className="grid size-9 flex-none place-items-center rounded-lg bg-ah-accent/15 text-ah-accent">
        <Icon name="ticket" className="size-4.5" />
      </span>
      <span className="min-w-0 flex-1 text-sm text-white/75">
        <span className="font-bold text-white">{invitation.app_name}</span> may
        have a pending invitation for you
      </span>
      <Icon name="chevron-right" className="size-4 flex-none text-white/30" />
    </Link>
  );
}

export default function SocialCompletePage() {
  return (
    <AuthShell>
      <Suspense
        fallback={
          <Card className="grid min-h-[320px] place-items-center p-6 sm:p-8">
            <Spinner className="size-6 text-ah-accent" />
          </Card>
        }
      >
        <SocialCompleteCard />
      </Suspense>
    </AuthShell>
  );
}
