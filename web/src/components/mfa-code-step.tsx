"use client";

import { useRef, useState } from "react";
import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Field } from "@/components/field";
import { Icon } from "@/components/icon";
import { api, ApiError, errMessage } from "@/lib/api";
import { applySession } from "@/lib/session";
import type { TokenPair } from "@/lib/types";

/** The challenge (5 min JWT) is spent or invalid — the user must re-authenticate. */
function isChallengeInvalid(err: unknown): boolean {
  if (!(err instanceof ApiError)) return false;
  if (err.status !== 400 && err.status !== 401 && err.status !== 403) {
    return false;
  }
  return (
    /expir/i.test(err.message) || /mfa[\s_-]*token|challenge/i.test(err.message)
  );
}

export interface MfaCodeStepProps {
  /** Short-lived challenge token from the login / social-complete response. */
  mfaToken: string;
  /**
   * Called after `POST /auth/login/2fa` verifies the code AND the returned
   * token pair has been applied (localStorage + `ah.session` cookie) — the
   * caller only decides where to navigate next.
   */
  onVerified: (pair: TokenPair) => void;
  /** The challenge token was rejected as expired/invalid — drop the step. */
  onChallengeExpired?: () => void;
  /** Renders a back/cancel action below the verify button when provided. */
  onBack?: () => void;
  backLabel?: string;
}

/**
 * The second sign-in step shared by password login (/login) and social login
 * (/social/complete): a 6-digit TOTP field (auto-focus, auto-submits at six
 * digits, paste-friendly; backup codes work in the same field) posting
 * `{mfa_token, code}` to `POST /auth/login/2fa`.
 */
export function MfaCodeStep({
  mfaToken,
  onVerified,
  onChallengeExpired,
  onBack,
  backLabel = "Back",
}: MfaCodeStepProps) {
  const [code, setCode] = useState("");
  const [codeError, setCodeError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  // Bumped on every wrong code to replay the shake animation (via remount).
  const [shakeCount, setShakeCount] = useState(0);
  // Sync guard: auto-submit + Enter can race before `verifying` re-renders.
  const verifyingRef = useRef(false);

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
      onVerified(pair);
    } catch (err) {
      if (isChallengeInvalid(err)) {
        onChallengeExpired?.();
      } else {
        setCodeError(errMessage(err, "That code didn't work. Try again."));
        setShakeCount((c) => c + 1);
      }
    } finally {
      verifyingRef.current = false;
      setVerifying(false);
    }
  }

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
          <span className="font-mono">XXXX-XXXX</span>) above instead — it works
          in the same field.
        </p>

        <Button
          type="submit"
          className="w-full py-3 text-[15px]"
          loading={verifying}
          disabled={!code.trim()}
        >
          Verify code
        </Button>
        {onBack && (
          <Button
            type="button"
            variant="ghost"
            className="w-full"
            onClick={onBack}
            disabled={verifying}
          >
            <Icon name="arrow-left" className="size-4" /> {backLabel}
          </Button>
        )}
      </form>
    </Card>
  );
}
