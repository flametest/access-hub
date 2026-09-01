"use client";

import { useEffect, useRef, useState } from "react";
import { Button, type ButtonProps } from "@/components/button";

/**
 * Destructive action with the house inline double-confirm: the first click
 * swaps the button into its "Confirm …" state, the second click fires.
 * Auto-resets after a few seconds of inactivity or when the click lands
 * elsewhere, so a stray confirm never lingers armed.
 */
export function ConfirmButton({
  onConfirm,
  confirmLabel,
  children,
  confirmVariant = "danger",
  resetMs = 4000,
  ...rest
}: Omit<ButtonProps, "onClick"> & {
  onConfirm: () => void | Promise<void>;
  /** Label shown in the armed state, e.g. "Confirm delete". */
  confirmLabel: string;
  confirmVariant?: ButtonProps["variant"];
  resetMs?: number;
}) {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  function arm() {
    setArmed(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setArmed(false), resetMs);
  }

  async function onClick() {
    if (!armed) {
      arm();
      return;
    }
    if (timer.current) clearTimeout(timer.current);
    setArmed(false);
    try {
      setBusy(true);
      await onConfirm();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Button
      {...rest}
      variant={armed ? confirmVariant : rest.variant ?? "secondary"}
      loading={busy}
      disabled={rest.disabled}
      onClick={onClick}
      onBlur={() => setArmed(false)}
    >
      {armed ? confirmLabel : children}
    </Button>
  );
}
