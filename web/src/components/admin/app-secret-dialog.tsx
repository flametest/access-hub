"use client";

import { Button } from "@/components/button";
import { Card } from "@/components/card";
import { Dialog } from "@/components/dialog";
import { Field } from "@/components/field";
import { Icon } from "@/components/icon";
import { useToast } from "@/components/toast";

/**
 * One-time reveal of the per-app internal-API secret (header X-App-Key).
 * The plaintext exists only in this render — the backend stores the hash,
 * so closing the dialog loses it forever (rotate to re-issue).
 */
export function AppSecretDialog({
  appKey,
  secret,
  onClose,
}: {
  appKey: string;
  secret: string;
  onClose: () => void;
}) {
  const toast = useToast();
  return (
    <Dialog
      title="Internal API secret"
      description={`Copy the X-App-Key secret for "${appKey}" now — it is never shown again.`}
      onClose={onClose}
    >
      <div className="space-y-4">
        <Card className="border-[#FFAB00]/30 bg-[#FFAB00]/[0.08] p-4">
          <p className="flex items-start gap-2 text-[13px] text-[#FFC96B]">
            <Icon name="alert" className="mt-0.5 size-4 flex-none" />
            This is the only time the secret is visible. Only its hash is
            stored — losing it means rotating to re-issue (the previous secret
            stops working immediately).
          </p>
        </Card>
        <Field
          label="X-App-Key"
          value={secret}
          readOnly
          onFocus={(event) => event.currentTarget.select()}
          className="font-mono text-[13px]"
        />
        <div className="flex justify-end gap-2">
          <Button
            variant="secondary"
            onClick={() => {
              void navigator.clipboard?.writeText(secret);
              toast("Copied to clipboard.", "success");
            }}
          >
            <Icon name="copy" className="size-4" /> Copy
          </Button>
          <Button onClick={onClose}>Done</Button>
        </div>
      </div>
    </Dialog>
  );
}
