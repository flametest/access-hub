"use client";

import { useEffect, useState } from "react";
import { toDataURL } from "qrcode";

/**
 * Renders a QR code as a canvas data URL on a white tile (scanners need the
 * contrast). Dark ink uses the portal's deep teal instead of pure black.
 */
export function QrCode({
  value,
  size = 216,
  className = "",
}: {
  value: string;
  size?: number;
  className?: string;
}) {
  const [rendered, setRendered] = useState<{
    value: string;
    url: string;
  } | null>(null);
  const [failed, setFailed] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    toDataURL(value, {
      errorCorrectionLevel: "M",
      margin: 2,
      width: size * 2, // 2x for crisp rendering on hi-dpi screens
      color: { dark: "#06302F", light: "#FFFFFF" },
    })
      .then((url) => {
        if (!cancelled) setRendered({ value, url });
      })
      .catch(() => {
        if (!cancelled) setFailed(value);
      });
    return () => {
      cancelled = true;
    };
  }, [value, size]);

  // Only the result for the current value counts; everything else renders
  // as a loading state until the async encoding finishes.
  const url = rendered?.value === value ? rendered.url : null;
  const failedCurrent = failed === value;

  return (
    <div
      className={`grid place-items-center rounded-xl bg-white p-3 shadow-[0_8px_20px_-8px_rgba(0,0,0,0.45)] ${className}`}
    >
      {url ? (
        // Static data URL generated locally by the app; Next/Image is unoptimized.
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={url}
          width={size}
          height={size}
          alt="Authenticator QR code"
          className="block size-auto"
        />
      ) : failedCurrent ? (
        <p className="max-w-[200px] p-4 text-center text-xs font-semibold text-[#334155]">
          Couldn&apos;t render the QR code — use the secret key below instead.
        </p>
      ) : (
        <div
          aria-hidden="true"
          className="animate-pulse rounded-lg bg-slate-200"
          style={{ width: size, height: size }}
        />
      )}
    </div>
  );
}
