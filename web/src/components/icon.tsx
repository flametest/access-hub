import type { ReactNode, SVGProps } from "react";

/**
 * Small inline stroke-icon set (solar-style, matching the prototype's line
 * icons). Kept offline on purpose: no runtime icon CDN dependency.
 */
const PATHS = {
  grid: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.8" />
    </>
  ),
  id: (
    <>
      <circle cx="12" cy="8" r="3.6" />
      <path d="M5.5 19.5c1.3-3.1 3.7-4.7 6.5-4.7s5.2 1.6 6.5 4.7" />
    </>
  ),
  logout: (
    <>
      <path d="M14.5 4H17a2.5 2.5 0 0 1 2.5 2.5v11A2.5 2.5 0 0 1 17 20h-2.5" />
      <path d="M10 8.5 5.5 12l4.5 3.5" />
      <path d="M5.5 12H15" />
    </>
  ),
  "arrow-left": (
    <>
      <path d="M20 12H4" />
      <path d="m10 6-6 6 6 6" />
    </>
  ),
  "chevron-right": <path d="m9 5 6 7-6 7" />,
  "check-circle": (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m8.5 12.3 2.4 2.4 4.8-5.2" />
    </>
  ),
  lock: (
    <>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="2.2" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
    </>
  ),
  key: (
    <>
      <circle cx="8.5" cy="15.5" r="4" />
      <path d="m11.4 12.6 8.1-8.1" />
      <path d="m15.5 8.5 3 3" />
    </>
  ),
  ticket: (
    <>
      <path d="M4 7.5A1.5 1.5 0 0 1 5.5 6h13A1.5 1.5 0 0 1 20 7.5v2a2.5 2.5 0 0 0 0 5v2a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 16.5v-2a2.5 2.5 0 0 0 0-5z" />
      <path d="M14.5 7v2M14.5 11v2M14.5 15v2" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3.5 19 6v5.5c0 4.4-2.9 7.6-7 9-4.1-1.4-7-4.6-7-9V6z" />
      <path d="m9.2 11.8 2 2 3.8-4.2" />
    </>
  ),
  plus: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 8.5v7M8.5 12h7" />
    </>
  ),
  copy: (
    <>
      <rect x="8.5" y="8.5" width="12" height="12" rx="2.2" />
      <path d="M15.5 8.5V6a2.2 2.2 0 0 0-2.2-2.2H6A2.2 2.2 0 0 0 3.8 6v7.3a2.2 2.2 0 0 0 2.2 2.2h2.5" />
    </>
  ),
  mail: (
    <>
      <rect x="3.5" y="5.5" width="17" height="13" rx="2.2" />
      <path d="m4.5 7.5 7.5 5.5 7.5-5.5" />
    </>
  ),
  alert: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 8v4.5" />
      <path d="M12 15.8h.01" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5" />
      <path d="M12 8h.01" />
    </>
  ),
  x: <path d="m6.5 6.5 11 11m0-11-11 11" />,
  refresh: (
    <>
      <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" />
      <path d="M19.5 4.5v3.6h-3.6" />
    </>
  ),
  download: (
    <>
      <path d="M12 4v10.5" />
      <path d="m7.5 10.5 4.5 4.5 4.5-4.5" />
      <path d="M5 19.5h14" />
    </>
  ),
  building: (
    <>
      <rect x="5" y="4" width="14" height="16.5" rx="1.8" />
      <path d="M9 8h2M13 8h2M9 12h2M13 12h2M10.5 20.5v-3.5h3v3.5" />
    </>
  ),
  layers: (
    <>
      <path d="m12 3.5 8.5 4.7L12 12.9 3.5 8.2z" />
      <path d="m4.5 12.5 7.5 4.2 7.5-4.2" />
      <path d="m4.5 16.5 7.5 4.2 7.5-4.2" />
    </>
  ),
  users: (
    <>
      <circle cx="9.5" cy="8.5" r="3.2" />
      <path d="M3.8 19.5c1.1-2.9 3.2-4.4 5.7-4.4s4.6 1.5 5.7 4.4" />
      <path d="M15.5 5.7a3.2 3.2 0 0 1 0 5.6" />
      <path d="M17.3 15.4c1.4.6 2.4 1.9 3 3.6" />
    </>
  ),
  log: (
    <>
      <path d="M5 4.5h14a1.5 1.5 0 0 1 1.5 1.5v12a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 18V6A1.5 1.5 0 0 1 5 4.5z" />
      <path d="M7 9h7M7 12.5h10M7 16h10" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3.5v2.3M12 18.2v2.3M3.5 12h2.3M18.2 12h2.3M5.9 5.9l1.6 1.6M16.5 16.5l1.6 1.6M18.1 5.9l-1.6 1.6M7.5 16.5l-1.6 1.6" />
    </>
  ),
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  ...rest
}: { name: IconName } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {PATHS[name] as ReactNode}
    </svg>
  );
}

export function GoogleIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 262 262" className={className} aria-hidden="true">
      <path
        fill="#4285f4"
        d="M255.878 133.451c0-10.734-.871-18.567-2.756-26.69H130.55v48.448h71.947c-1.45 12.04-9.283 30.172-26.69 42.356l-.244 1.622 38.755 30.023 2.685.268c24.659-22.774 38.875-56.282 38.875-96.027"
      />
      <path
        fill="#34a853"
        d="M130.55 261.1c35.248 0 64.839-11.605 86.453-31.622l-41.196-31.913c-11.024 7.688-25.82 13.055-45.257 13.055-34.523 0-63.824-22.773-74.269-54.25l-1.531.13-40.298 31.187-.527 1.465C35.393 231.798 79.49 261.1 130.55 261.1"
      />
      <path
        fill="#fbbc05"
        d="M56.281 156.37c-2.756-8.123-4.351-16.827-4.351-25.82 0-8.994 1.595-17.697 4.206-25.82l-.073-1.73L15.26 71.312l-1.335.635C5.077 89.644 0 109.517 0 130.55s5.077 40.905 13.925 58.602z"
      />
      <path
        fill="#eb4335"
        d="M130.55 50.479c24.514 0 41.05 10.589 50.479 19.438l36.844-35.974C195.245 12.91 165.798 0 130.55 0 79.49 0 35.393 29.301 13.925 71.947l42.211 32.783c10.59-31.477 39.891-54.251 74.414-54.251"
      />
    </svg>
  );
}

export function MicrosoftIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 256 256" className={className} aria-hidden="true">
      <path fill="#f1511b" d="M121.666 121.666H0V0h121.666z" />
      <path fill="#80cc28" d="M256 121.666H134.335V0H256z" />
      <path fill="#00adef" d="M121.663 256.002H0V134.336h121.663z" />
      <path fill="#fbbc09" d="M256 256.002H134.335V134.336H256z" />
    </svg>
  );
}

/** Monochrome Apple mark — rendered white on the black provider button. */
export function AppleIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 384 512" className={className} aria-hidden="true">
      <path
        fill="currentColor"
        d="M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z"
      />
    </svg>
  );
}

/** Monochrome Facebook "f" — rendered white on the #1877F2 provider button. */
export function FacebookIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 320 512" className={className} aria-hidden="true">
      <path
        fill="currentColor"
        d="M279.14 288l14.22-92.66h-88.91v-60.13c0-25.35 12.42-50.06 52.24-50.06h40.42V6.26S260.43 0 225.36 0c-73.22 0-121.08 44.38-121.08 124.72v70.62H22.89V288h81.39v224h100.17V288z"
      />
    </svg>
  );
}

/**
 * Brand mark for a social provider id (google | microsoft | facebook | apple),
 * falling back to the generic stroke icon set for anything else (sign-in
 * method keys like password / email / totp).
 */
export function ProviderIcon({
  provider,
  className = "",
}: {
  provider: string;
  className?: string;
}) {
  switch (provider.toLowerCase()) {
    case "google":
      return <GoogleIcon className={className} />;
    case "microsoft":
      return <MicrosoftIcon className={className} />;
    case "facebook":
      return <FacebookIcon className={className} />;
    case "apple":
      return <AppleIcon className={className} />;
    default:
      return <Icon name={methodIcon(provider)} className={className} />;
  }
}

/** Maps a sign-in method key to a generic stroke icon. */
export function methodIcon(method: string): IconName {
  switch (method.toLowerCase()) {
    case "password":
      return "lock";
    case "email":
    case "email_code":
      return "mail";
    case "totp":
    case "2fa":
      return "shield";
    default:
      return "key";
  }
}
