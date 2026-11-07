/**
 * Minimal dependency-free User-Agent parsing for the sessions/devices list.
 * The stored `device` field is the raw UA captured at sign-in; this turns it
 * into the human labels shown per row. Correctness beats coverage: anything
 * unrecognized falls through to "Unknown" and the UI shows the raw UA.
 */

export interface UaInfo {
  browser: string;
  os: string;
  device: "desktop" | "mobile" | "unknown";
}

/** Ordered: later regexes must not shadow earlier matches. */
const BROWSERS: [RegExp, string][] = [
  [/Edg(?:e|A|iOS)?\//, "Edge"],
  [/OPR\/|Opera/, "Opera"],
  [/SamsungBrowser\//, "Samsung Internet"],
  [/Firefox\//, "Firefox"],
  [/Chrome\/|CriOS\//, "Chrome"],
  [/Safari\//, "Safari"],
];

const OSES: [RegExp, string][] = [
  [/Windows NT [\d.]+/, "Windows"],
  [/Mac OS X|Macintosh/, "macOS"],
  [/Android/, "Android"],
  [/[Ii]Phone|[Ii]Pad|iPod/, "iOS"],
  [/CrOS/, "ChromeOS"],
  [/Linux/, "Linux"],
];

/** Mobile-first UA signals; otherwise assume desktop when we know the OS. */
const MOBILE = /Mobile|iPhone|iPod|Android(?!.*Tablet)|iPad.*Mobile/;

export function parseUA(ua: string): UaInfo {
  if (!ua.trim()) {
    return { browser: "Unknown device", os: "", device: "unknown" };
  }
  const browser = BROWSERS.find(([re]) => re.test(ua))?.[1] ?? "Unknown browser";
  const os = OSES.find(([re]) => re.test(ua))?.[1] ?? "";
  let device: UaInfo["device"] = "unknown";
  if (MOBILE.test(ua) || /iPhone|iPod/.test(ua)) {
    device = "mobile";
  } else if (os) {
    device = "desktop";
  }
  return { browser, os, device };
}

/** "Chrome · Windows" (or whichever parts are known). */
export function uaLabel(ua: string): string {
  const { browser, os } = parseUA(ua);
  return [browser, os].filter(Boolean).join(" · ");
}
