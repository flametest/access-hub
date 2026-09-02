import type { NextConfig } from "next";

// Backend base URL for the /api/v1 proxy rewrite. The browser stays same-origin
// with the portal; Next.js forwards /api/v1/* to the access-hub Go server.
const backend = process.env.ACCESS_HUB_API_URL ?? "http://localhost:8080";

const nextConfig: NextConfig = {
  output: "standalone",
  // Inline the backend origin into the client bundle so the portal can vet
  // absolute SSO `next` targets against it (see src/lib/session.ts).
  env: {
    NEXT_PUBLIC_ACCESS_HUB_API_URL: backend,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${backend}/api/v1/:path*`,
      },
    ];
  },
  async headers() {
    // Hardening headers. The CSP intentionally allows inline script/style
    // (Next.js hydration bootstrap) but blocks every external origin: no
    // CDN, no third-party frame/embed surface. Dev needs 'unsafe-eval' for
    // React refresh; the production build omits it.
    const csp = [
      "default-src 'self'",
      `script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; ");
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;
