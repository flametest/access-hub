import type { NextConfig } from "next";

// Backend base URL for the /api/v1 proxy rewrite. The browser stays same-origin
// with the portal; Next.js forwards /api/v1/* to the access-hub Go server.
const backend = process.env.ACCESS_HUB_API_URL ?? "http://localhost:8080";

const nextConfig: NextConfig = {
  output: "standalone",
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
};

export default nextConfig;
