import type { NextConfig } from "next";

const apiProxyUrl = (
  process.env.TELESEC_API_PROXY_URL ?? "http://127.0.0.1:8000"
).replace(/\/+$/, "");
const allowedDevOrigins = [
  "localhost",
  "127.0.0.1",
  ...(process.env.TELESEC_LAN_IP ? [process.env.TELESEC_LAN_IP] : []),
];

const nextConfig: NextConfig = {
  output: "standalone",
  allowedDevOrigins,
  experimental: {
    cpus: 1,
    workerThreads: true,
  },
  async headers() {
    return [
      {
        source: "/downloads/agent/:path*",
        headers: [{ key: "Cache-Control", value: "private, no-store" }],
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${apiProxyUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
