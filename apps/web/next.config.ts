import type { NextConfig } from "next";

const apiProxyUrl = (
  process.env.FORGESEC_API_PROXY_URL ?? "http://127.0.0.1:8000"
).replace(/\/+$/, "");
const allowedDevOrigins = [
  "localhost",
  "127.0.0.1",
  ...(process.env.FORGESEC_LAN_IP ? [process.env.FORGESEC_LAN_IP] : []),
];

const nextConfig: NextConfig = {
  output: "standalone",
  devIndicators: false,
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
