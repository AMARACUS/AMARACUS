// Next.js configuration for a self-hosted AMARACUS installation.
// NEXT_OUTPUT_STANDALONE=true builds a Node server (used by the Docker image); otherwise a static export is built.
// NEXT_PUBLIC_API_URL and NEXT_PUBLIC_APP_URL are read at build time (see src/lib/api-base.ts and src/lib/seo.ts).

// Only used for the dev/build-time /v1 rewrite below. The browser calls NEXT_PUBLIC_API_URL directly.
const API_BACKEND_URL = process.env.API_URL || process.env.API_INTERNAL_URL || 'http://localhost:4000';

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: process.env.NEXT_OUTPUT_STANDALONE === 'true' ? 'standalone' : 'export',
  trailingSlash: true,
  // Disable the built-in image optimisation endpoint.
  images: {
    unoptimized: true,
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()' },
          { key: 'X-XSS-Protection', value: '1; mode=block' },
        ],
      },
    ];
  },
  async rewrites() {
    return [
      { source: '/api/v1/:path*', destination: `${API_BACKEND_URL}/v1/:path*` },
      { source: '/v1/:path*', destination: `${API_BACKEND_URL}/v1/:path*` },
    ];
  },
};

// The public source tree is not obfuscated: the anti-reverse-engineering step of AMARACUS Cloud is left out.
module.exports = nextConfig;
