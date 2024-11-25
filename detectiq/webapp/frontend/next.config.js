/** @type {import('next').NextConfig} */
const nextConfig = {
  trailingSlash: true,
  async rewrites() {
    return [
      // Handle license requests first (Next.js API routes)
      {
        source: '/api/licenses/:type',
        destination: '/api/licenses/:type',
      },
      // Forward all other API requests to Django with consistent trailing slashes
      {
        source: '/api/:path*/',
        destination: 'http://127.0.0.1:8000/api/:path*/',
        basePath: false
      },
      // Catch-all for API requests without trailing slashes
      {
        source: '/api/:path*',
        destination: 'http://127.0.0.1:8000/api/:path*/',
        basePath: false
      }
    ];
  },
}

module.exports = nextConfig 