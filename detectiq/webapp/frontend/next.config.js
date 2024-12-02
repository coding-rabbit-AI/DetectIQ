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
      // Forward rules to refactored /rules
      {
        source: '/rules/:path*/',
        destination: 'http://127.0.0.1:8000/rules/:path*/',
        basePath: false
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
  // Increase timeouts
  serverOptions: {
    timeout: 600000, // 10 minutes
    keepAliveTimeout: 610000, // Slightly longer than timeout
    headersTimeout: 620000, // Slightly longer than keepAliveTimeout
  },
  // Increase webpack buffer
  webpack: (config) => {
    config.performance = {
      ...config.performance,
      maxAssetSize: 5000000,
      maxEntrypointSize: 5000000,
    };
    return config;
  },
};

module.exports = nextConfig; 