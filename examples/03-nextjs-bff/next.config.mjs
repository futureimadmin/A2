/** @type {import('next').NextConfig} */
const nextConfig = {
  // grpc native modules run only on the server
  experimental: {
    serverComponentsExternalPackages: ["@grpc/grpc-js", "@grpc/proto-loader"],
  },
};

export default nextConfig;
