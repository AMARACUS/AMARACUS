# ==============================================================================
# AMARACUS Cryptographic API Gateway - Production Multi-Stage Dockerfile
# ==============================================================================

# Stage 1: Build & Bundle
FROM node:20-alpine AS builder

WORKDIR /app

# Install system dependencies needed for native modules & crypto build
RUN apk add --no-cache python3 make g++ git openssl

# Enable pnpm
RUN corepack enable && corepack prepare pnpm@10.22.0 --activate

# Copy root workspace manifests
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./

# Copy packages and API manifests
COPY packages/config/package.json ./packages/config/
COPY packages/types/package.json ./packages/types/
COPY packages/crypto-core/package.json ./packages/crypto-core/
COPY packages/database/package.json ./packages/database/
COPY packages/sdk-ts/package.json ./packages/sdk-ts/
COPY apps/api/package.json ./apps/api/

# Install the API and its workspace dependencies only
RUN pnpm install --frozen-lockfile --filter "api..."

# Copy source code
COPY packages/config ./packages/config
COPY packages/types ./packages/types
COPY packages/crypto-core ./packages/crypto-core
COPY packages/database ./packages/database
COPY packages/sdk-ts ./packages/sdk-ts
COPY apps/api ./apps/api
# Licence texts: a self-hosted API shows them on the activation screen and records their hashes.
COPY LICENSE AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md ./

# Build internal packages (the database build runs prisma generate) and the API.
# No '|| true': a failing package build must fail the image.
RUN pnpm --filter @amaracus/types build
RUN pnpm --filter @amaracus/crypto-core build
RUN pnpm --filter @amaracus/database build
RUN pnpm --filter @amaracus/sdk build
RUN pnpm --filter api build

# Stage 2: Production Distroless/Minimal Runtime
FROM node:20-alpine AS runner

WORKDIR /app

# Install wget for container health probes
RUN apk add --no-cache wget openssl

# Create non-privileged user and group
RUN addgroup -S amaracus && adduser -S amaracus -G amaracus

# Set production environment
ENV NODE_ENV=production
ENV PORT=4000

# Copy application and built artifacts from builder
COPY --from=builder --chown=amaracus:amaracus /app/node_modules ./node_modules
COPY --from=builder --chown=amaracus:amaracus /app/packages ./packages
COPY --from=builder --chown=amaracus:amaracus /app/apps/api ./apps/api
COPY --from=builder --chown=amaracus:amaracus /app/LICENSE /app/AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md ./

WORKDIR /app/apps/api

# Switch to non-root user
USER amaracus

# Expose API service port
EXPOSE 4000

# Container liveness check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:4000/health/live || exit 1

# Start production API server
CMD ["node", "dist/index.js"]
