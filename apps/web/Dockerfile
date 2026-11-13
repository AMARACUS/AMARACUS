# ==============================================================================
# AMARACUS Cryptographic Enterprise Control Plane (Web) - Production Dockerfile
# ==============================================================================

# Stage 1: Build & Standalone Bundle
FROM node:20-alpine AS builder

WORKDIR /app

# Enable pnpm
RUN corepack enable && corepack prepare pnpm@10.22.0 --activate

# Copy root workspace manifests
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./

# Copy packages and web manifests
COPY packages/config/package.json ./packages/config/
COPY packages/types/package.json ./packages/types/
COPY packages/database/package.json ./packages/database/
COPY apps/web/package.json ./apps/web/

# Install workspace dependencies
RUN pnpm install --frozen-lockfile --filter "web..."

# Copy source files
COPY packages/config ./packages/config
COPY packages/types ./packages/types
COPY packages/database ./packages/database
COPY apps/web ./apps/web

# Build internal packages (the database build runs prisma generate).
# No '|| true': a failing package build must fail the image.
RUN pnpm --filter @amaracus/types build
RUN pnpm --filter @amaracus/database build

# NEXT_PUBLIC_* values are compiled into the browser bundle, so they must be passed at BUILD time:
#   docker build -f apps/web/Dockerfile \
#     --build-arg NEXT_PUBLIC_API_URL=https://api.example.com \
#     --build-arg NEXT_PUBLIC_APP_URL=https://app.example.com .
# (run from the repository root). API_URL is the address the Next.js server uses for its /v1 rewrite.
ARG NEXT_PUBLIC_API_URL=""
ARG NEXT_PUBLIC_APP_URL=""
ARG API_URL=""
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_APP_URL=$NEXT_PUBLIC_APP_URL
ENV API_URL=$API_URL

# Build Next.js application in standalone mode
ENV NEXT_OUTPUT_STANDALONE=true
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm --filter web build

# Stage 2: Production Minimal Web Runtime
FROM node:20-alpine AS runner

WORKDIR /app

# Install wget for health checks
RUN apk add --no-cache wget

# Create non-privileged user and group
RUN addgroup -S nextjs && adduser -S nextjs -G nextjs

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
ENV NEXT_TELEMETRY_DISABLED=1

# Copy public assets and static files
COPY --from=builder /app/apps/web/public ./apps/web/public
COPY --from=builder --chown=nextjs:nextjs /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=nextjs:nextjs /app/apps/web/.next/standalone ./

WORKDIR /app/apps/web

# Switch to non-root user
USER nextjs

# Expose Web port
EXPOSE 3000

# Container health probe
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000/ || exit 1

# Start Next.js standalone server
CMD ["node", "server.js"]
