/// <reference path="./types/express.d.ts" />
import 'reflect-metadata';
import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';
const isTestRunner = process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID !== undefined;
const originalNodeEnv = process.env.NODE_ENV;
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });
dotenv.config();
if (isTestRunner && originalNodeEnv) {
  process.env.NODE_ENV = originalNodeEnv;
}
import { applyNodeEnvDefault, validateStartupConfig, resolveTrustProxyHops } from './lib/runtime-config';
applyNodeEnvDefault();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

import authRoutes from './routes/auth';
import userRoutes from './routes/user';
import organizationsRoutes from './routes/organizations';
import projectsRoutes from './routes/projects';
import environmentsRoutes from './routes/environments';
import credentialsRoutes from './routes/credentials';
import auditRoutes from './routes/audit';
import emailRouter from './routes/v1/email';
import cryptoRoutes from './routes/crypto';
import keysRoutes from './routes/keys';
import byokRoutes from './routes/byok';
import pkiRoutes from './routes/pki';
import uploadsRoutes from './routes/uploads';
import intelligenceRoutes from './routes/intelligence';
import { advancedCryptoRouter } from './routes/advanced-crypto';
import { v1Router } from './routes/v1';
import { idempotencyMiddleware } from './middleware/idempotency';
import { usageTracker } from './middleware/usage-tracker';
import { metricsExporter } from './lib/metrics-exporter';
import { db } from './lib/data-store';
import { managedOperationQueue } from './lib/managed-operation-queue';
import { sanitizeRequestMiddleware } from './middleware/sanitize';
import { requestContextMiddleware } from './lib/request-context';
import { getEdition, loadCloudModule } from './lib/edition';
import selfHostRouter from './routes/v1/selfhost';

// AMARACUS Cloud only (billing, payment webhooks, hosted-site features). Null when self-hosted.
const cloud = loadCloudModule();

const app = express();
// Behind Render (and Cloudflare): let req.ip be the client, not the proxy. See runtime-config.
app.set('trust proxy', resolveTrustProxyHops());
// Makes the client IP available to audit entries written outside the route handlers.
app.use(requestContextMiddleware);

const isProduction = process.env.NODE_ENV === 'production';
// The hosted service's own origins. A self-hosted installation allows only APP_URL and
// CORS_ALLOWED_ORIGINS.
const DEFAULT_ALLOWED_ORIGINS: string[] = cloud ? cloud.CLOUD_ALLOWED_ORIGINS : [];
const allowedOrigins = Array.from(
  new Set([
    ...DEFAULT_ALLOWED_ORIGINS,
    ...(process.env.CORS_ALLOWED_ORIGINS || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  ])
);

app.use(
  helmet({
    contentSecurityPolicy: false, // Managed per-frontend app or disabled for headless API JSON responses
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hsts: isProduction
      ? {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true,
        }
      : false,
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
  })
);

app.use(
  cors({
    origin: (origin, callback) => {
      // 1. Allow server-to-server, curl, mobile native requests without Origin header
      if (!origin) {
        return callback(null, true);
      }

      const lowerOrigin = origin.toLowerCase();

      // 2. Allow local development ports (e.g. Next.js on 3000, 3001, etc.)
      if (!isProduction && (lowerOrigin.startsWith('http://localhost:') || lowerOrigin.startsWith('http://127.0.0.1:'))) {
        return callback(null, true);
      }

      // 3. Allow explicitly configured origins from CORS_ALLOWED_ORIGINS
      if (allowedOrigins.includes(lowerOrigin)) {
        return callback(null, true);
      }

      // 4. Match APP_URL or NEXT_PUBLIC_APP_URL
      const appUrl = process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL;
      if (appUrl) {
        try {
          const parsed = new URL(appUrl);
          if (lowerOrigin === parsed.origin.toLowerCase()) {
            return callback(null, true);
          }
        } catch {
          // ignore parsing error
        }
      }

      // 5. In non-production, allow with warning to prevent dev disruption
      if (!isProduction) {
        return callback(null, true);
      }

      // 6. Block untrusted origins in production
      return callback(new Error(`CORS blocked for unauthorized origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Request-Id',
      'X-Api-Key',
      'X-Organization-Id',
      'x-organization-id',
      'X-Idempotency-Key',
      'X-Webhook-Secret',
      'stripe-signature',
      'webhook-id',
      'webhook-timestamp',
      'webhook-signature',
      'x-razorpay-signature',
      'paddle-signature',
      'x-signature',
    ],
  })
);

app.use(cookieParser());
app.use(
  express.json({
    limit: '20mb',
    verify: (req: any, _res, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(express.urlencoded({ limit: '20mb', extended: true }));
app.use(sanitizeRequestMiddleware());

let isShuttingDown = false;

// Request correlation ID and HTTP metrics middleware
app.use((req, res, next) => {
  const reqId = (req.headers['x-request-id'] as string) || `req_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  (req as any).requestId = reqId;
  res.setHeader('x-request-id', reqId);

  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    metricsExporter.recordHttpRequest(req.method, res.statusCode, duration);
  });

  next();
});

// Phase 17 Production Health Probes
// Kubernetes Liveness Probe: Verifies process is alive and responsive
app.get('/health/live', (req, res) => {
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    service: 'amaracus-api',
    uptimeSeconds: Math.floor(process.uptime()),
  });
});

// Kubernetes Readiness Probe: Verifies DB connectivity and worker health
app.get('/health/ready', async (req, res) => {
  if (isShuttingDown) {
    return res.status(503).json({
      status: 'terminating',
      ready: false,
      message: 'Server is currently draining connections for shutdown',
    });
  }

  try {
    const isDbConnected = await db.pingDatabase();
    const queueStatus = managedOperationQueue.getQueueMetrics();

    return res.status(isDbConnected ? 200 : 503).json({
      status: isDbConnected ? 'ready' : 'database_unavailable',
      ready: isDbConnected,
      timestamp: new Date().toISOString(),
      service: 'amaracus-api',
      version: '1.0.0',
      database: db.isMemoryMode() ? 'memory' : isDbConnected ? 'connected' : 'unavailable',
      queue: {
        depth: queueStatus.depth,
        activeWorkers: queueStatus.activeWorkers,
      },
    });
  } catch (err: any) {
    return res.status(503).json({
      status: 'unhealthy',
      ready: false,
      error: err.message,
    });
  }
});

// Prometheus text format metrics exposition. Only for a scraper holding METRICS_TOKEN; without
// the variable the route does not exist, so process details are not public reconnaissance.
app.get('/metrics', (req, res) => {
  const token = process.env.METRICS_TOKEN;
  const presented = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const valid =
    !!token &&
    presented.length === token.length &&
    crypto.timingSafeEqual(Buffer.from(presented), Buffer.from(token));
  if (!valid) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found.' } });
    return;
  }
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(metricsExporter.generatePrometheusMetrics());
});

// Standard health check alias
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'amaracus-api',
    version: '1.0.0',
  });
});

// Mount Phase 3, 4 & 5 routes (Web Console / Session-based) under both /v1 and /api/v1
const mountDual = (path: string, ...handlers: any[]) => {
  app.use(`/v1${path}`, ...handlers);
  app.use(`/api/v1${path}`, ...handlers);
};

mountDual('/auth', authRoutes);
mountDual('/user', userRoutes);
mountDual('/email', emailRouter);
mountDual('/organizations', organizationsRoutes);
mountDual('/organizations/:orgId/projects', projectsRoutes);
mountDual('/organizations/:orgId/projects/:projectId/environments', environmentsRoutes);
mountDual('/organizations/:orgId/credentials', credentialsRoutes);
mountDual('/organizations/:orgId/audit', auditRoutes);
mountDual('/organizations/:orgId/crypto', cryptoRoutes);
mountDual('/organizations/:orgId/keys', keysRoutes);
mountDual('/organizations/:orgId/byok', byokRoutes);
// Phase 7 PKI & Certificate Management endpoints
mountDual('/organizations/:orgId/pki', pkiRoutes);
// Secure File Uploads endpoints (Strict type, size, and isolated non-executable storage)
mountDual('/organizations/:orgId/uploads', uploadsRoutes);
// Phase 8 Crypto Intelligence & CBOM endpoints
mountDual('/organizations/:orgId/intelligence', intelligenceRoutes);
mountDual('/organizations/:orgId/crypto/intelligence', intelligenceRoutes);
// Phase 9 Advanced Cryptography (ZK, FHE, MPC, Threshold) endpoints
mountDual('/organizations/:orgId/advanced', advancedCryptoRouter);
mountDual('/organizations/:orgId/crypto/advanced', advancedCryptoRouter);
// AMARACUS Cloud: billing, payment webhooks and Trigger.dev agent routes.
if (cloud) cloud.mountCloudAppRoutes(app, mountDual);

// Self-hosted: licence acceptance, licence keys and the local usage ledger. On Cloud these
// routes do not exist (404), which is how the web console tells the two editions apart.
if (getEdition() === 'selfhosted') mountDual('/selfhost', selfHostRouter);

// Mount Phase 10 & 12 Universal Public Developer API (/v1 and /api/v1)
app.use('/api/v1', idempotencyMiddleware, usageTracker, v1Router);
app.use('/v1', idempotencyMiddleware, usageTracker, v1Router);

// Centralized error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[API Error]:', err);
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : (err.status || err.statusCode || 500);
  // Unexpected 500s (Prisma errors included) never echo internals to the client.
  const exposeDetails = status !== 500;
  res.status(status).json({
    error: {
      code: exposeDetails ? err.code || 'INTERNAL_ERROR' : 'INTERNAL_ERROR',
      message: exposeDetails ? err.message || 'An internal error occurred' : 'An internal error occurred',
      requestId,
    },
  });
});

import { isResendConfigured } from './lib/email-service';
import { loadPlatformMasterKey } from '@amaracus/crypto-core';

const PORT = process.env.PORT || 4000;
let server: any;

if (process.env.NODE_ENV !== 'test' && !isTestRunner) {
  const configErrors = validateStartupConfig();
  if (configErrors.length > 0) {
    console.error('[Amaracus API] Refusing to start: invalid configuration.');
    for (const e of configErrors) console.error(`  - ${e}`);
    process.exit(1);
  }

  // A sealed master key is unwrapped by Azure Key Vault before any request is served.
  loadPlatformMasterKey()
    .then((mode) => {
      console.log(`[Amaracus API] Platform master key: ${mode === 'sealed' ? 'unsealed via Azure Key Vault' : 'plain environment variable'}`);
      server = app.listen(PORT, () => {
        console.log(`[Amaracus API] listening on http://localhost:${PORT}`);
        console.log(`[Amaracus API] Edition: ${getEdition()}`);
        if (cloud) cloud.onCloudListen();
        console.log(`[Amaracus API] Email provider: ${isResendConfigured() ? 'Resend HTTPS API' : 'SMTP'}`);
      });
    })
    .catch((err) => {
      console.error('[Amaracus API] Refusing to start: the platform master key could not be unsealed.', err?.message || err);
      process.exit(1);
    });

  const gracefulShutdown = async (signal: string) => {
    console.log(`\n[Amaracus API] Received ${signal}. Initiating graceful shutdown...`);
    isShuttingDown = true;

    if (server) {
      server.close(async () => {
        console.log('[Amaracus API] Closed HTTP listener. Draining tasks and resources...');
        try {
          await managedOperationQueue.shutdown();
          console.log('[Amaracus API] Background queues drained cleanly.');
          process.exit(0);
        } catch (err) {
          console.error('[Amaracus API] Error during graceful shutdown cleanup:', err);
          process.exit(1);
        }
      });
    } else {
      process.exit(0);
    }

    // Force exit if draining exceeds 15 seconds
    setTimeout(() => {
      console.error('[Amaracus API] Graceful shutdown deadline exceeded (15s). Forcing termination.');
      process.exit(1);
    }, 15000).unref();
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

export { app, server };
export default app;
