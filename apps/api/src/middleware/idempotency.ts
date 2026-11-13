import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

const SECRET_BEARING_PATH = /(decrypt|unwrap|decapsulate|encapsulate|agreement|derive|generate-key|keygen|keypair)/i;

function getCallerScope(req: Request): string | null {
  const authHeader = req.headers.authorization;
  let credential: string | undefined;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    credential = authHeader.substring(7).trim();
  } else if (req.cookies) {
    credential = req.cookies.sessionToken || req.cookies['better-auth.session_token'];
  }
  if (!credential) return null;
  return crypto.createHash('sha256').update(credential).digest('hex');
}

interface CachedResponse {
  status: 'IN_PROGRESS' | 'COMPLETED';
  statusCode: number;
  headers: Record<string, string>;
  body: any;
  createdAt: number;
  expiresAt: number;
}

// In-memory idempotency cache (TTL: 24 hours)
const idempotencyStore = new Map<string, CachedResponse>();

// Clean up expired entries every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of idempotencyStore.entries()) {
    if (entry.expiresAt <= now) {
      idempotencyStore.delete(key);
    }
  }
}, 30 * 60 * 1000).unref();

/**
 * Middleware that provides idempotent request execution for mutations (POST, PUT, PATCH, DELETE).
 * Honors the standard 'Idempotency-Key' HTTP header.
 */
export function idempotencyMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Only apply to state-modifying HTTP methods
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return next();
  }

  const rawKey = req.headers['idempotency-key'] || req.headers['x-idempotency-key'];
  if (!rawKey || typeof rawKey !== 'string' || rawKey.trim().length === 0) {
    return next();
  }

  // Responses that carry plaintext or secret material are never cached.
  const fullPath = req.baseUrl + req.path;
  if (SECRET_BEARING_PATH.test(fullPath)) {
    return next();
  }

  // This middleware runs before authentication, so the cache is scoped to the
  // caller's credential. Requests without one are not cached at all.
  const callerScope = getCallerScope(req);
  if (!callerScope) {
    return next();
  }

  const idempotencyKey = rawKey.trim();
  const cacheKey = `${callerScope}:${req.method}:${fullPath}:${idempotencyKey}`;
  const requestId = (req as any).requestId;
  const now = Date.now();
  const ttlMs = 24 * 60 * 60 * 1000; // 24 hours

  const cached = idempotencyStore.get(cacheKey);

  if (cached && cached.expiresAt > now) {
    if (cached.status === 'IN_PROGRESS') {
      res.status(409).json({
        error: {
          code: 'CONFLICT',
          message: 'A request with this Idempotency-Key is currently in progress. Please retry shortly.',
          requestId,
        },
      });
      return;
    }

    // Replay completed response
    res.setHeader('X-Cache', 'IDEMPOTENT_REPLAY');
    res.setHeader('Idempotency-Key', idempotencyKey);
    for (const [hName, hVal] of Object.entries(cached.headers)) {
      if (!res.hasHeader(hName)) {
        res.setHeader(hName, hVal);
      }
    }
    res.status(cached.statusCode).send(cached.body);
    return;
  }

  // Mark request in-progress
  idempotencyStore.set(cacheKey, {
    status: 'IN_PROGRESS',
    statusCode: 200,
    headers: {},
    body: null,
    createdAt: now,
    expiresAt: now + ttlMs,
  });

  // Intercept response finish
  const originalSend = res.send.bind(res);
  const originalJson = res.json.bind(res);

  res.send = (body: any): Response => {
    // Only cache successful or client error mutations, not 500 internal errors
    if (res.statusCode < 500) {
      idempotencyStore.set(cacheKey, {
        status: 'COMPLETED',
        statusCode: res.statusCode,
        headers: {
          'content-type': res.getHeader('content-type') as string || 'application/json',
        },
        body,
        createdAt: now,
        expiresAt: now + ttlMs,
      });
    } else {
      idempotencyStore.delete(cacheKey);
    }
    return originalSend(body);
  };

  res.json = (body: any): Response => {
    if (res.statusCode < 500) {
      idempotencyStore.set(cacheKey, {
        status: 'COMPLETED',
        statusCode: res.statusCode,
        headers: {
          'content-type': 'application/json',
        },
        body,
        createdAt: now,
        expiresAt: now + ttlMs,
      });
    } else {
      idempotencyStore.delete(cacheKey);
    }
    return originalJson(body);
  };

  next();
}

/**
 * Clear test cache helper
 */
export function clearIdempotencyCache(): void {
  idempotencyStore.clear();
}
