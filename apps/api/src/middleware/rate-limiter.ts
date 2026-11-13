import { Request, Response, NextFunction } from 'express';
import { prisma } from '@amaracus/database';
import { isTestEnv } from '../lib/runtime-config';

interface RateLimitRecord {
  count: number;
  resetAt: number;
}

/** Counts one request against a fixed window and returns the window's state after counting it. */
export interface RateLimitStore {
  hit(key: string, windowMs: number): Promise<RateLimitRecord>;
}

export class InMemoryRateLimiter implements RateLimitStore {
  private records = new Map<string, RateLimitRecord>();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, record] of this.records.entries()) {
        if (now > record.resetAt) {
          this.records.delete(key);
        }
      }
    }, 60000);
    // Do not hold process open
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  private increment(key: string, windowMs: number): RateLimitRecord {
    const now = Date.now();
    let record = this.records.get(key);

    if (!record || now > record.resetAt) {
      record = { count: 1, resetAt: now + windowMs };
      this.records.set(key, record);
      return { ...record };
    }

    record.count += 1;
    return { ...record };
  }

  public async hit(key: string, windowMs: number): Promise<RateLimitRecord> {
    return this.increment(key, windowMs);
  }

  public check(key: string, limit: number, windowMs: number): { allowed: boolean; remaining: number; resetAt: number } {
    const { count, resetAt } = this.increment(key, windowMs);
    return { allowed: count <= limit, remaining: Math.max(0, limit - count), resetAt };
  }
}

/**
 * Counters in the rate_limit_bucket table, so limits hold across restarts and instances.
 * One atomic upsert per request: a row whose window has passed restarts at 1.
 * Times come from the database clock so every instance agrees on window edges.
 */
export class PostgresRateLimitStore implements RateLimitStore {
  private static readonly SWEEP_INTERVAL_MS = 10 * 60 * 1000;
  private lastSweepAt = 0;

  public async hit(key: string, windowMs: number): Promise<RateLimitRecord> {
    const windowSeconds = windowMs / 1000;
    const rows = await prisma.$queryRaw<{ count: number; resetAt: Date }[]>`
      INSERT INTO "rate_limit_bucket" ("key", "count", "resetAt")
      VALUES (${key}, 1, (now() AT TIME ZONE 'UTC') + make_interval(secs => ${windowSeconds}::float8))
      ON CONFLICT ("key") DO UPDATE SET
        "count" = CASE WHEN "rate_limit_bucket"."resetAt" <= (now() AT TIME ZONE 'UTC')
          THEN 1 ELSE "rate_limit_bucket"."count" + 1 END,
        "resetAt" = CASE WHEN "rate_limit_bucket"."resetAt" <= (now() AT TIME ZONE 'UTC')
          THEN EXCLUDED."resetAt" ELSE "rate_limit_bucket"."resetAt" END
      RETURNING "count", "resetAt"`;
    this.maybeSweep();
    return { count: Number(rows[0].count), resetAt: rows[0].resetAt.getTime() };
  }

  /** Deletes long-expired rows, at most once per interval, without delaying the request. */
  private maybeSweep(): void {
    const now = Date.now();
    if (now - this.lastSweepAt < PostgresRateLimitStore.SWEEP_INTERVAL_MS) return;
    this.lastSweepAt = now;
    prisma.$executeRaw`
      DELETE FROM "rate_limit_bucket" WHERE "resetAt" < (now() AT TIME ZONE 'UTC') - interval '1 hour'`.catch((err) =>
      console.warn('[RateLimiter] Sweeping expired buckets failed:', err?.message || err)
    );
  }
}

export const defaultRateLimiter = new InMemoryRateLimiter();
const postgresRateLimitStore = new PostgresRateLimitStore();

const FALLBACK_LOG_INTERVAL_MS = 60 * 1000;
let lastFallbackLogAt = 0;

/**
 * Postgres outside tests. If the database call fails the request is still limited, by this
 * instance's memory, so an outage neither blocks all traffic nor removes the limits.
 */
async function hitBucket(key: string, windowMs: number): Promise<RateLimitRecord> {
  if (isTestEnv()) return defaultRateLimiter.hit(key, windowMs);
  try {
    return await postgresRateLimitStore.hit(key, windowMs);
  } catch (err: any) {
    const now = Date.now();
    if (now - lastFallbackLogAt > FALLBACK_LOG_INTERVAL_MS) {
      lastFallbackLogAt = now;
      console.error('[RateLimiter] Postgres unavailable, using in-memory limits:', err?.message || err);
    }
    return defaultRateLimiter.hit(key, windowMs);
  }
}

export interface RateLimiterOptions {
  limit?: number;
  windowMs?: number;
  message?: string;
  keyGenerator?: (req: Request) => string;
  /** Overrides where counts are kept; tests use it to exercise the shared-store path. */
  store?: RateLimitStore;
}

/**
 * Who a request counts against: the API key when there is one, else the signed-in user, else the
 * client IP. Counting API-key traffic per key (not per IP) means a stolen key is slowed however
 * many IPs it is used from, and it does not use up the budget of other keys on the same server.
 */
export function defaultCallerKey(req: Request): string {
  const apiKeyId = (req as any).apiKey?.id as string | undefined;
  const caller = apiKeyId ? `key:${apiKeyId}` : req.user?.id || req.ip || 'anonymous';
  return caller + ':' + (req.baseUrl || '') + (req.path || '');
}

/**
 * A ceiling on cryptographic calls per organization per minute, across all of its API keys and
 * users, so a set of stolen keys cannot drain data faster than this. RATE_LIMIT_ORG_PER_MINUTE
 * overrides the default.
 */
export function organizationCryptoLimiter() {
  const configured = Number(process.env.RATE_LIMIT_ORG_PER_MINUTE);
  return createRateLimiter({
    limit: Number.isFinite(configured) && configured > 0 ? configured : 1500,
    windowMs: 60000,
    message: 'Too many cryptographic requests for this organization. Please slow down.',
    keyGenerator: (req) => `org:${req.organizationId || req.ip || 'anonymous'}:crypto`,
  });
}

export function createRateLimiter(options: RateLimiterOptions = {}) {
  const limit = options.limit || 120; // 120 reqs
  const windowMs = options.windowMs || 60000; // 1 minute
  const message = options.message || 'Too many requests. Please slow down.';

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const key = options.keyGenerator ? options.keyGenerator(req) : defaultCallerKey(req);

    let record: RateLimitRecord;
    try {
      record = options.store ? await options.store.hit(key, windowMs) : await hitBucket(key, windowMs);
    } catch (err) {
      next(err);
      return;
    }
    const { count, resetAt } = record;
    const remaining = Math.max(0, limit - count);

    res.setHeader('X-RateLimit-Limit', limit);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(resetAt / 1000));

    if (count > limit) {
      res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message,
          retryAfter: Math.max(0, Math.ceil((resetAt - Date.now()) / 1000)),
        },
      });
      return;
    }

    next();
  };
}

export function payloadSizeLimiter(maxBytes = 1048576) { // 1 MB default
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > maxBytes) {
      res.status(413).json({
        error: {
          code: 'INVALID_INPUT',
          message: `Payload size exceeds the maximum allowed limit of ${maxBytes} bytes (1MB).`,
        },
      });
      return;
    }
    next();
  };
}
