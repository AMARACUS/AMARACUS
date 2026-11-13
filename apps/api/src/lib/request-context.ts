import { AsyncLocalStorage } from 'async_hooks';
import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';

/**
 * Who made the current request, available to code that has no access to `req`, such as the
 * audit sink the cryptographic runtime calls after an operation.
 */
export interface RequestContext {
  ipAddress?: string;
  userAgent?: string;
  /** Set by auth when the request authenticated with an API key. */
  apiKeyId?: string;
  /** Server-generated, unique per HTTP request; never taken from the client. */
  nonce?: string;
  /** The Idempotency-Key (or X-Idempotency-Key) header, when the client sent one. */
  idempotencyKey?: string;
  /** The parsed request body (read lazily: body parsing runs after this middleware). */
  body?: () => unknown;
}

const storage = new AsyncLocalStorage<RequestContext>();

/** Express middleware. Register after `trust proxy` so `req.ip` is the real client address. */
export function requestContextMiddleware(req: Request, _res: Response, next: NextFunction): void {
  const idem = req.headers['idempotency-key'] || req.headers['x-idempotency-key'];
  storage.run(
    {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string | undefined,
      nonce: crypto.randomUUID(),
      idempotencyKey: typeof idem === 'string' && idem.trim() ? idem.trim() : undefined,
      body: () => req.body,
    },
    next
  );
}

export function currentRequestContext(): RequestContext {
  return storage.getStore() || {};
}
