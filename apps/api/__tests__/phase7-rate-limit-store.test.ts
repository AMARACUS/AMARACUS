import express from 'express';
import http from 'http';
import { AddressInfo } from 'net';
import { createRateLimiter, InMemoryRateLimiter, RateLimitStore } from '../src/middleware/rate-limiter';

/** Two app instances sharing one store stand in for two API processes sharing Postgres. */
function startApp(store: RateLimitStore): Promise<{ url: string; server: http.Server }> {
  const app = express();
  app.use(createRateLimiter({ limit: 3, windowMs: 60_000, keyGenerator: () => 'shared-client', store }));
  app.get('/ping', (_req, res) => res.json({ ok: true }));
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server });
    });
  });
}

describe('Phase 7: rate limits in a shared store', () => {
  it('counts requests across instances that share a store', async () => {
    const store = new InMemoryRateLimiter();
    const a = await startApp(store);
    const b = await startApp(store);
    try {
      const statuses = [];
      for (const url of [a.url, b.url, a.url, b.url]) {
        statuses.push((await fetch(`${url}/ping`)).status);
      }
      expect(statuses).toEqual([200, 200, 200, 429]);

      const blocked = await fetch(`${a.url}/ping`);
      expect(blocked.status).toBe(429);
      expect(blocked.headers.get('x-ratelimit-remaining')).toBe('0');
      const body = await blocked.json();
      expect(body.error.code).toBe('RATE_LIMITED');
      expect(body.error.retryAfter).toBeGreaterThan(0);
    } finally {
      a.server.close();
      b.server.close();
    }
  });

  it('passes store errors to the error handler instead of hanging the request', async () => {
    const failing: RateLimitStore = { hit: () => Promise.reject(new Error('store down')) };
    const limiter = createRateLimiter({ store: failing });
    const next = jest.fn();
    await limiter({ ip: '1.2.3.4', headers: {} } as any, { setHeader: jest.fn() } as any, next);
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ message: 'store down' }));
  });

  it('restarts a window once it has passed', async () => {
    const store = new InMemoryRateLimiter();
    expect((await store.hit('k', 20)).count).toBe(1);
    expect((await store.hit('k', 20)).count).toBe(2);
    await new Promise((r) => setTimeout(r, 30));
    expect((await store.hit('k', 20)).count).toBe(1);
  });
});
