import http from 'http';
import crypto from 'crypto';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { SESSION_IDLE_TTL_MS, shouldExtendSession } from '../src/lib/session-policy';

const DAY = 24 * 60 * 60 * 1000;

describe('Console sessions: sliding 30-day idle window', () => {
  let server: http.Server;
  let baseUrl: string;
  let userId: string;

  beforeAll(async () => {
    server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const user = await db.createUser({
      email: `sliding-${crypto.randomBytes(6).toString('hex')}@example.com`,
      name: 'Sliding',
      passwordHash: crypto.randomBytes(16).toString('hex'),
    });
    userId = user.id;
  });

  afterAll((done) => {
    server.close(done);
  });

  async function sessionExpiringIn(ms: number) {
    const token = `sess_${crypto.randomBytes(24).toString('hex')}`;
    await db.createSession({ sessionToken: token, userId, expiresAt: new Date(Date.now() + ms) });
    return token;
  }

  const me = (token: string) =>
    fetch(`${baseUrl}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } });

  it('extends a session last used 20 days ago back to 30 days from now', async () => {
    const token = await sessionExpiringIn(10 * DAY);
    expect((await me(token)).status).toBe(200);

    const session = await db.findSessionByToken(token);
    const remaining = new Date(session!.expiresAt).getTime() - Date.now();
    expect(remaining).toBeGreaterThan(SESSION_IDLE_TTL_MS - 60_000);
  });

  it('does not rewrite the expiry on every request (at most once a day)', async () => {
    expect(shouldExtendSession(new Date(Date.now() + SESSION_IDLE_TTL_MS - 60_000))).toBe(false);
    expect(shouldExtendSession(new Date(Date.now() + SESSION_IDLE_TTL_MS - 2 * DAY))).toBe(true);
  });

  it('rejects a session that has been idle for more than 30 days', async () => {
    const token = await sessionExpiringIn(-1000);
    expect((await me(token)).status).toBe(401);
  });

  it('signing out ends the session immediately', async () => {
    const token = await sessionExpiringIn(SESSION_IDLE_TTL_MS);
    await fetch(`${baseUrl}/api/v1/auth/signout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
    expect((await me(token)).status).toBe(401);
  });
});
