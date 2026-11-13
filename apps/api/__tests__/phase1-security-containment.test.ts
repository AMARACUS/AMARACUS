/**
 * Phase 1 recovery regression tests: critical security containment.
 * Each block pins one finding from the recovery audit (SEC-01 … SEC-09).
 */
import { describeCloud, itCloud } from './helpers/edition';
import http from 'http';
import crypto from 'crypto';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import * as runtimeConfig from '../src/lib/runtime-config';

describe('Phase 1 — critical security containment', () => {
  let server: http.Server;
  let baseUrl: string;

  let orgA: any;
  let orgB: any;
  let ownerAToken: string;
  let readOnlyAToken: string;
  let ownerBToken: string;
  let ownerBEmail: string;
  let apiKeyB: string;

  async function makeUser(orgId: string, role: string, activeOrgId = orgId) {
    const email = `${role.toLowerCase()}-${crypto.randomBytes(6).toString('hex')}@phase1.test`;
    const user = await db.createUser({ email, name: role, passwordHash: crypto.randomBytes(16).toString('hex') });
    await db.addMember({ organizationId: orgId, userId: user.id, role: role as any });
    const token = `sess_${crypto.randomBytes(24).toString('hex')}`;
    await db.createSession({ sessionToken: token, userId: user.id, activeOrgId, expiresAt: new Date(Date.now() + 3600_000) });
    return { user, token, email };
  }

  async function call(method: string, path: string, opts: { token?: string; body?: any; headers?: Record<string, string> } = {}) {
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
        ...(opts.headers || {}),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = text;
    }
    return { status: res.status, body: json, headers: res.headers };
  }

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });

    orgA = await db.createOrganization({ name: 'Phase1 Tenant A', slug: `p1-a-${Date.now()}` });
    orgB = await db.createOrganization({ name: 'Phase1 Tenant B', slug: `p1-b-${Date.now()}` });
    for (const org of [orgA, orgB]) {
      await db.upsertBillingSubscription({ organizationId: org.id, plan: 'BUSINESS', status: 'ACTIVE' });
    }

    ownerAToken = (await makeUser(orgA.id, 'OWNER')).token;
    readOnlyAToken = (await makeUser(orgA.id, 'READ_ONLY')).token;
    const ownerB = await makeUser(orgB.id, 'OWNER');
    ownerBToken = ownerB.token;
    ownerBEmail = ownerB.email;

    const rawB = generateAmaracusApiKey('live');
    apiKeyB = rawB.fullKey;
    await db.createApiCredential({
      organizationId: orgB.id,
      name: 'Tenant B full key',
      keyHash: rawB.keyHash,
      prefix: rawB.prefix,
      scopes: ['*'],
    } as any);
  });

  afterAll(async () => {
    jest.restoreAllMocks();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('SEC-01: organization takeover through the control plane', () => {
    it('rejects a foreign user adding themselves to another organization', async () => {
      const res = await call('POST', `/v1/control/organizations/${orgA.id}/members`, {
        token: ownerBToken,
        body: { email: ownerBEmail, role: 'OWNER' },
      });
      expect(res.status).toBe(403);
      expect(await db.getMember(orgA.id, (await db.findUserByEmail(ownerBEmail))!.id)).toBeFalsy();
    });

    it('rejects a foreign user reading or renaming another organization', async () => {
      expect((await call('GET', `/v1/control/organizations/${orgA.id}`, { token: ownerBToken })).status).toBe(403);
      expect(
        (await call('PATCH', `/v1/control/organizations/${orgA.id}`, { token: ownerBToken, body: { name: 'pwned' } })).status
      ).toBe(403);
      expect((await db.findOrgById(orgA.id))!.name).toBe('Phase1 Tenant A');
    });

    it('rejects an API key that targets another organization', async () => {
      const res = await call('GET', '/v1/control/projects', {
        token: apiKeyB,
        headers: { 'x-organization-id': orgA.id },
      });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('TENANT_ACCESS_DENIED');
    });

    it('still lets members manage their own organization', async () => {
      const res = await call('GET', `/v1/control/organizations/${orgA.id}`, { token: ownerAToken });
      expect(res.status).toBe(200);
    });
  });

  describe('SEC-09: role checks on scoped /v1 routes', () => {
    it('denies cryptographic execution to a READ_ONLY member', async () => {
      const res = await call('POST', '/v1/hash', { token: readOnlyAToken, body: { data: 'x' } });
      expect(res.status).toBe(403);
    });

    it('allows cryptographic execution to an OWNER', async () => {
      const res = await call('POST', '/v1/hash', { token: ownerAToken, body: { data: 'x' } });
      expect(res.status).toBe(200);
    });
  });

  describe('SEC-08: /v1/advanced tenant checks and disabled engines', () => {
    it('rejects advanced routes aimed at another organization', async () => {
      const res = await call('GET', '/v1/advanced/zk/circuits', {
        token: ownerBToken,
        headers: { 'x-organization-id': orgA.id },
      });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });

    it('serves advanced routes for the caller’s own organization', async () => {
      expect((await call('GET', '/v1/advanced/zk/circuits', { token: ownerAToken })).status).toBe(200);
    });

    it.each(['/v1/advanced/threshold/keys', '/v1/advanced/mpc/sessions'])('returns 501 for %s', async (path) => {
      const res = await call('POST', path, { token: ownerAToken, body: {} });
      expect(res.status).toBe(501);
    });
  });

  describe('SEC-07: idempotency is scoped per caller and tenant', () => {
    it('does not replay another caller’s response for the same Idempotency-Key', async () => {
      const key = `idem-${crypto.randomUUID()}`;
      const a = await call('POST', '/v1/hash', { token: ownerAToken, body: { data: 'tenant-a' }, headers: { 'Idempotency-Key': key } });
      const b = await call('POST', '/v1/hash', { token: ownerBToken, body: { data: 'tenant-b' }, headers: { 'Idempotency-Key': key } });
      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
      expect(b.headers.get('x-cache')).not.toBe('IDEMPOTENT_REPLAY');
      expect(b.body.data.digest).toBe(crypto.createHash('sha256').update('tenant-b').digest('hex'));
    });

    it('scopes the runtime cache by tenant for body idempotency keys', async () => {
      const key = `body-idem-${crypto.randomUUID()}`;
      await call('POST', '/v1/hash', { token: ownerAToken, body: { data: 'runtime-a', idempotencyKey: key } });
      const b = await call('POST', '/v1/hash', { token: ownerBToken, body: { data: 'runtime-b', idempotencyKey: key } });
      expect(b.body.data.digest).toBe(crypto.createHash('sha256').update('runtime-b').digest('hex'));
    });

    it('still replays for the same caller', async () => {
      const key = `idem-${crypto.randomUUID()}`;
      await call('POST', '/v1/hash', { token: ownerAToken, body: { data: 'same' }, headers: { 'Idempotency-Key': key } });
      const again = await call('POST', '/v1/hash', { token: ownerAToken, body: { data: 'same' }, headers: { 'Idempotency-Key': key } });
      expect(again.headers.get('x-cache')).toBe('IDEMPOTENT_REPLAY');
    });
  });

  describeCloud('SEC-04: /trigger requires a platform admin', () => {
    it.each([
      ['GET', '/trigger'],
      ['POST', '/trigger'],
      ['GET', '/api/trigger/approval'],
      ['POST', '/api/trigger/approval'],
    ])('rejects anonymous %s %s with 401', async (method, path) => {
      expect((await call(method, path, { body: method === 'POST' ? {} : undefined })).status).toBe(401);
    });

    it('rejects an organization owner who is not a platform admin', async () => {
      expect((await call('GET', '/trigger', { token: ownerAToken })).status).toBe(403);
    });

    it('rejects API keys even when they have every scope', async () => {
      expect((await call('GET', '/trigger', { token: apiKeyB })).status).toBe(403);
    });
  });

  describeCloud('SEC-09: platform-admin routes ignore organization roles', () => {
    it('rejects review moderation for an org owner', async () => {
      expect((await call('GET', '/v1/reviews/pending', { token: ownerAToken })).status).toBe(403);
    });

    it('allows a listed platform admin', async () => {
      const prev = process.env.PLATFORM_ADMIN_EMAILS;
      process.env.PLATFORM_ADMIN_EMAILS = ownerBEmail;
      try {
        expect((await call('GET', '/v1/reviews/pending', { token: ownerBToken })).status).toBe(200);
      } finally {
        process.env.PLATFORM_ADMIN_EMAILS = prev;
      }
    });
  });

  describe('SEC-02 / SEC-09: auth responses outside the test runner', () => {
    // With the test-runner switch off, secrets must be present as in production.
    const prevSecret = process.env.UNSUBSCRIBE_SECRET;
    beforeEach(() => {
      process.env.UNSUBSCRIBE_SECRET = 'u'.repeat(40);
    });
    afterEach(() => {
      if (prevSecret === undefined) delete process.env.UNSUBSCRIBE_SECRET;
      else process.env.UNSUBSCRIBE_SECRET = prevSecret;
    });

    it('never returns the reset link', async () => {
      jest.spyOn(runtimeConfig, 'isTestEnv').mockReturnValue(false);
      const res = await call('POST', '/v1/auth/forgot-password', { body: { email: ownerBEmail } });
      expect(res.status).toBe(200);
      expect(res.body.resetLink).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toMatch(/token=/);
    });

    it('gives the same answer for unknown and known emails', async () => {
      jest.spyOn(runtimeConfig, 'isTestEnv').mockReturnValue(false);
      const known = await call('POST', '/v1/auth/forgot-password', { body: { email: ownerBEmail } });
      const unknown = await call('POST', '/v1/auth/forgot-password', { body: { email: `nobody-${Date.now()}@phase1.test` } });
      expect(known.body).toEqual(unknown.body);
    });

    it('disables direct signup that skips email verification', async () => {
      jest.spyOn(runtimeConfig, 'isTestEnv').mockReturnValue(false);
      const res = await call('POST', '/v1/auth/signup', {
        body: { email: `direct-${Date.now()}@phase1.test`, password: 'Sup3r-secret-pass', termsAccepted: true },
      });
      expect(res.status).toBe(404);
    });
  });

  describe('SEC-05 / SEC-03: configuration', () => {
    const SECRET_NAMES = ['AMARACUS_LOCAL_MASTER_KEY', 'API_SECRET', 'AUTH_SECRET', 'UNSUBSCRIBE_SECRET'];
    const ENV_NAMES = [...SECRET_NAMES, 'DATABASE_URL'];
    let saved: Record<string, string | undefined>;

    beforeEach(() => {
      saved = Object.fromEntries(ENV_NAMES.map((n) => [n, process.env[n]]));
      process.env.DATABASE_URL = 'postgresql://localhost:5432/amaracus_test';
    });
    afterEach(() => {
      for (const n of ENV_NAMES) {
        if (saved[n] === undefined) delete process.env[n];
        else process.env[n] = saved[n];
      }
    });

    it('reports every missing secret at startup', () => {
      for (const n of SECRET_NAMES) delete process.env[n];
      const errors = runtimeConfig.validateStartupConfig();
      expect(errors.join('\n')).toMatch(/AMARACUS_LOCAL_MASTER_KEY/);
      expect(errors.join('\n')).toMatch(/API_SECRET/);
      expect(errors.join('\n')).toMatch(/UNSUBSCRIBE_SECRET/);
    });

    it('requires DATABASE_URL, since Postgres is the only store outside tests', () => {
      process.env.AMARACUS_LOCAL_MASTER_KEY = 'm'.repeat(40);
      process.env.API_SECRET = 'x'.repeat(40);
      process.env.UNSUBSCRIBE_SECRET = 'y'.repeat(40);
      delete process.env.DATABASE_URL;
      process.env.APP_URL = 'https://kms.example.com';
      expect(runtimeConfig.validateStartupConfig()).toEqual([expect.stringMatching(/DATABASE_URL is not set/)]);
    });

    it('rejects short secrets', () => {
      process.env.AMARACUS_LOCAL_MASTER_KEY = 'short';
      process.env.APP_URL = 'https://kms.example.com';
      process.env.API_SECRET = 'x'.repeat(40);
      process.env.UNSUBSCRIBE_SECRET = 'y'.repeat(40);
      expect(runtimeConfig.validateStartupConfig()).toEqual([expect.stringMatching(/AMARACUS_LOCAL_MASTER_KEY must be at least/)]);
    });

    it('accepts a complete configuration', () => {
      process.env.AMARACUS_LOCAL_MASTER_KEY = 'm'.repeat(40);
      process.env.API_SECRET = 'x'.repeat(40);
      process.env.UNSUBSCRIBE_SECRET = 'y'.repeat(40);
      // A self-hosted build also needs its own public URL (the public tree is always self-hosted).
      process.env.APP_URL = 'https://kms.example.com';
      expect(runtimeConfig.validateStartupConfig()).toEqual([]);
    });

    it('treats a missing NODE_ENV as production', () => {
      const prev = process.env.NODE_ENV;
      delete process.env.NODE_ENV;
      try {
        runtimeConfig.applyNodeEnvDefault();
        expect(process.env.NODE_ENV).toBe('production');
      } finally {
        process.env.NODE_ENV = prev;
      }
    });
  });

  describe('SEC-06: no default admin account', () => {
    it('does not seed the well-known admin user', async () => {
      expect(await db.findUserById('usr_admin_default')).toBeFalsy();
      expect(await db.findUserByEmail('admin@amaracus.tech')).toBeFalsy();
    });
  });
});
