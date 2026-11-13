/**
 * Fixes from the November 2026 breach drill (docs/recovery/breach-drill-2026-11.md):
 *   1. /v1/decrypt checks the AAD the caller expects against the envelope's.
 *   3. Crypto rate limits count per API key, under a per-organization ceiling.
 *   4. Decrypts are audited with the caller's IP, the audit log pages back, and a burst of
 *      decrypts by one key raises an alert.
 * (Fix 2, the console's encrypt-only default, is a web change.)
 */
import 'reflect-metadata';
import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import type { Express } from 'express';

// Read when the crypto routes are loaded, so set before requiring the app.
process.env.RATE_LIMIT_ORG_PER_MINUTE = '350';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { app } = require('../src/index') as { app: Express };
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { db } = require('../src/lib/data-store');
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { generateAmaracusApiKey } = require('../src/lib/api-keys');
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { getSentEmailsHistory, clearSentEmailsHistory } = require('../src/lib/email-service');
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { resetDecryptAlertCounters } = require('../src/lib/decrypt-alerts');

jest.setTimeout(120000);

let server: http.Server;
let baseUrl: string;

async function call(apiKeyOrToken: string, method: string, urlPath: string, body?: any, orgId?: string) {
  const res = await fetch(`${baseUrl}${urlPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKeyOrToken}`,
      ...(orgId ? { 'X-Organization-Id': orgId } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as any };
}

/** An organization with an owner session, a managed AES key and API keys with the given scopes. */
async function tenant(keyScopes: string[][]) {
  const tag = crypto.randomUUID().slice(0, 8);
  const org = await db.createOrganization({ name: `drill ${tag}`, slug: `drill-${tag}` });
  const project = await db.createProject({ organizationId: org.id, name: 'p', slug: `p-${tag}` });
  const env = await db.createEnvironment({ projectId: project.id, name: 'prod', slug: 'prod', type: 'PRODUCTION' });
  await db.upsertBillingSubscription({ organizationId: org.id, plan: 'BUSINESS', status: 'ACTIVE' });
  const owner = await db.createUser({ email: `owner-${tag}@drill.example`, name: 'Owner', passwordHash: 'x' });
  await db.addMember({ organizationId: org.id, userId: owner.id, role: 'OWNER' });
  const session = `sess_${crypto.randomUUID()}`;
  await db.createSession({ sessionToken: session, userId: owner.id, activeOrgId: org.id, expiresAt: new Date(Date.now() + 3600_000) });

  const keys: { id: string; key: string }[] = [];
  for (const scopes of keyScopes) {
    const gen = generateAmaracusApiKey('live');
    const cred = await db.createApiCredential({
      organizationId: org.id,
      projectId: project.id,
      environmentId: env.id,
      name: `key-${scopes.join('+')}`,
      prefix: gen.prefix,
      keyHash: gen.keyHash,
      scopes,
    });
    keys.push({ id: cred.id, key: gen.fullKey });
  }
  const created = await call(keys[0].key, 'POST', '/v1/keys', { name: 'customer-data', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
  if (created.status !== 201) {
    // Keys may lack keys:create; fall back to the owner session.
    const viaSession = await call(session, 'POST', '/v1/keys', { name: 'customer-data', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' }, org.id);
    expect(viaSession.status).toBe(201);
    return { org, session, keys, keyId: viaSession.body.data.id as string, ownerEmail: owner.email };
  }
  return { org, session, keys, keyId: created.body.data.id as string, ownerEmail: owner.email };
}

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      resolve();
    });
  });
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe('Fix 1: /v1/decrypt checks the expected AAD', () => {
  it('refuses an envelope whose AAD is not the one the caller expects', async () => {
    const t = await tenant([['crypto:execute', 'keys:create']]);
    const k = t.keys[0].key;
    const a = (await call(k, 'POST', '/v1/encrypt', { key: t.keyId, data: 'a@example.com', aad: 'customer:A:email' })).body.data;

    const right = await call(k, 'POST', '/v1/decrypt', { key: t.keyId, envelope: a.envelope, aad: 'customer:A:email' });
    expect(right.status).toBe(200);
    expect(right.body.data.plaintext).toBe('a@example.com');

    const moved = await call(k, 'POST', '/v1/decrypt', { key: t.keyId, envelope: a.envelope, aad: 'customer:B:email' });
    expect(moved.status).toBe(400);
    expect(moved.body.error.code).toBe('AAD_MISMATCH');

    // Without an expected AAD the envelope's own is used, as before.
    expect((await call(k, 'POST', '/v1/decrypt', { key: t.keyId, envelope: a.envelope })).status).toBe(200);

    // An envelope made without AAD does not match a caller who expects one.
    const plain = (await call(k, 'POST', '/v1/encrypt', { key: t.keyId, data: 'no aad' })).body.data;
    const expectsAad = await call(k, 'POST', '/v1/decrypt', { key: t.keyId, envelope: plain.envelope, aad: 'customer:A:email' });
    expect(expectsAad.body.error?.code).toBe('AAD_MISMATCH');

    // Sending back the whole encrypt response still works (its "aad" is the one used).
    expect((await call(k, 'POST', '/v1/decrypt', { key: t.keyId, ...a })).status).toBe(200);
  });
});

describe('Fix 3: rate limits per API key, under a per-organization ceiling', () => {
  it('limits one key without blocking another key from the same IP, until the organization ceiling', async () => {
    const t = await tenant([['crypto:execute', 'keys:create'], ['crypto:execute']]);
    const [a, b] = t.keys;
    const hash = (key: string) => call(key, 'POST', '/v1/encrypt', { key: t.keyId, data: 'x' });

    let firstLimitedA = 0;
    for (let i = 1; i <= 301 && !firstLimitedA; i++) {
      if ((await hash(a.key)).status === 429) firstLimitedA = i;
    }
    expect(firstLimitedA).toBe(301); // 300 per key per minute

    // Same IP, different key: not affected by key A's limit.
    expect((await hash(b.key)).status).toBe(200);

    // Organization ceiling (350 in this test): 300 from A + 50 from B, then 429 for B too.
    let bOk = 1;
    let bLimited = false;
    for (let i = 0; i < 60 && !bLimited; i++) {
      const s = (await hash(b.key)).status;
      if (s === 429) bLimited = true;
      else bOk++;
    }
    expect(bLimited).toBe(true);
    expect(bOk).toBe(50);
  });
});

describe('Fix 4: decrypts are traceable and a burst raises an alert', () => {
  beforeEach(() => {
    resetDecryptAlertCounters();
    clearSentEmailsHistory();
  });
  afterEach(() => {
    delete process.env.DECRYPT_ALERT_PER_HOUR;
  });

  it('records the caller IP on decrypt audit events and pages back through the log', async () => {
    const t = await tenant([['crypto:execute', 'keys:create']]);
    const k = t.keys[0];
    const env = (await call(k.key, 'POST', '/v1/encrypt', { key: t.keyId, data: 'x' })).body.data.envelope;
    for (let i = 0; i < 6; i++) {
      expect((await call(k.key, 'POST', '/v1/decrypt', { key: t.keyId, envelope: env })).status).toBe(200);
    }
    await new Promise((r) => setTimeout(r, 200)); // audit writes are not awaited by the request

    const first = await call(t.session, 'GET', `/v1/organizations/${t.org.id}/audit?limit=4&action=crypto.decrypt`, undefined, t.org.id);
    expect(first.status).toBe(200);
    expect(first.body.auditEvents).toHaveLength(4);
    for (const e of first.body.auditEvents) {
      expect(e.action).toBe('crypto.decrypt');
      expect(e.actorId).toBe(k.id);
      expect(e.ipAddress).toMatch(/127\.0\.0\.1|::1/);
    }
    expect(first.body.nextBefore).toBeTruthy();

    const older = await call(t.session, 'GET',
      `/v1/organizations/${t.org.id}/audit?limit=4&action=crypto.decrypt&before=${encodeURIComponent(first.body.nextBefore)}`,
      undefined, t.org.id);
    expect(older.status).toBe(200);
    expect(older.body.auditEvents.length).toBeGreaterThan(0);
    const firstIds = new Set(first.body.auditEvents.map((e: any) => e.id));
    for (const e of older.body.auditEvents) expect(firstIds.has(e.id)).toBe(false);

    const bad = await call(t.session, 'GET', `/v1/organizations/${t.org.id}/audit?before=not-a-date`, undefined, t.org.id);
    expect(bad.status).toBe(400);
  });

  it('alerts the owner once when one key decrypts more than the hourly threshold', async () => {
    process.env.DECRYPT_ALERT_PER_HOUR = '5';
    const t = await tenant([['crypto:execute', 'keys:create']]);
    const k = t.keys[0];
    const env = (await call(k.key, 'POST', '/v1/encrypt', { key: t.keyId, data: 'x' })).body.data.envelope;
    for (let i = 0; i < 8; i++) await call(k.key, 'POST', '/v1/decrypt', { key: t.keyId, envelope: env });

    let spikes: any[] = [];
    for (let i = 0; i < 20 && spikes.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 100));
      const audit = await call(t.session, 'GET', `/v1/organizations/${t.org.id}/audit?action=security.decrypt_spike`, undefined, t.org.id);
      spikes = audit.body.auditEvents;
    }
    expect(spikes).toHaveLength(1); // once, not on every decrypt past the threshold
    expect(spikes[0].actorId).toBe(k.id);
    expect(spikes[0].metadata.threshold).toBe(5);

    const alerts = getSentEmailsHistory().filter((m: any) => m.toEmail === t.ownerEmail);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].subject).toMatch(/decrypt/i);
  });
});
