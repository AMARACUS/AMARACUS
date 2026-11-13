/**
 * November 2026:
 *  - AMARACUS has no free tier. An organization without a paid plan keeps its account, keys and
 *    data, but every API operation, managed-key creation and API-key creation returns
 *    402 PAYMENT_REQUIRED.
 *  - Stolen-key guards (docs/recovery/breach-drill-2026-11.md): an optional IP allowlist per API
 *    key, and an automatic lock when a key passes the decrypt alert level in an hour.
 */
import { describeCloud, itCloud } from './helpers/edition';
import 'reflect-metadata';
import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { getSentEmailsHistory, clearSentEmailsHistory } from '../src/lib/email-service';
import { resetDecryptAlertCounters } from '../src/lib/decrypt-alerts';
import { isIpAllowed, validateAllowedIps } from '../src/lib/ip-allowlist';

jest.setTimeout(120000);

let server: http.Server;
let baseUrl: string;

async function call(token: string, method: string, urlPath: string, body?: any, orgId?: string) {
  const res = await fetch(`${baseUrl}${urlPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(orgId ? { 'X-Organization-Id': orgId } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

async function tenant(plan: string) {
  const tag = crypto.randomUUID().slice(0, 8);
  const org = await db.createOrganization({ name: `t ${tag}`, slug: `t-${tag}` });
  const project = await db.createProject({ organizationId: org.id, name: 'p', slug: `p-${tag}` });
  const env = await db.createEnvironment({ projectId: project.id, name: 'prod', slug: 'prod', type: 'PRODUCTION' });
  await db.upsertBillingSubscription({ organizationId: org.id, plan, status: 'ACTIVE' });
  const owner = await db.createUser({ email: `owner-${tag}@guards.example`, name: 'Owner', passwordHash: 'x' });
  await db.addMember({ organizationId: org.id, userId: owner.id, role: 'OWNER' });
  const session = `sess_${crypto.randomUUID()}`;
  await db.createSession({ sessionToken: session, userId: owner.id, activeOrgId: org.id, expiresAt: new Date(Date.now() + 3600_000) });
  const gen = generateAmaracusApiKey('live');
  const cred = await db.createApiCredential({
    organizationId: org.id,
    projectId: project.id,
    environmentId: env.id,
    name: 'app key',
    prefix: gen.prefix,
    keyHash: gen.keyHash,
    scopes: ['crypto:execute', 'keys:create', 'keys:read', 'pqc:execute'],
  });
  return { org, env, session, ownerEmail: owner.email, key: gen.fullKey, credId: cred.id };
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

describeCloud('no free tier', () => {
  it('blocks every operation and key creation for an organization without a paid plan', async () => {
    const t = await tenant('FREE');
    const checks = [
      await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' }),
      await call(t.key, 'POST', '/v1/encrypt', { rawKey: crypto.randomBytes(32).toString('base64'), data: 'x' }),
      await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'x' }),
      await call(t.key, 'POST', '/v1/pqc/keypair', { algorithm: 'ML-KEM-768' }),
      await call(t.session, 'POST', '/v1/credentials', { name: 'new', environmentId: t.env.id, scopes: ['crypto:encrypt'] }, t.org.id),
    ];
    for (const r of checks) {
      expect(r.status).toBe(402);
      expect(r.body.error.code).toBe('PAYMENT_REQUIRED');
    }
    // The account itself still works: the owner can read the organization's settings.
    expect((await call(t.session, 'GET', '/v1/credentials', undefined, t.org.id)).status).toBe(200);
  });

  it.each(['STARTER', 'PRO', 'BUSINESS', 'PAYG'])('lets a %s organization use the API', async (plan) => {
    const t = await tenant(plan);
    const created = await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    expect(created.status).toBe(201);
    const enc = await call(t.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'hello' });
    expect(enc.status).toBe(200);
  });

  it('exempts the internal platform organization (it holds the platform vault key)', async () => {
    const t = await tenant('FREE');
    const saved = process.env.AMARACUS_PLATFORM_ORG_ID;
    process.env.AMARACUS_PLATFORM_ORG_ID = t.org.id;
    try {
      const created = await call(t.key, 'POST', '/v1/keys', { name: 'platform-pii', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
      expect(created.status).toBe(201);
    } finally {
      if (saved === undefined) delete process.env.AMARACUS_PLATFORM_ORG_ID;
      else process.env.AMARACUS_PLATFORM_ORG_ID = saved;
    }
  });
});

describe('IP allowlist per API key', () => {
  it('validates entries and matches addresses and CIDR ranges', () => {
    expect(validateAllowedIps(['203.0.113.7', '10.0.0.0/8', '2001:db8::/32'])).toEqual({
      ok: true,
      value: ['203.0.113.7', '10.0.0.0/8', '2001:db8::/32'],
    });
    expect(validateAllowedIps([]).ok && validateAllowedIps([]).value).toBeNull();
    for (const bad of [['not-an-ip'], ['10.0.0.0/33'], ['1.2.3.4/8/1'], 'x', [5]]) {
      expect(validateAllowedIps(bad).ok).toBe(false);
    }
    expect(isIpAllowed('::ffff:10.1.2.3', ['10.0.0.0/8'])).toBe(true);
    expect(isIpAllowed('11.1.2.3', ['10.0.0.0/8'])).toBe(false);
    expect(isIpAllowed('2001:db8::5', ['2001:db8::/32'])).toBe(true);
    expect(isIpAllowed('8.8.8.8', null)).toBe(true);
  });

  it('refuses a key from an address outside its list, and accepts it from inside', async () => {
    const t = await tenant('PRO');
    const set = (allowedIps: string[] | null) =>
      call(t.session, 'PATCH', `/v1/credentials/${t.credId}`, { allowedIps }, t.org.id);
    const hash = () => call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'x' });

    const restricted = await set(['10.0.0.0/8']);
    expect(restricted.status).toBe(200);
    expect(restricted.body.data.allowedIps).toEqual(['10.0.0.0/8']);
    expect(restricted.body.data.keyHash).toBeUndefined();
    const refused = await hash();
    expect(refused.status).toBe(403);
    expect(refused.body.error.code).toBe('IP_NOT_ALLOWED');

    expect((await set(['127.0.0.0/8'])).status).toBe(200);
    expect((await hash()).status).toBe(200);

    expect((await set(null)).status).toBe(200);
    expect((await hash()).status).toBe(200);

    expect((await set(['bad'])).status).toBe(400);
  });

  it('can be set when a key is created', async () => {
    const t = await tenant('PRO');
    const res = await call(t.session, 'POST', '/v1/credentials',
      { name: 'server only', environmentId: t.env.id, scopes: ['crypto:encrypt'], allowedIps: ['192.0.2.10'] }, t.org.id);
    expect(res.status).toBe(201);
    expect(res.body.data.credential.allowedIps).toEqual(['192.0.2.10']);
    const used = await call(res.body.data.apiKey, 'POST', '/v1/encrypt', { rawKey: crypto.randomBytes(32).toString('base64'), data: 'x' });
    expect(used.status).toBe(403);
    expect(used.body.error.code).toBe('IP_NOT_ALLOWED');
  });
});

describe('auto-lock on a decrypt spike', () => {
  beforeEach(() => {
    resetDecryptAlertCounters();
    clearSentEmailsHistory();
    process.env.DECRYPT_ALERT_PER_HOUR = '5';
  });
  afterEach(() => {
    delete process.env.DECRYPT_ALERT_PER_HOUR;
    delete process.env.DECRYPT_AUTO_LOCK;
  });

  async function spike(t: Awaited<ReturnType<typeof tenant>>, attempts: number) {
    const created = await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    const keyId = created.body.data.id;
    const envelope = (await call(t.key, 'POST', '/v1/encrypt', { key: keyId, data: 'secret' })).body.data.envelope;
    const statuses: number[] = [];
    for (let i = 0; i < attempts; i++) {
      statuses.push((await call(t.key, 'POST', '/v1/decrypt', { key: keyId, envelope })).status);
    }
    return statuses;
  }

  it('locks the key once it passes the level, so no more than the level is read', async () => {
    const t = await tenant('PRO');
    const statuses = await spike(t, 9);
    expect(statuses.filter((s) => s === 200)).toHaveLength(5);
    expect(statuses.slice(5).every((s) => s === 401)).toBe(true);

    await new Promise((r) => setTimeout(r, 200));
    const cred = await db.findCredentialById(t.credId);
    expect(cred?.status).toBe('DISABLED');
    const locked = await call(t.session, 'GET', `/v1/organizations/${t.org.id}/audit?action=security.key_auto_locked`, undefined, t.org.id);
    expect(locked.body.auditEvents).toHaveLength(1);
    const mail = getSentEmailsHistory().filter((m: any) => m.toEmail === t.ownerEmail);
    expect(mail).toHaveLength(1);
    expect(mail[0].subject).toMatch(/locked/i);

    // The owner enables it again; it works and counts afresh.
    const enabled = await call(t.session, 'POST', `/v1/credentials/${t.credId}/enable`, {}, t.org.id);
    expect(enabled.status).toBe(200);
    expect(enabled.body.data.credential.keyHash).toBeUndefined();
    expect((await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'x' })).status).toBe(200);
  });

  it('only alerts when DECRYPT_AUTO_LOCK=0', async () => {
    process.env.DECRYPT_AUTO_LOCK = '0';
    const t = await tenant('PRO');
    const statuses = await spike(t, 8);
    expect(statuses.every((s) => s === 200)).toBe(true);
    await new Promise((r) => setTimeout(r, 200));
    const spikes = await call(t.session, 'GET', `/v1/organizations/${t.org.id}/audit?action=security.decrypt_spike`, undefined, t.org.id);
    expect(spikes.body.auditEvents).toHaveLength(1);
    expect(spikes.body.auditEvents[0].metadata.locked).toBe(false);
  });
});
