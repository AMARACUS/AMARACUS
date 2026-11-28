/**
 * Self-hosted edition (AMARACUS_EDITION=selfhosted):
 *  - Cloud billing routes do not exist.
 *  - Nothing runs until both licences are accepted (click-to-accept activation).
 *  - Every successful billable operation is appended once to a hash-chained local ledger;
 *    failed operations and idempotent retries are not counted.
 *  - 10,000 lifetime operations are free; after that new operations need a licence key, while
 *    decrypt and verify always keep working.
 *  - Licence keys are verified offline; the installation makes no outbound request.
 *  - Startup validation refuses AMARACUS's own addresses and missing customer configuration.
 */
import 'reflect-metadata';
import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';

process.env.AMARACUS_EDITION = 'selfhosted';
process.env.AMARACUS_TEST_ENFORCE_SELFHOST_GATE = '1';
// Empty, not deleted: dotenv would otherwise fill it from a developer's .env.
process.env.PLATFORM_ADMIN_EMAILS = '';

const testSigner = crypto.generateKeyPairSync('ed25519');
process.env.AMARACUS_TEST_LICENSE_PUBLIC_KEY = testSigner.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

/* eslint-disable @typescript-eslint/no-var-requires */
const { app } = require('../src/index');
const { db } = require('../src/lib/data-store');
const { generateAmaracusApiKey } = require('../src/lib/api-keys');
const { getEdition } = require('../src/lib/edition');
const { validateStartupConfig } = require('../src/lib/runtime-config');
const ledger = require('../src/lib/usage-ledger');
const license = require('../src/lib/selfhost-license');
/* eslint-enable @typescript-eslint/no-var-requires */

jest.setTimeout(120000);

let server: http.Server;
let baseUrl: string;
const outbound: string[] = [];
const realFetch = global.fetch;

async function call(token: string | null, method: string, urlPath: string, body?: any, headers: Record<string, string> = {}) {
  const res = await realFetch(`${baseUrl}${urlPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: any = {};
  try {
    json = JSON.parse(text);
  } catch {
    // not JSON (ledger export)
  }
  return { status: res.status, body: json, text };
}

async function tenant() {
  const tag = crypto.randomUUID().slice(0, 8);
  const org = await db.createOrganization({ name: `t ${tag}`, slug: `t-${tag}` });
  const project = await db.createProject({ organizationId: org.id, name: 'p', slug: `p-${tag}` });
  const env = await db.createEnvironment({ projectId: project.id, name: 'prod', slug: 'prod', type: 'PRODUCTION' });
  const owner = await db.createUser({ email: `owner-${tag}@selfhost.example`, name: 'Owner', passwordHash: 'x' });
  await db.addMember({ organizationId: org.id, userId: owner.id, role: 'OWNER' });
  const session = `sess_${crypto.randomUUID()}`;
  await db.createSession({ sessionToken: session, userId: owner.id, activeOrgId: org.id, expiresAt: new Date(Date.now() + 3600_000) });
  const gen = generateAmaracusApiKey('live');
  await db.createApiCredential({
    organizationId: org.id,
    projectId: project.id,
    environmentId: env.id,
    name: 'app key',
    prefix: gen.prefix,
    keyHash: gen.keyHash,
    scopes: ['crypto:execute', 'keys:create', 'keys:read', 'pqc:execute'],
  });
  return { org, env, session, ownerEmail: owner.email, key: gen.fullKey };
}

async function accept(session: string, licensee = 'Example Bank Group plc') {
  const docs = (await call(null, 'GET', '/v1/selfhost/licenses')).body.data;
  return call(session, 'POST', '/v1/selfhost/accept', {
    acceptShield: true,
    acceptCommercialTerms: true,
    licensee,
    shieldSha256: docs.shield.sha256,
    commercialSha256: docs.commercial.sha256,
  });
}

function licenceKey(operations: number, licenseId = `lic_${crypto.randomUUID().slice(0, 8)}`, signer = testSigner.privateKey) {
  return license.signLicenseKey(
    { v: 1, licenseId, licensee: 'Example Bank Group plc', operations, issuedAt: new Date().toISOString() },
    signer
  );
}

beforeAll(async () => {
  // Any request this process makes to anything but the test server is recorded.
  global.fetch = (async (input: any, init?: any) => {
    outbound.push(String(typeof input === 'string' ? input : input?.url || input));
    return realFetch(input, init);
  }) as typeof fetch;
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      resolve();
    });
  });
});

afterAll(async () => {
  global.fetch = realFetch;
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  ledger.resetLedgerForTests();
  license.resetSelfHostLicenseForTests();
});

describe('edition', () => {
  it('runs as selfhosted and has no Cloud billing, webhook, hackathon or review routes', async () => {
    expect(getEdition()).toBe('selfhosted');
    const t = await tenant();
    for (const path of ['/v1/billing/plans', '/v1/hackathon', '/v1/reviews', '/webhooks/polar', '/webhooks/razorpay', '/v1/billing/razorpay/plans']) {
      const method = path.startsWith('/webhooks') ? 'POST' : 'GET';
      const r = await call(t.session, method, path, method === 'POST' ? {} : undefined);
      expect([401, 403, 404]).toContain(r.status);
      expect(r.status).toBe(404);
    }
  });

  it('reports status publicly without usage, and with usage to a signed-in user', async () => {
    const anon = await call(null, 'GET', '/v1/selfhost/status');
    expect(anon.status).toBe(200);
    expect(anon.body.data).toMatchObject({ edition: 'selfhosted', activated: false, telemetry: 'none' });
    expect(anon.body.data.usage).toBeUndefined();
    expect(anon.body.data.licenses.shield.sha256).toMatch(/^[0-9a-f]{64}$/);

    const t = await tenant();
    const signedIn = await call(t.session, 'GET', '/v1/selfhost/status');
    expect(signedIn.body.data.usage).toMatchObject({ lifetimeOperations: 0, freeAllowance: 10000, licensedOperations: 0, remaining: 10000, ratePer1kOpsCents: 15, currency: 'USD' });

    // An expired or unknown session is not an error for the status call.
    const stale = await call('sess_does_not_exist', 'GET', '/v1/selfhost/status');
    expect(stale.status).toBe(200);
    expect(stale.body.data.usage).toBeUndefined();
  });

  it('serves the unmodified PolyForm Shield 1.0.0 text and the additional commercial terms', async () => {
    const docs = (await call(null, 'GET', '/v1/selfhost/licenses')).body.data;
    expect(docs.shield.text).toContain('PolyForm Shield License 1.0.0');
    expect(docs.shield.text).toContain('https://polyformproject.org/licenses/shield/1.0.0');
    expect(docs.commercial.text).toContain('AMARACUS Additional Commercial Terms');
    expect(docs.commercial.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe('activation (click-to-accept)', () => {
  it('blocks new operations and key creation until both licences are accepted', async () => {
    const t = await tenant();
    const checks = [
      await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' }),
      await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'x' }),
      await call(t.session, 'POST', '/v1/credentials', { name: 'new', environmentId: t.env.id, scopes: ['crypto:encrypt'] }, { 'X-Organization-Id': t.org.id }),
    ];
    for (const r of checks) {
      expect(r.status).toBe(403);
      expect(r.body.error.code).toBe('LICENSE_ACCEPTANCE_REQUIRED');
    }
  });

  it('rejects an incomplete acceptance, a stale text, and API keys', async () => {
    const t = await tenant();
    const docs = (await call(null, 'GET', '/v1/selfhost/licenses')).body.data;
    const good = { acceptShield: true, acceptCommercialTerms: true, licensee: 'Example Ltd', shieldSha256: docs.shield.sha256, commercialSha256: docs.commercial.sha256 };

    expect((await call(t.session, 'POST', '/v1/selfhost/accept', { ...good, acceptCommercialTerms: false })).body.error.code).toBe('ACCEPTANCE_INCOMPLETE');
    expect((await call(t.session, 'POST', '/v1/selfhost/accept', { ...good, licensee: ' ' })).body.error.code).toBe('LICENSEE_REQUIRED');
    const stale = await call(t.session, 'POST', '/v1/selfhost/accept', { ...good, commercialSha256: 'f'.repeat(64) });
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe('LICENSE_TEXT_MISMATCH');
    expect((await call(t.key, 'POST', '/v1/selfhost/accept', good)).status).toBe(403);
    expect((await call(null, 'POST', '/v1/selfhost/accept', good)).status).toBe(401);
    expect((await call(null, 'GET', '/v1/selfhost/status')).body.data.activated).toBe(false);
  });

  it('activates on acceptance and records who accepted which texts', async () => {
    const t = await tenant();
    const r = await accept(t.session);
    expect(r.status).toBe(200);
    expect(r.body.data.activated).toBe(true);
    expect(r.body.data.acceptance).toMatchObject({ acceptedByEmail: t.ownerEmail, licensee: 'Example Bank Group plc', current: true });
    const created = await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    expect(created.status).toBe(201);
  });

  it('restricts acceptance to PLATFORM_ADMIN_EMAILS when that is set', async () => {
    const t = await tenant();
    process.env.PLATFORM_ADMIN_EMAILS = 'someone-else@selfhost.example';
    try {
      const denied = await accept(t.session);
      expect(denied.status).toBe(403);
      expect(denied.body.error.code).toBe('INSTALLATION_ADMIN_REQUIRED');
      process.env.PLATFORM_ADMIN_EMAILS = t.ownerEmail;
      expect((await accept(t.session)).status).toBe(200);
    } finally {
      process.env.PLATFORM_ADMIN_EMAILS = '';
    }
  });
});

describe('usage ledger', () => {
  it('counts successful operations once, and not failures or idempotent retries', async () => {
    const t = await tenant();
    await accept(t.session);

    const created = await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    expect(created.status).toBe(201);
    const afterKey = await ledger.getLifetimeOperations();
    expect(afterKey).toBe(1); // key generation

    const enc = await call(t.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'hello' });
    expect(enc.status).toBe(200);
    expect(await ledger.getLifetimeOperations()).toBe(afterKey + 1);
    ledger.resetLedgerForTests();
    await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: 'seed-1', operationType: 'ENCRYPT', quantity: 1 });
    await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: 'seed-2', operationType: 'ENCRYPT', quantity: 1 });

    // A failed operation is not billable.
    const bad = await call(t.key, 'POST', '/v1/encrypt', { key: 'key_does_not_exist', data: 'hello' });
    expect(bad.status).toBeGreaterThanOrEqual(400);
    expect(await ledger.getLifetimeOperations()).toBe(2);

    // Health checks and reads are not billable.
    await call(null, 'GET', '/health');
    await call(t.key, 'GET', '/v1/keys');
    expect(await ledger.getLifetimeOperations()).toBe(2);

    // The same Idempotency-Key twice is one operation.
    const idem = { 'Idempotency-Key': `idem-${crypto.randomUUID()}` };
    const first = await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'same' }, idem);
    const second = await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'same' }, idem);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(await ledger.getLifetimeOperations()).toBe(3);

    const entries = await ledger.listLedgerEntries(0, 100);
    expect(entries.map((e: any) => e.cumulativeTotal)).toEqual([1, 2, 3]);
    expect(entries[0].prevHash).toBe(ledger.LEDGER_GENESIS_HASH);
    expect(entries[1].prevHash).toBe(entries[0].entryHash);
  });

  it('verifies the chain and shows where it was tampered with', async () => {
    const t = await tenant();
    await accept(t.session);
    for (let i = 0; i < 5; i++) {
      await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: `op_${i}`, operationType: 'ENCRYPT', quantity: 1 });
    }
    const ok = await call(t.session, 'GET', '/v1/selfhost/ledger/verify');
    expect(ok.body.data).toEqual({ valid: true, entriesChecked: 5, cumulativeTotal: 5, firstBrokenSeq: null });

    // Lower one entry's quantity, as someone under-reporting would.
    ledger.ledgerMemoryForTests()[2].quantity = 0;
    const broken = await call(t.session, 'GET', '/v1/selfhost/ledger/verify');
    expect(broken.body.data.valid).toBe(false);
    expect(broken.body.data.firstBrokenSeq).toBe(3);

    // Removing an entry is detected as well.
    ledger.resetLedgerForTests();
    for (let i = 0; i < 4; i++) {
      await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: `op2_${i}`, operationType: 'SIGN', quantity: 2 });
    }
    ledger.ledgerMemoryForTests().splice(1, 1);
    expect((await ledger.verifyLedger()).valid).toBe(false);
  });

  it('exports the ledger as JSON Lines to the administrator only', async () => {
    const t = await tenant();
    await accept(t.session);
    await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: 'op_export', operationType: 'ENCRYPT', quantity: 3 });
    const out = await call(t.session, 'GET', '/v1/selfhost/ledger/export');
    expect(out.status).toBe(200);
    const lines = out.text.trim().split('\n').map((l) => JSON.parse(l));
    expect(lines[0]).toMatchObject({ type: 'header', format: 'amaracus-usage-ledger/1', licensee: 'Example Bank Group plc' });
    expect(lines[0].verification.valid).toBe(true);
    expect(lines[1]).toMatchObject({ type: 'entry', operationId: 'op_export', quantity: 3, cumulativeTotal: 3 });
    expect((await call(t.key, 'GET', '/v1/selfhost/ledger/export')).status).toBe(403);
    expect((await call(null, 'GET', '/v1/selfhost/ledger')).status).toBe(401);
  });
});

describe('lifetime allowance and licence keys', () => {
  it('stops new operations after 10,000 lifetime operations, but never decrypt or verify', async () => {
    const t = await tenant();
    await accept(t.session);
    const created = await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    const enc = await call(t.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'keep me readable' });
    expect(enc.status).toBe(200);

    // Bring the installation to 9,999 operations, then use the last free one.
    const used = await ledger.getLifetimeOperations();
    await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: 'bulk', operationType: 'ENCRYPT', quantity: 9999 - used });
    expect((await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'op 10000' })).status).toBe(200);
    expect(await ledger.getLifetimeOperations()).toBe(10000);

    // Operation 1,001 needs a licence key.
    const blocked = [
      await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'op 10001' }),
      await call(t.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'new data' }),
      await call(t.key, 'POST', '/v1/keys', { name: 'k2', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' }),
      await call(t.session, 'POST', '/v1/credentials', { name: 'new', environmentId: t.env.id, scopes: ['crypto:encrypt'] }, { 'X-Organization-Id': t.org.id }),
    ];
    for (const r of blocked) {
      expect(r.status).toBe(402);
      expect(r.body.error.code).toBe('SELF_HOST_LICENSE_REQUIRED');
    }
    expect(blocked[0].body.error).toMatchObject({ freeAllowance: 10000, totalAllowance: 10000, ratePer1kOpsCents: 15 });
    expect(await ledger.getLifetimeOperations()).toBe(10000);

    // Earlier data stays readable, and the decrypt is still recorded.
    const dec = await call(t.key, 'POST', '/v1/decrypt', { key: created.body.data.id, envelope: enc.body.data.envelope });
    expect(dec.status).toBe(200);
    expect(await ledger.getLifetimeOperations()).toBe(10001);
    const status = (await call(t.session, 'GET', '/v1/selfhost/status')).body.data;
    expect(status.usage).toMatchObject({ lifetimeOperations: 10001, remaining: 0, licenseRequired: true });
  });

  it('accepts only keys signed by AMARACUS, adds their operations, and refuses a repeat', async () => {
    const t = await tenant();
    await accept(t.session);
    await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: 'bulk', operationType: 'ENCRYPT', quantity: 10000 });
    expect((await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'x' })).status).toBe(402);

    const forged = licenceKey(1_000_000, 'lic_forged', crypto.generateKeyPairSync('ed25519').privateKey);
    for (const bad of ['not a key', forged, licenceKey(5000).replace(/\.[^.]+$/, '.AAAA')]) {
      const r = await call(t.session, 'POST', '/v1/selfhost/license-keys', { key: bad });
      expect(r.status).toBe(400);
      expect(r.body.error.code).toBe('INVALID_LICENSE_KEY');
    }
    expect((await call(t.key, 'POST', '/v1/selfhost/license-keys', { key: licenceKey(5000) })).status).toBe(403);

    const key = licenceKey(5000, 'lic_real');
    const added = await call(t.session, 'POST', '/v1/selfhost/license-keys', { key });
    expect(added.status).toBe(200);
    expect(added.body.data.usage).toMatchObject({ licensedOperations: 5000, totalAllowance: 15000, remaining: 5000, licenseRequired: false });
    expect(added.body.data.licenseKeys).toHaveLength(1);
    expect(JSON.stringify(added.body.data)).not.toContain(key);

    expect((await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: 'x' })).status).toBe(200);
    const again = await call(t.session, 'POST', '/v1/selfhost/license-keys', { key });
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe('LICENSE_KEY_ALREADY_ADDED');
  });

  it('keeps tenants apart: one organization cannot use another organization\'s key', async () => {
    const a = await tenant();
    const b = await tenant();
    await accept(a.session);
    const created = await call(a.key, 'POST', '/v1/keys', { name: 'a-key', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    const enc = await call(a.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'tenant a secret' });
    const stolen = await call(b.key, 'POST', '/v1/decrypt', { key: created.body.data.id, envelope: enc.body.data.envelope });
    expect(stolen.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(stolen.body)).not.toContain('tenant a secret');
    expect((await call(b.key, 'GET', `/v1/keys/${created.body.data.id}`)).status).toBeGreaterThanOrEqual(400);
  });
});

describe('gate and ledger cannot be steered by the caller', () => {
  async function atCap(t: any) {
    await accept(t.session);
    await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: 'bulk-cap', operationType: 'ENCRYPT', quantity: 10000 });
  }

  it('ignores body labels such as operation: "verify" on a protective route', async () => {
    const t = await tenant();
    await atCap(t);
    for (const body of [
      { algorithm: 'SHA-256', data: 'x', operation: 'verify' },
      { algorithm: 'SHA-256', data: 'x', operationType: 'decrypt' },
      { algorithm: 'SHA-256', data: 'x', action: 'unwrap' },
    ]) {
      const r = await call(t.key, 'POST', '/v1/hash', body);
      expect(r.status).toBe(402);
      expect(r.body.error.code).toBe('SELF_HOST_LICENSE_REQUIRED');
    }
  });

  it('classifies the generic /v1/operations route by the field it executes', async () => {
    const t = await tenant();
    await atCap(t);
    const enc = await call(t.key, 'POST', '/v1/operations', { type: 'HASH', operation: 'verify', algorithm: 'SHA-256', params: { data: 'x' } });
    expect(enc.status).toBe(402);
    const dec = await call(t.key, 'POST', '/v1/operations', { type: 'DECRYPT', keyId: 'key_missing', params: { ciphertext: 'x' } });
    expect(dec.body?.error?.code).not.toBe('SELF_HOST_LICENSE_REQUIRED');
  });

  it('counts every request even when the client repeats the same X-Request-Id', async () => {
    const t = await tenant();
    await accept(t.session);
    const before = await ledger.getLifetimeOperations();
    for (let i = 0; i < 3; i++) {
      expect((await call(t.key, 'POST', '/v1/hash', { algorithm: 'SHA-256', data: `d${i}` }, { 'X-Request-Id': 'constant' })).status).toBe(200);
    }
    expect(await ledger.getLifetimeOperations()).toBe(before + 3);
  });

  it('treats a reused Idempotency-Key with a different body as a new operation', async () => {
    const t = await tenant();
    await accept(t.session);
    const created = await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    const e1 = await call(t.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'one' });
    const e2 = await call(t.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'two' });
    const before = await ledger.getLifetimeOperations();
    const idem = { 'Idempotency-Key': 'same-key-every-time' };
    // /v1/decrypt is never served from the response cache, so each call runs.
    expect((await call(t.key, 'POST', '/v1/decrypt', { key: created.body.data.id, envelope: e1.body.data.envelope }, idem)).status).toBe(200);
    expect((await call(t.key, 'POST', '/v1/decrypt', { key: created.body.data.id, envelope: e1.body.data.envelope }, idem)).status).toBe(200);
    expect(await ledger.getLifetimeOperations()).toBe(before + 1); // a true retry counts once
    expect((await call(t.key, 'POST', '/v1/decrypt', { key: created.body.data.id, envelope: e2.body.data.envelope }, idem)).status).toBe(200);
    expect(await ledger.getLifetimeOperations()).toBe(before + 2); // a different body is a different operation
  });

  it('gates and counts signing with a managed key under /organizations/:orgId/keys', async () => {
    const t = await tenant();
    await accept(t.session);
    const created = await call(t.key, 'POST', '/v1/keys', { name: 's', algorithm: 'Ed25519', purpose: 'SIGNING' });
    expect(created.status).toBe(201);
    const path = `/v1/organizations/${t.org.id}/keys/${created.body.data.id}/sign`;
    const before = await ledger.getLifetimeOperations();
    const ok = await call(t.session, 'POST', path, { data: 'hello' }, { 'X-Organization-Id': t.org.id });
    expect(ok.status).toBe(200);
    await new Promise((r) => setTimeout(r, 50));
    expect(await ledger.getLifetimeOperations()).toBe(before + 1);
    await ledger.appendLedgerEntry({ organizationId: t.org.id, operationId: 'bulk-sign', operationType: 'ENCRYPT', quantity: 10000 });
    const blocked = await call(t.session, 'POST', path, { data: 'hello' }, { 'X-Organization-Id': t.org.id });
    expect(blocked.status).toBe(402);
  });
});

describe('no telemetry', () => {
  it('makes no outbound request while activating, operating, licensing and exporting', async () => {
    outbound.length = 0;
    const t = await tenant();
    await accept(t.session);
    const created = await call(t.key, 'POST', '/v1/keys', { name: 'k', algorithm: 'AES-256-GCM', purpose: 'ENCRYPTION' });
    await call(t.key, 'POST', '/v1/encrypt', { key: created.body.data.id, data: 'hello' });
    await call(t.session, 'POST', '/v1/selfhost/license-keys', { key: licenceKey(100) });
    await call(t.session, 'GET', '/v1/selfhost/ledger/export');
    await new Promise((r) => setTimeout(r, 300));
    expect(outbound).toEqual([]);
  });
});

describe('startup configuration', () => {
  const saved = { ...process.env };
  afterEach(() => {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  });

  function baseEnv() {
    process.env.AMARACUS_EDITION = 'selfhosted';
    process.env.DATABASE_URL = 'postgresql://u:p@localhost:5432/db';
    process.env.API_SECRET = crypto.randomBytes(32).toString('base64url');
    process.env.AUTH_SECRET = crypto.randomBytes(32).toString('base64url');
    process.env.API_URL = 'https://kms-api.example-bank.com';
    delete process.env.NEXT_PUBLIC_API_URL;
    delete process.env.NEXT_PUBLIC_APP_URL;
    delete process.env.SUPPORT_EMAIL;
    process.env.UNSUBSCRIBE_SECRET = crypto.randomBytes(32).toString('base64url');
    process.env.AMARACUS_LOCAL_MASTER_KEY = crypto.randomBytes(32).toString('base64url');
    delete process.env.AMARACUS_MASTER_KEY_WRAPPED;
    delete process.env.AMARACUS_MASTER_KEY_KEK_ID;
    process.env.APP_URL = 'https://kms.example-bank.com';
    process.env.SMTP_HOST = 'smtp.example-bank.com';
    process.env.SMTP_FROM = '"KMS" <kms@example-bank.com>';
    for (const n of ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_KEY_VAULT_URL', 'AZURE_MANAGED_HSM_URL', 'EMAIL_FROM_DEFAULT', 'EMAIL_FROM_VERIFY', 'EMAIL_FROM_RECOVERY', 'RESEND_API_KEY', 'VERIFY_SMTP_FROM', 'RECOVERY_SMTP_FROM', 'SMTP_FROM_SECURITY', 'SMTP_FROM_NOTIFICATIONS', 'SMTP_FROM_MARKETING', 'API_INTERNAL_URL']) {
      delete process.env[n];
    }
  }

  it('accepts a complete customer-owned configuration', () => {
    baseEnv();
    expect(validateStartupConfig()).toEqual([]);
  });

  it('explains what is missing or wrong', () => {
    baseEnv();
    delete process.env.APP_URL;
    delete process.env.NEXT_PUBLIC_APP_URL;
    expect(validateStartupConfig().join('\n')).toMatch(/APP_URL is not set/);

    baseEnv();
    process.env.APP_URL = 'https://amaracus.tech';
    expect(validateStartupConfig().join('\n')).toMatch(/must use your own domain/);

    baseEnv();
    process.env.API_URL = 'https://api.amaracus.tech';
    expect(validateStartupConfig().join('\n')).toMatch(/API_URL points at amaracus\.tech/);

    baseEnv();
    process.env.SMTP_FROM = '"AMARACUS" <noreply@amaracus.tech>';
    expect(validateStartupConfig().join('\n')).toMatch(/SMTP_FROM uses an amaracus\.tech address/);

    baseEnv();
    delete process.env.SMTP_FROM;
    expect(validateStartupConfig().join('\n')).toMatch(/EMAIL_FROM_DEFAULT \(or SMTP_FROM\) is not set/);

    baseEnv();
    process.env.API_SECRET = 'replace_me_with_secure_secret_xxxxxxxxxxxxxxxx';
    expect(validateStartupConfig().join('\n')).toMatch(/API_SECRET still has the placeholder value/);

    baseEnv();
    process.env.AZURE_CLIENT_SECRET = 'not-a-real-secret';
    expect(validateStartupConfig().join('\n')).toMatch(/Azure is partly configured/);

    baseEnv();
    delete process.env.DATABASE_URL;
    expect(validateStartupConfig().join('\n')).toMatch(/DATABASE_URL is not set/);

    baseEnv();
    process.env.AMARACUS_EDITION = 'enterprise';
    expect(validateStartupConfig().join('\n')).toMatch(/AMARACUS_EDITION must be/);
  });

  it('never falls back to AMARACUS addresses for email or links', () => {
    baseEnv();
    /* eslint-disable @typescript-eslint/no-var-requires */
    const { site, appUrl } = require('../src/lib/site-config');
    /* eslint-enable @typescript-eslint/no-var-requires */
    const keys = ['appUrl', 'apiUrl', 'supportEmail', 'privacyEmail', 'grievanceEmail', 'securityEmail', 'unsubscribeEmail', 'fromSecurity', 'fromNotifications', 'fromMarketing', 'fromVerify', 'fromRecovery', 'fromDefault', 'fromVerifySmtp', 'fromRecoverySmtp', 'fromDefaultSmtp', 'legalCompany', 'legalAddress'];
    for (const k of keys) expect(site(k)).not.toMatch(/amaracus\.tech|Amaracus Technologies|Bengaluru/i);
    expect(appUrl()).toBe('https://kms.example-bank.com');
    expect(site('supportEmail')).toBe('kms@example-bank.com');
  });
});
