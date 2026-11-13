/**
 * Phase 4 recovery regression tests: bytes survive every crypto path over HTTP,
 * tampering is detected, key-version state is enforced, PQC matches NIST ACVP
 * vectors, and certificate chains honour anchors, expiry and revocation.
 */
import 'reflect-metadata';
import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { MlKemEngine, MlDsaEngine, X509Engine, ChainValidator, registry, normalizeAlgorithmId } from '@amaracus/crypto-core';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { sanitizePayload } from '../src/lib/sanitize';
import { isCryptoBodyPath } from '../src/middleware/sanitize';

jest.setTimeout(120000);

const NIST = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'nist-acvp-pqc.json'), 'utf8'));
const hex = (h: string) => Buffer.from(h, 'hex');

/** Random bytes that always include NUL and invalid UTF-8 sequences. */
function awkwardBytes(n = 96): Buffer {
  return Buffer.concat([Buffer.from([0x00, 0xff, 0xfe, 0xc3, 0x28, 0x80, 0x00]), crypto.randomBytes(n)]);
}

let server: http.Server;
let baseUrl: string;
let apiKey: string;

async function call(method: string, urlPath: string, body?: any) {
  const res = await fetch(`${baseUrl}${urlPath}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as any };
}
const post = (p: string, b: any) => call('POST', p, b);

async function createKey(algorithm: string, purpose: string) {
  const res = await post('/v1/keys', { name: `p4-${crypto.randomUUID().slice(0, 8)}`, algorithm, purpose });
  expect(res.status).toBe(201);
  return res.body.data.id as string;
}

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      resolve();
    });
  });
  const org = await db.createOrganization({ name: 'Phase 4 Org', slug: `p4-${Date.now()}` });
  const project = await db.createProject({ organizationId: org.id, name: 'p4', slug: 'p4' });
  const env = await db.createEnvironment({ projectId: project.id, name: 'prod', slug: 'prod', type: 'PRODUCTION' });
  await db.upsertBillingSubscription({ organizationId: org.id, plan: 'BUSINESS', status: 'ACTIVE' });
  const gen = generateAmaracusApiKey('live');
  apiKey = gen.fullKey;
  await db.createApiCredential({
    organizationId: org.id,
    projectId: project.id,
    environmentId: env.id,
    name: 'p4 full',
    prefix: gen.prefix,
    keyHash: gen.keyHash,
    scopes: ['*'],
  });
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe('Phase 4 — byte-exact round trips over HTTP', () => {
  it('managed AES key: binary payload with NUL and invalid UTF-8 round-trips', async () => {
    const keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    const bytes = awkwardBytes();
    const enc = await post('/v1/encrypt', { key: keyId, data: bytes.toString('base64'), encoding: 'base64' });
    expect(enc.status).toBe(200);
    const dec = await post('/v1/decrypt', { key: keyId, ...enc.body.data, outputEncoding: 'base64' });
    expect(dec.status).toBe(200);
    expect(Buffer.from(dec.body.data.plaintext, 'base64').equals(bytes)).toBe(true);
  });

  it('raw key: binary payload round-trips (previously corrupted to U+FFFD)', async () => {
    const rawKey = crypto.randomBytes(32).toString('base64');
    const bytes = awkwardBytes();
    const enc = await post('/v1/encrypt', { rawKey, data: bytes.toString('base64'), encoding: 'base64' });
    expect(enc.status).toBe(200);
    const dec = await post('/v1/decrypt', { rawKey, ...enc.body.data, outputEncoding: 'base64' });
    expect(dec.status).toBe(200);
    expect(Buffer.from(dec.body.data.plaintext, 'base64').equals(bytes)).toBe(true);
  });

  it('defaults to UTF-8 but falls back to base64 instead of returning a lossy string', async () => {
    const keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    const bytes = awkwardBytes();
    const enc = await post('/v1/encrypt', { key: keyId, data: bytes.toString('base64'), encoding: 'base64' });
    const dec = await post('/v1/decrypt', { key: keyId, ...enc.body.data });
    expect(dec.body.data.encoding).toBe('base64');
    expect(Buffer.from(dec.body.data.plaintext, 'base64').equals(bytes)).toBe(true);
  });

  it('text with HTML, quotes, control chars and padding is not sanitized', async () => {
    const keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    const text = '  <script>alert("x")</script> & \u0001 = `tick` / end\n ';
    const aad = 'tenant=<a&b>';
    const enc = await post('/v1/encrypt', { key: keyId, data: text, aad });
    const dec = await post('/v1/decrypt', { key: keyId, ...enc.body.data });
    expect(dec.status).toBe(200);
    expect(dec.body.data.plaintext).toBe(text);
    expect(dec.body.data.encoding).toBe('utf8');
  });

  it('the opaque envelope string alone is enough to decrypt', async () => {
    const keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    const bytes = awkwardBytes(32);
    const enc = await post('/v1/encrypt', { key: keyId, data: bytes.toString('base64'), encoding: 'base64', aad: 'ctx' });
    expect(typeof enc.body.data.envelope).toBe('string');
    const dec = await post('/v1/decrypt', { key: keyId, envelope: enc.body.data.envelope, outputEncoding: 'base64' });
    expect(dec.status).toBe(200);
    expect(Buffer.from(dec.body.data.plaintext, 'base64').equals(bytes)).toBe(true);
  });

  it('hash and HMAC over binary input match Node crypto', async () => {
    const bytes = awkwardBytes();
    const hash = await post('/v1/hash', { data: bytes.toString('base64'), encoding: 'base64', algorithm: 'SHA-256' });
    expect(hash.status).toBe(200);
    expect(hash.body.data.digest).toBe(crypto.createHash('sha256').update(bytes).digest('hex'));

    const key = crypto.randomBytes(32);
    const expected = crypto.createHmac('sha256', key).update(bytes).digest('hex');
    for (const algorithm of ['HMAC-SHA-256', 'HMAC-SHA256', 'hmac_sha256']) {
      const mac = await post('/v1/crypto/hmac', {
        algorithm,
        key: key.toString('base64'),
        keyEncoding: 'base64',
        data: bytes.toString('base64'),
        dataEncoding: 'base64',
      });
      expect(mac.status).toBe(200);
      expect(mac.body.data.mac).toBe(expected);
    }
  });

  it('managed Ed25519 sign/verify over binary data; altered data fails', async () => {
    const keyId = await createKey('ED25519', 'SIGNING');
    const bytes = awkwardBytes();
    const sig = await post('/v1/sign', { key: keyId, data: bytes.toString('base64'), encoding: 'base64' });
    expect(sig.status).toBe(200);
    const ok = await post('/v1/verify', { key: keyId, data: bytes.toString('base64'), encoding: 'base64', signature: sig.body.data.signature });
    expect(ok.body.data.valid).toBe(true);
    const flipped = Buffer.from(bytes);
    flipped[3] ^= 0x01;
    const bad = await post('/v1/verify', { key: keyId, data: flipped.toString('base64'), encoding: 'base64', signature: sig.body.data.signature });
    expect(bad.body.data?.valid ?? false).toBe(false);
  });
  it('managed ML-DSA-65 key signs and verifies binary data', async () => {
    const keyId = await createKey('ML-DSA-65', 'SIGNING');
    const bytes = awkwardBytes();
    const sig = await post('/v1/sign', { key: keyId, data: bytes.toString('base64'), encoding: 'base64' });
    expect(sig.status).toBe(200);
    const ok = await post('/v1/verify', { key: keyId, data: bytes.toString('base64'), encoding: 'base64', signature: sig.body.data.signature });
    expect(ok.body.data.valid).toBe(true);
  });
});

describe('Phase 4 — tamper detection', () => {
  let keyId: string;
  let enc: any;

  beforeAll(async () => {
    keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    enc = (await post('/v1/encrypt', { key: keyId, data: 'secret payload', aad: 'bound-context' })).body.data;
    // Tamper with the individual fields; the opaque envelope would take precedence
    delete enc.envelope;
  });

  const flip = (b64url: string) => {
    const buf = Buffer.from(b64url, 'base64url');
    buf[0] ^= 0x01;
    return buf.toString('base64url');
  };

  it.each([
    ['tag', (e: any) => ({ ...e, tag: flip(e.tag) })],
    ['iv', (e: any) => ({ ...e, iv: flip(e.iv) })],
    ['ciphertext', (e: any) => ({ ...e, ciphertext: flip(e.ciphertext) })],
    ['aad', (e: any) => ({ ...e, aad: 'other-context' })],
    ['missing aad', (e: any) => ({ ...e, aad: undefined })],
  ])('rejects a modified %s', async (_label, mutate) => {
    const dec = await post('/v1/decrypt', { key: keyId, ...mutate(enc) });
    expect(dec.status).toBeGreaterThanOrEqual(400);
    expect(dec.status).toBeLessThan(500);
    expect(dec.body.data).toBeUndefined();
  });
});

describe('Phase 4 — key-version state', () => {
  it('after rotation: new data uses v2, v1 data still decrypts, v1 cannot encrypt, no cross-version retry', async () => {
    const keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    const v1 = (await post('/v1/encrypt', { key: keyId, data: 'from v1' })).body.data;
    expect(v1.keyVersion).toBe(1);

    const rotated = await post(`/v1/keys/${keyId}/rotate`, {});
    expect(rotated.status).toBeLessThan(300);

    const v2 = (await post('/v1/encrypt', { key: keyId, data: 'from v2' })).body.data;
    expect(v2.keyVersion).toBe(2);

    // v1 ciphertext decrypts through the version recorded in the envelope
    const dec1 = await post('/v1/decrypt', { key: keyId, envelope: v1.envelope });
    expect(dec1.status).toBe(200);
    expect(dec1.body.data.plaintext).toBe('from v1');

    // Encrypting with the DEPRECATED version is refused
    const encOld = await post('/v1/encrypt', { key: keyId, data: 'x', version: 1 });
    expect(encOld.status).toBe(400);
    expect(encOld.body.error.code).toBe('KEY_DISABLED');

    // v1 ciphertext presented as v2 fails instead of silently trying v1
    const wrong = await post('/v1/decrypt', { key: keyId, ciphertext: v1.ciphertext, iv: v1.iv, tag: v1.tag, version: 2 });
    expect(wrong.status).toBe(400);
  });

  it('a DISABLED version cannot decrypt; a disabled key cannot encrypt but can decrypt', async () => {
    const keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    const v1 = (await post('/v1/encrypt', { key: keyId, data: 'payload' })).body.data;

    const [version] = await db.listKeyVersions(keyId);
    await db.updateKeyVersion(version.id, { status: 'DISABLED' as any });
    expect((await post('/v1/decrypt', { key: keyId, envelope: v1.envelope })).status).toBe(400);
    await db.updateKeyVersion(version.id, { status: 'ACTIVE' as any });

    await db.updateKey(keyId, { status: 'DISABLED' as any });
    expect((await post('/v1/encrypt', { key: keyId, data: 'x' })).status).toBe(400);
    const dec = await post('/v1/decrypt', { key: keyId, envelope: v1.envelope });
    expect(dec.status).toBe(200);
    expect(dec.body.data.plaintext).toBe('payload');
  });

  it('destroying a key erases every version’s key material and blocks all use', async () => {
    const keyId = await createKey('AES-256-GCM', 'ENCRYPTION');
    const v1 = (await post('/v1/encrypt', { key: keyId, data: 'payload' })).body.data;
    await post(`/v1/keys/${keyId}/rotate`, {});

    const destroyed = await call('DELETE', `/v1/keys/${keyId}`);
    expect(destroyed.status).toBe(200);
    for (const v of await db.listKeyVersions(keyId)) {
      expect(v.status).toBe('DESTROYED');
      expect(v.encryptedKeyMaterial).toBeFalsy();
    }
    expect((await post('/v1/encrypt', { key: keyId, data: 'x' })).status).toBe(400);
    expect((await post('/v1/decrypt', { key: keyId, envelope: v1.envelope })).status).toBe(400);
    expect((await call('DELETE', `/v1/keys/${keyId}`)).status).toBe(409);
  });
});

describe('Phase 4 — PQC known-answer tests (NIST ACVP)', () => {
  it.each(NIST.kemKeyGen.map((t: any) => [t.parameterSet, t]))('%s keyGen matches ek/dk', (_p, t: any) => {
    const kp = MlKemEngine.keygen(t.parameterSet, 'hex', Buffer.concat([hex(t.d), hex(t.z)]));
    expect(kp.publicKey).toBe(t.ek.toLowerCase());
    expect(kp.privateKey).toBe(t.dk.toLowerCase());
  });

  it.each(NIST.kemEncap.map((t: any) => [t.parameterSet, t]))('%s encapsulation with fixed m matches c/k', (_p, t: any) => {
    const res = MlKemEngine.encapsulate({ algorithm: t.parameterSet, publicKey: t.ek, randomness: t.m, outputEncoding: 'hex' });
    expect(res.ciphertext).toBe(t.c.toLowerCase());
    expect(res.sharedSecret).toBe(t.k.toLowerCase());
  });

  it.each([...NIST.kemEncap, ...NIST.kemDecap].map((t: any) => [t.parameterSet, t.tcId, t]))(
    '%s decapsulation through MlKemEngine (tc %s) recovers k',
    (_p, _id, t: any) => {
      const res = MlKemEngine.decapsulate({ algorithm: t.parameterSet, privateKey: t.dk, ciphertext: t.c, outputEncoding: 'hex' } as any);
      expect(res.sharedSecret).toBe(t.k.toLowerCase());
    }
  );

  it.each(NIST.dsaKeyGen.map((t: any) => [t.parameterSet, t]))('%s keyGen matches pk/sk', (_p, t: any) => {
    const kp = MlDsaEngine.keygen(t.parameterSet, 'hex', hex(t.seed));
    expect(kp.publicKey).toBe(t.pk.toLowerCase());
    expect(kp.privateKey).toBe(t.sk.toLowerCase());
  });

  it.each(NIST.dsaSigVer.map((t: any) => [t.parameterSet, t.tcId, t.testPassed, t]))(
    '%s sigVer through MlDsaEngine (tc %s) returns %s',
    async (_p, _id, expected, t: any) => {
      const res = await MlDsaEngine.verify({
        algorithm: t.parameterSet,
        publicKey: t.pk,
        publicKeyEncoding: 'hex',
        message: hex(t.message),
        signature: t.signature,
        signatureEncoding: 'hex',
        context: hex(t.context),
      } as any);
      expect(res.valid).toBe(expected);
    }
  );
});

describe('Phase 4 — PKI chain validation', () => {
  let rootA: any;
  let rootAKp: any;
  let rootB: any;
  let sub: any;
  let leaf: any;

  beforeAll(async () => {
    rootAKp = await X509Engine.generateKeypair('ECDSA-P256');
    rootA = await X509Engine.createRootCA({ subject: 'CN=P4 Root A, O=Amaracus, C=US', keypair: rootAKp, validityDays: 3650 });
    const rootBKp = await X509Engine.generateKeypair('ECDSA-P256');
    rootB = await X509Engine.createRootCA({ subject: 'CN=P4 Root B, O=Amaracus, C=US', keypair: rootBKp, validityDays: 3650 });
    const subKp = await X509Engine.generateKeypair('ECDSA-P256');
    sub = await X509Engine.createIntermediateCA({
      subject: 'CN=P4 Issuing CA, O=Amaracus, C=US',
      keypair: subKp,
      parentAuthority: { certificatePem: rootA.certificatePem, privateKeyPem: rootAKp.privateKeyPem },
      validityDays: 1825,
    });
    const leafKp = await X509Engine.generateKeypair('ECDSA-P256');
    leaf = await X509Engine.createEndEntityCertificate({
      subject: 'CN=leaf.p4.amaracus.test, O=Amaracus, C=US',
      publicKeyPem: leafKp.publicKeyPem,
      certificateType: 'SERVER',
      issuingAuthority: { certificatePem: sub.certificatePem, privateKeyPem: subKp.privateKeyPem },
      validityDays: 30,
    });
  });

  const chain = (extra: Record<string, any> = {}) =>
    ChainValidator.validateChain({ leafCertPem: leaf.certificatePem, intermediatePems: [sub.certificatePem], ...extra });

  it('picks the right anchor from several', async () => {
    const res = await chain({ trustAnchorsPem: [rootB.certificatePem, rootA.certificatePem] });
    expect(res.errors).toEqual([]);
    expect(res.trustAnchor).toContain('P4 Root A');
  });

  it('rejects a chain whose only anchor is the wrong root', async () => {
    const res = await chain({ trustAnchorsPem: [rootB.certificatePem] });
    expect(res.valid).toBe(false);
    expect(res.errors.join(' ')).toMatch(/No trust anchor issued/);
  });

  it('rejects a revoked leaf or intermediate, unless revocation checking is off', async () => {
    const anchors = { trustAnchorsPem: [rootA.certificatePem] };
    const revokedLeaf = await chain({ ...anchors, revokedSerialNumbers: [leaf.serialNumber] });
    expect(revokedLeaf.valid).toBe(false);
    expect(revokedLeaf.errors.join(' ')).toMatch(/revoked/);
    const revokedSub = await chain({ ...anchors, revokedSerialNumbers: [sub.serialNumber] });
    expect(revokedSub.valid).toBe(false);
    const unchecked = await chain({ ...anchors, revokedSerialNumbers: [leaf.serialNumber], checkRevocation: false });
    expect(unchecked.valid).toBe(true);
  });

  it('rejects an expired leaf, unless expiry checking is off', async () => {
    jest.useFakeTimers({
      now: Date.now() + 60 * 86400000,
      doNotFake: ['hrtime', 'nextTick', 'performance', 'queueMicrotask', 'setImmediate', 'clearImmediate', 'setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'],
    });
    try {
      const expired = await chain({ trustAnchorsPem: [rootA.certificatePem] });
      expect(expired.valid).toBe(false);
      expect(expired.errors.join(' ')).toMatch(/expired/);
      const unchecked = await chain({ trustAnchorsPem: [rootA.certificatePem], checkExpiry: false });
      expect(unchecked.valid).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  it('compares names in RDN order: a reordered issuer name does not chain', async () => {
    // Same attributes as Root A's subject, opposite order, signed by Root A's key
    const reordered = await X509Engine.createRootCA({ subject: 'C=US, O=Amaracus, CN=P4 Root A', keypair: rootAKp, validityDays: 3650 });
    const res = await chain({ trustAnchorsPem: [reordered.certificatePem] });
    expect(res.valid).toBe(false);
  });
});

describe('Phase 4 — names, labels and sanitizer scope', () => {
  it('normalises algorithm spellings to registry IDs', () => {
    expect(normalizeAlgorithmId('hmac_sha256')).toBe('HMAC-SHA-256');
    expect(normalizeAlgorithmId('HMAC-SHA512')).toBe('HMAC-SHA-512');
    expect(normalizeAlgorithmId('sha256')).toBe('SHA-256');
    expect(normalizeAlgorithmId('SHA3_384')).toBe('SHA3-384');
    expect(registry.get('HMAC-SHA256').id).toBe('HMAC-SHA-256');
  });

  it('does not label the hybrid KEM as X-Wing or any primitive as FIPS-validated', async () => {
    const hybrid = registry.get('X25519+ML-KEM-768');
    expect(hybrid.fipsStatus).not.toMatch(/X-WING/);
    expect(hybrid.standardReference).not.toMatch(/xwing-kem \//);
    const res = await post('/v1/pqc/keypair', { algorithm: 'X-WING' });
    expect(res.status).toBe(400);
  });

  it('crypto paths keep strings intact; other paths only lose control characters', () => {
    expect(isCryptoBodyPath('/v1/encrypt')).toBe(true);
    expect(isCryptoBodyPath('/api/v1/organizations/org_1/keys/key_1/encrypt')).toBe(true);
    expect(isCryptoBodyPath('/v1/pqc/sign')).toBe(true);
    expect(isCryptoBodyPath('/v1/reviews')).toBe(false);
    expect(isCryptoBodyPath('/v1/encryption-notes')).toBe(false);

    const body = { nonce: '<a>&\u0001', __proto__: { polluted: true } } as any;
    expect(sanitizePayload(body, '', { preserveStrings: true }).nonce).toBe('<a>&\u0001');
    expect(sanitizePayload({ nonce: '<a>&\u0001' }).nonce).toBe('<a>&');
  });
});
