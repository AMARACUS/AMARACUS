import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 4 — Crypto API Routes & Tenant Security', () => {
  let server: http.Server;
  let baseUrl: string;

  let userA: any;
  let sessionA: any;
  let orgA: any;

  let userB: any;
  let sessionB: any;
  let orgB: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Set up Tenant A
    userA = await db.createUser({
      email: `crypto_user_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A User',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Cryptography Corp',
      slug: `tenant-a-crypto-${Date.now()}`,
    });
    await db.addMember({
      organizationId: orgA.id,
      userId: userA.id,
      role: 'OWNER',
    });
    sessionA = await db.createSession({
      userId: userA.id,
      activeOrgId: orgA.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Set up Tenant B
    userB = await db.createUser({
      email: `crypto_user_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B User',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Security Ltd',
      slug: `tenant-b-sec-${Date.now()}`,
    });
    await db.addMember({
      organizationId: orgB.id,
      userId: userB.id,
      role: 'OWNER',
    });
    sessionB = await db.createSession({
      userId: userB.id,
      activeOrgId: orgB.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
  }, 60000);

  afterAll((done) => {
    server.close(done);
  });

  // --- 1. ALGORITHM CATALOG ---
  describe('GET /v1/organizations/:orgId/crypto/algorithms', () => {
    it('returns the algorithm registry for authenticated org member', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/algorithms`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      const data = await res.json();

      expect(res.status).toBe(200);
      expect(Array.isArray(data.data)).toBe(true);
      expect(data.data.some((a: any) => a.id === 'AES-256-GCM')).toBe(true);
      expect(data.data.some((a: any) => a.id === 'SHA-256')).toBe(true);
    });

    it('rejects unauthenticated caller with 401', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/algorithms`);
      expect(res.status).toBe(401);
    });

    it('rejects cross-tenant access with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/algorithms`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      const data = await res.json();

      expect(res.status).toBe(403);
      expect(data.error.code).toBe('FORBIDDEN');
    });
  });

  // --- 2. HASH ENDPOINT ---
  describe('POST /v1/organizations/:orgId/crypto/hash', () => {
    it('computes real SHA-256 hash and records safe audit event', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'SHA-256',
          data: 'NIST Test String',
        }),
      });
      const data = await res.json();

      expect(res.status).toBe(200);
      expect(data.data.digest).toBeDefined();
      expect(data.meta.executionTimingMs).toBeDefined();

      // Check audit log
      const auditEvents = await db.getAuditEventsByOrg(orgA.id);
      const hashAudit = auditEvents.find((e) => e.action === 'crypto:hash');
      expect(hashAudit).toBeDefined();
      expect(hashAudit?.resourceId).toBe('SHA-256');
      expect(JSON.stringify(hashAudit?.metadata)).not.toContain('NIST Test String');
    });

    it('rejects unsupported algorithm with 400', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'UNSUPPORTED_HASH',
          data: 'test',
        }),
      });
      const data = await res.json();

      expect(res.status).toBe(400);
      expect(data.error.code).toBe('UNSUPPORTED_ALGORITHM');
    });
  });

  // --- 3. HMAC ENDPOINT ---
  describe('POST /v1/organizations/:orgId/crypto/hmac and /verify', () => {
    it('computes HMAC and verifies it correctly', async () => {
      const key = 'secret_hmac_key_test_123';
      const msg = 'Critical Financial Transaction #99481';

      const macRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hmac`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'HMAC-SHA-256',
          key,
          data: msg,
        }),
      });
      const macData = await macRes.json();
      expect(macRes.status).toBe(200);
      const mac = macData.data.mac;
      expect(mac).toBeDefined();

      // Verify MAC
      const verifyRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hmac/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'HMAC-SHA-256',
          key,
          data: msg,
          mac,
        }),
      });
      const verifyData = await verifyRes.json();
      expect(verifyRes.status).toBe(200);
      expect(verifyData.data.valid).toBe(true);

      // Verify tampered MAC fails
      const badVerifyRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/hmac/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'HMAC-SHA-256',
          key,
          data: 'Tampered Transaction',
          mac,
        }),
      });
      const badVerifyData = await badVerifyRes.json();
      expect(badVerifyRes.status).toBe(200);
      expect(badVerifyData.data.valid).toBe(false);
    });
  });

  // --- 4. ENCRYPT AND DECRYPT (AES-256-GCM) ---
  describe('POST /v1/organizations/:orgId/crypto/encrypt and /decrypt', () => {
    const key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const plaintext = 'Sensitive Patient Health Record #7721';
    const aad = 'Hospital_A:Patient_7721';

    it('encrypts and decrypts payload seamlessly', async () => {
      const encRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'AES-256-GCM',
          key,
          keyEncoding: 'hex',
          plaintext,
          aad,
        }),
      });
      const encData = await encRes.json();

      expect(encRes.status).toBe(200);
      const envelope = encData.data;
      expect(envelope.v).toBe(1);
      expect(envelope.alg).toBe('AES-256-GCM');
      expect(envelope.iv).toBeDefined();
      expect(envelope.ct).toBeDefined();
      expect(envelope.tag).toBeDefined();

      const decRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          envelope,
          key,
          keyEncoding: 'hex',
        }),
      });
      const decData = await decRes.json();

      expect(decRes.status).toBe(200);
      expect(decData.data.plaintext).toBe(plaintext);
    });

    it('rejects decryption with wrong key with 400 AUTHENTICATION_FAILED', async () => {
      const encRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'AES-256-GCM',
          key,
          keyEncoding: 'hex',
          plaintext,
        }),
      });
      const encData = await encRes.json();
      const envelope = encData.data;
      const wrongKey = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

      const decRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          envelope,
          key: wrongKey,
          keyEncoding: 'hex',
        }),
      });
      const decData = await decRes.json();

      expect(decRes.status).toBe(400);
      expect(decData.error.code).toBe('AUTHENTICATION_FAILED');
    });
  });

  // --- 5. SIGN AND VERIFY (ED25519) ---
  describe('POST /v1/organizations/:orgId/crypto/sign and /verify', () => {
    it('generates keypair, signs message, and verifies signature', async () => {
      const kpRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/keypair`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({ algorithm: 'ED25519' }),
      });
      const kpData = await kpRes.json();
      expect(kpRes.status).toBe(200);
      const { publicKey, privateKey } = kpData.data;

      const message = 'Deploy Production Smart Contract 0x123';

      const signRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ED25519',
          privateKey,
          message,
        }),
      });
      const signData = await signRes.json();
      expect(signRes.status).toBe(200);
      const signature = signData.data.signature;

      const verifyRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          algorithm: 'ED25519',
          publicKey,
          message,
          signature,
        }),
      });
      const verifyData = await verifyRes.json();
      expect(verifyRes.status).toBe(200);
      expect(verifyData.data.valid).toBe(true);
    });
  });

  // --- 6. SECURE RANDOM BYTES ---
  describe('POST /v1/organizations/:orgId/crypto/random', () => {
    it('returns cryptographically secure random bytes', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/crypto/random`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({ length: 32, encoding: 'hex' }),
      });
      const data = await res.json();

      expect(res.status).toBe(200);
      expect(data.data.length).toBe(32);
      expect(data.data.random.length).toBe(64);
    });
  });
});
