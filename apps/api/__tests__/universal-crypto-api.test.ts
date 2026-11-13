import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { isSelfHosted } from '../src/lib/edition';
import { listLedgerEntries } from '../src/lib/usage-ledger';

/** Billable operations of one organization: the Cloud usage record, or the self-hosted ledger. */
async function billableUsage(orgId: string): Promise<{ operationCount: number }> {
  if (!isSelfHosted()) return db.getCurrentBillingUsage(orgId);
  const entries = await listLedgerEntries(0, 5000);
  return { operationCount: entries.filter((e) => e.organizationId === orgId).reduce((n, e) => n + e.quantity, 0) };
}
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { usageMeter } from '../src/lib/usage-meter';

describe('Phase 12 — Universal Cryptographic API Integration Test Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A Context
  let tenantAOrg: any;
  let tenantAUser: any;
  let tenantAProject: any;
  let tenantAEnv: any;
  let tenantAKeyFull: string;
  let tenantAKeyEncryptOnly: string;
  let tenantAKeyHashOnly: string;

  // Tenant B Context (for isolation & IDOR tests)
  let tenantBOrg: any;
  let tenantBUser: any;
  let tenantBProject: any;
  let tenantBEnv: any;
  let tenantBKeyFull: string;
  let tenantBLogicalKeyId: string;

  beforeAll(async () => {
    // 1. Start Server on random port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 2. Setup Tenant A
    tenantAOrg = await db.createOrganization({
      name: 'Tenant A Cryptographic Corp',
      slug: `tenant-a-${Date.now()}`,
    });

    tenantAUser = await db.createUser({
      email: `alice_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Alice Admin',
    });

    await db.addMember({
      organizationId: tenantAOrg.id,
      userId: tenantAUser.id,
      role: 'OWNER',
    });

    tenantAProject = await db.createProject({
      organizationId: tenantAOrg.id,
      name: 'Payments System',
      slug: 'payments',
    });

    tenantAEnv = await db.createEnvironment({
      projectId: tenantAProject.id,
      name: 'Production',
      slug: 'production',
      type: 'PRODUCTION',
    });

    // Seed active billing plan with ample allowance
    await db.upsertBillingSubscription({
      organizationId: tenantAOrg.id,
      plan: 'BUSINESS',
      status: 'ACTIVE',
      polarSubscriptionId: `sub_tenant_a_${Date.now()}`,
    });

    // Generate Full-Access API Key for Tenant A
    const genFull = generateAmaracusApiKey('live');
    tenantAKeyFull = genFull.fullKey;
    await db.createApiCredential({
      organizationId: tenantAOrg.id,
      projectId: tenantAProject.id,
      environmentId: tenantAEnv.id,
      name: 'Tenant A Full Key',
      prefix: genFull.prefix,
      keyHash: genFull.keyHash,
      scopes: ['*'],
    });

    // Generate Encrypt-Only Scoped Key for Tenant A
    const genEncOnly = generateAmaracusApiKey('live');
    tenantAKeyEncryptOnly = genEncOnly.fullKey;
    await db.createApiCredential({
      organizationId: tenantAOrg.id,
      projectId: tenantAProject.id,
      environmentId: tenantAEnv.id,
      name: 'Tenant A Encrypt Only',
      prefix: genEncOnly.prefix,
      keyHash: genEncOnly.keyHash,
      scopes: ['crypto:encrypt'],
    });

    // Generate Hash-Only Scoped Key for Tenant A
    const genHashOnly = generateAmaracusApiKey('live');
    tenantAKeyHashOnly = genHashOnly.fullKey;
    await db.createApiCredential({
      organizationId: tenantAOrg.id,
      projectId: tenantAProject.id,
      environmentId: tenantAEnv.id,
      name: 'Tenant A Hash Only',
      prefix: genHashOnly.prefix,
      keyHash: genHashOnly.keyHash,
      scopes: ['crypto:hash'],
    });

    // 3. Setup Tenant B (for cross-tenant IDOR verification)
    tenantBOrg = await db.createOrganization({
      name: 'Tenant B Logistics Inc',
      slug: `tenant-b-${Date.now()}`,
    });

    tenantBUser = await db.createUser({
      email: `bob_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Bob Admin',
    });

    await db.addMember({
      organizationId: tenantBOrg.id,
      userId: tenantBUser.id,
      role: 'OWNER',
    });

    tenantBProject = await db.createProject({
      organizationId: tenantBOrg.id,
      name: 'Logistics Vault',
      slug: 'logistics',
    });

    tenantBEnv = await db.createEnvironment({
      projectId: tenantBProject.id,
      name: 'Production',
      slug: 'production',
      type: 'PRODUCTION',
    });

    await db.upsertBillingSubscription({
      organizationId: tenantBOrg.id,
      plan: 'PRO',
      status: 'ACTIVE',
      polarSubscriptionId: `sub_tenant_b_${Date.now()}`,
    });

    const genB = generateAmaracusApiKey('live');
    tenantBKeyFull = genB.fullKey;
    await db.createApiCredential({
      organizationId: tenantBOrg.id,
      projectId: tenantBProject.id,
      environmentId: tenantBEnv.id,
      name: 'Tenant B Full Key',
      prefix: genB.prefix,
      keyHash: genB.keyHash,
      scopes: ['*'],
    });

    // Create a logical key inside Tenant B
    const bKeyRes = await fetch(`${baseUrl}/v1/keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tenantBKeyFull}`,
      },
      body: JSON.stringify({
        name: 'tenant-b-secret-key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
      }),
    });
    const bKeyData = await bKeyRes.json();
    tenantBLogicalKeyId = bKeyData.data.id;
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  // =========================================================================
  // 1. PUBLIC DISCOVERY & CAPABILITIES
  // =========================================================================
  describe('1. Public Discovery Endpoints (GET /v1/capabilities & /v1/algorithms)', () => {
    it('GET /v1/capabilities - returns platform cryptographic capabilities without auth', async () => {
      const res = await fetch(`${baseUrl}/v1/capabilities`);
      expect(res.status).toBe(200);
      const json = await res.json();

      expect(json.data).toBeDefined();
      expect(json.data.version).toBe('1.0.0');
      expect(json.data.supportedOperations).toContain('ENCRYPT');
      expect(json.data.supportedOperations).toContain('DECRYPT');
      expect(json.data.supportedOperations).toContain('HASH');
      expect(json.data.supportedOperations).toContain('SIGN');
      expect(json.data.supportedOperations).toContain('VERIFY');
      expect(json.data.features.zeroSecretLeakage).toBe(true);
      expect(json.data.features.billingUsageProtection).toBe(true);
      expect(json.requestId).toBeDefined();
    });

    it('GET /api/v1/capabilities - accessible under canonical /api/v1 namespace', async () => {
      const res = await fetch(`${baseUrl}/api/v1/capabilities`);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.supportedOperations).toBeDefined();
    });

    it('GET /v1/algorithms - returns full cryptographic algorithm catalog', async () => {
      const res = await fetch(`${baseUrl}/v1/algorithms`);
      expect(res.status).toBe(200);
      const json = await res.json();

      expect(Array.isArray(json.data)).toBe(true);
      expect(json.meta.count).toBeGreaterThanOrEqual(10);
      const ids = json.data.map((a: any) => a.id);
      expect(ids).toContain('AES-256-GCM');
      expect(ids).toContain('ED25519');
      expect(ids).toContain('SHA-256');
    });
  });

  // =========================================================================
  // 2. AUTHENTICATION & SCOPING
  // =========================================================================
  describe('2. Authentication & Granular Scopes', () => {
    it('rejects unauthenticated requests to protected endpoints with 401', async () => {
      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          data: 'sensitive data',
          rawKey: crypto.randomBytes(32).toString('hex'),
        }),
      });
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects invalid or forged API keys with 401', async () => {
      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer am_live_invalidkey1234567890abcdef1234567890abcdef',
        },
        body: JSON.stringify({
          data: 'sensitive data',
          rawKey: crypto.randomBytes(32).toString('hex'),
        }),
      });
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error.code).toBe('INVALID_API_KEY');
    });

    it('enforces granular scopes: rejects encrypt when key only has crypto:hash scope with 403', async () => {
      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyHashOnly}`,
        },
        body: JSON.stringify({
          data: 'sensitive data',
          rawKey: crypto.randomBytes(32).toString('hex'),
        }),
      });
      expect(res.status).toBe(403);
      const json = await res.json();
      expect(['INSUFFICIENT_SCOPE', 'FORBIDDEN']).toContain(json.error.code);
    });

    it('allows hash when key has crypto:hash scope', async () => {
      const res = await fetch(`${baseUrl}/v1/hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyHashOnly}`,
        },
        body: JSON.stringify({
          data: 'Hello AMARACUS Hashing',
          algorithm: 'SHA-256',
        }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.digest).toBeDefined();
    });

    it('allows encrypt when key has crypto:encrypt scope', async () => {
      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyEncryptOnly}`,
        },
        body: JSON.stringify({
          data: 'Scoped user payload',
          rawKey: crypto.randomBytes(32).toString('hex'),
        }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.ciphertext).toBeDefined();
    });
  });

  // =========================================================================
  // 3. LOGICAL KEY MANAGEMENT (/v1/keys)
  // =========================================================================
  describe('3. Logical Key Management Lifecycle (POST, GET, ROTATE, PATCH, DELETE)', () => {
    let createdKeyId: string;

    it('POST /v1/keys - creates a new AES-256-GCM logical key without leaking secrets', async () => {
      const res = await fetch(`${baseUrl}/v1/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          name: 'payments-master-key',
          algorithm: 'AES-256-GCM',
          purpose: 'ENCRYPT_DECRYPT',
          description: 'Master key for customer card tokens',
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.id).toBeDefined();
      expect(json.data.name).toBe('payments-master-key');
      expect(json.data.algorithm).toBe('AES-256-GCM');
      expect(json.data.currentVersion).toBe(1);
      expect(json.data.status).toBe('ACTIVE');

      // Zero-Secret-Leakage: Ensure no encryptedKeyMaterial or privateKey in response
      expect((json.data as any).encryptedKeyMaterial).toBeUndefined();
      expect((json.data as any).privateKey).toBeUndefined();

      createdKeyId = json.data.id;
    });

    it('GET /v1/keys - lists tenant keys with pagination', async () => {
      const res = await fetch(`${baseUrl}/v1/keys?limit=10`, {
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThanOrEqual(1);
      expect(json.meta.count).toBeDefined();
      const found = json.data.find((k: any) => k.id === createdKeyId);
      expect(found).toBeDefined();
    });

    it('GET /v1/keys/:keyId - retrieves sanitized key metadata', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/${createdKeyId}`, {
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.id).toBe(createdKeyId);
      expect(json.data.currentVersion).toBe(1);
      expect((json.data as any).encryptedKeyMaterial).toBeUndefined();
    });

    it('POST /v1/keys/:keyId/rotate - rotates key to version 2', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/${createdKeyId}/rotate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.currentVersion).toBe(2);
      expect(json.data.status).toBe('ACTIVE');
    });

    it('PATCH /v1/keys/:keyId - updates key description and status', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/${createdKeyId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          description: 'Updated description for card tokenization',
        }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.description).toBe('Updated description for card tokenization');
    });

    it('GET /v1/keys/providers - retrieves provider health information', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/providers`, {
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThan(0);
      expect(json.meta.count).toBeDefined();
    });

    it('DELETE /v1/keys/:keyId - destroys key safely', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/${createdKeyId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.status).toBe('DESTROYED');
    });
  });

  // =========================================================================
  // 4. TENANT ISOLATION & IDOR DEFENSE
  // =========================================================================
  describe('4. Tenant Isolation & IDOR Defense', () => {
    it('Tenant A cannot retrieve Tenant B logical key (returns 404)', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/${tenantBLogicalKeyId}`, {
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });
      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('KEY_NOT_FOUND');
    });

    it('Tenant A cannot rotate Tenant B logical key (returns 404)', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/${tenantBLogicalKeyId}/rotate`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });
      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('KEY_NOT_FOUND');
    });

    it('Tenant A cannot encrypt data using Tenant B key (returns 400 or 404 KEY_NOT_FOUND)', async () => {
      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: tenantBLogicalKeyId,
          data: 'Unauthorized cross-tenant plaintext',
        }),
      });
      expect([400, 404]).toContain(res.status);
      const json = await res.json();
      expect(json.error.code).toBe('KEY_NOT_FOUND');
    });

    it('Tenant A cannot delete Tenant B logical key (returns 404)', async () => {
      const res = await fetch(`${baseUrl}/v1/keys/${tenantBLogicalKeyId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });
      expect(res.status).toBe(404);
    });
  });

  // =========================================================================
  // 5. ENCRYPT & DECRYPT OPERATIONS
  // =========================================================================
  describe('5. Universal Encryption & Decryption (POST /v1/encrypt & /v1/decrypt)', () => {
    let logicalKeyId: string;
    let encryptedEnvelope: any;

    beforeAll(async () => {
      // Create fresh logical encryption key in Tenant A
      const res = await fetch(`${baseUrl}/v1/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          name: 'crypto-ops-key',
          algorithm: 'AES-256-GCM',
          purpose: 'ENCRYPT_DECRYPT',
        }),
      });
      const data = await res.json();
      logicalKeyId = data.data.id;
    });

    it('encrypts plaintext with logical key and returns standard envelope', async () => {
      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: logicalKeyId,
          data: 'Sensitive customer payment data 1234-5678-9012-3456',
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.ciphertext).toBeDefined();
      expect(json.data.iv).toBeDefined();
      expect(json.data.tag).toBeDefined();
      expect(json.data.algorithm).toBe('AES-256-GCM');
      expect(json.data.keyId).toBe(logicalKeyId);
      expect(json.data.format).toBe('v1');
      expect(json.operationId).toBeDefined();
      expect(json.status).toBe('COMPLETED');

      encryptedEnvelope = json.data;
    });

    it('decrypts envelope using logical key and recovers original plaintext', async () => {
      const res = await fetch(`${baseUrl}/v1/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: logicalKeyId,
          ciphertext: encryptedEnvelope.ciphertext,
          iv: encryptedEnvelope.iv,
          tag: encryptedEnvelope.tag,
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.plaintext).toBe('Sensitive customer payment data 1234-5678-9012-3456');
    });

    it('decrypts when full envelope object is passed in request body', async () => {
      const res = await fetch(`${baseUrl}/v1/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: logicalKeyId,
          envelope: encryptedEnvelope,
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.plaintext).toBe('Sensitive customer payment data 1234-5678-9012-3456');
    });

    it('rejects tampered ciphertext with DECRYPTION_FAILED', async () => {
      // Modify single character in ciphertext
      const tamperedCt = encryptedEnvelope.ciphertext.startsWith('A')
        ? 'B' + encryptedEnvelope.ciphertext.slice(1)
        : 'A' + encryptedEnvelope.ciphertext.slice(1);

      const res = await fetch(`${baseUrl}/v1/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: logicalKeyId,
          ciphertext: tamperedCt,
          iv: encryptedEnvelope.iv,
          tag: encryptedEnvelope.tag,
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(['AUTHENTICATION_FAILED', 'DECRYPTION_FAILED']).toContain(json.error.code);
    });

    it('supports direct rawKey roundtrip without creating logical key', async () => {
      const rawSecret = crypto.randomBytes(32).toString('hex');
      const testSecret = 'Developer raw key direct encryption';

      const encRes = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          rawKey: rawSecret,
          data: testSecret,
        }),
      });

      expect(encRes.status).toBe(200);
      const encJson = await encRes.json();
      expect(encJson.data.ciphertext).toBeDefined();

      const decRes = await fetch(`${baseUrl}/v1/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          rawKey: rawSecret,
          ciphertext: encJson.data.ciphertext,
          iv: encJson.data.iv,
          tag: encJson.data.tag,
        }),
      });

      expect(decRes.status).toBe(200);
      const decJson = await decRes.json();
      expect(decJson.data.plaintext).toBe(testSecret);
    });
  });

  // =========================================================================
  // 6. CRYPTOGRAPHIC HASHING (POST /v1/hash)
  // =========================================================================
  describe('6. Cryptographic Hashing (POST /v1/hash)', () => {
    it('hashes data with SHA-256 producing valid hex digest', async () => {
      const input = 'The quick brown fox jumps over the lazy dog';
      const expectedDigest = crypto.createHash('sha256').update(input).digest('hex');

      const res = await fetch(`${baseUrl}/v1/hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          data: input,
          algorithm: 'SHA-256',
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.digest).toBe(expectedDigest);
      expect(json.data.byteLength).toBe(32);
      expect(json.data.algorithm).toBe('SHA-256');
    });

    it('hashes data with SHA-512 producing 64-byte digest', async () => {
      const input = 'High security audit log record';
      const expected = crypto.createHash('sha512').update(input).digest('hex');

      const res = await fetch(`${baseUrl}/v1/hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          data: input,
          algorithm: 'SHA-512',
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.digest).toBe(expected);
      expect(json.data.byteLength).toBe(64);
    });

    it('rejects unsupported insecure algorithms (e.g. MD5) with ALGORITHM_UNSUPPORTED', async () => {
      const res = await fetch(`${baseUrl}/v1/hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          data: 'test payload',
          algorithm: 'MD5',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('ALGORITHM_UNSUPPORTED');
    });
  });

  // =========================================================================
  // 7. SIGN & VERIFY (POST /v1/sign & /v1/verify)
  // =========================================================================
  describe('7. Digital Signatures (POST /v1/sign & /v1/verify)', () => {
    let signingKeyId: string;
    let signatureStr: string;
    const documentToSign = 'Official Contract: AMARACUS Cryptographic Infrastructure SLA';

    beforeAll(async () => {
      const res = await fetch(`${baseUrl}/v1/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          name: 'ed25519-signing-key',
          algorithm: 'ED25519',
          purpose: 'SIGN_VERIFY',
        }),
      });
      const data = await res.json();
      signingKeyId = data.data.id;
    });

    it('signs document using logical ED25519 key', async () => {
      const res = await fetch(`${baseUrl}/v1/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: signingKeyId,
          data: documentToSign,
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.signature).toBeDefined();
      expect(json.data.algorithm).toBe('ED25519');
      expect(json.data.keyId).toBe(signingKeyId);
      signatureStr = json.data.signature;
    });

    it('verifies valid signature returns valid: true', async () => {
      const res = await fetch(`${baseUrl}/v1/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: signingKeyId,
          data: documentToSign,
          signature: signatureStr,
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.valid).toBe(true);
      expect(json.data.keyId).toBe(signingKeyId);
    });

    it('verifies tampered document or tampered signature returns valid: false', async () => {
      const res = await fetch(`${baseUrl}/v1/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: signingKeyId,
          data: 'Tampered contract terms',
          signature: signatureStr,
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.valid).toBe(false);
    });
  });

  // =========================================================================
  // 8. IDEMPOTENCY & REPLAY PROTECTION
  // =========================================================================
  describe('8. Idempotency & Replay Protection (Idempotency-Key Header)', () => {
    it('repeated requests with identical Idempotency-Key return cached response', async () => {
      const idempotencyKey = `idemp_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const payload = {
        data: 'Unique financial transaction record',
        rawKey: crypto.randomBytes(32).toString('hex'),
      };

      // 1st Call
      const res1 = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(payload),
      });

      expect(res1.status).toBe(200);
      const json1 = await res1.json();
      const opId1 = json1.operationId;
      const ct1 = json1.data.ciphertext;

      // 2nd Call with identical Idempotency-Key
      const res2 = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(payload),
      });

      expect(res2.status).toBe(200);
      const json2 = await res2.json();
      // Should return the exact same operationId and ciphertext from cache
      expect(json2.operationId).toBe(opId1);
      expect(json2.data.ciphertext).toBe(ct1);
    });
  });

  // =========================================================================
  // 9. OPERATION OBSERVABILITY (GET /v1/operations/:operationId)
  // =========================================================================
  describe('9. Operation Observability (GET /v1/operations/:operationId)', () => {
    it('retrieves operation status by operationId for authorized tenant', async () => {
      // Execute an operation to produce a record
      const encRes = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          data: 'Observability check payload',
          rawKey: crypto.randomBytes(32).toString('hex'),
        }),
      });
      const encData = await encRes.json();
      const opId = encData.operationId;

      // Query operation status
      const res = await fetch(`${baseUrl}/v1/operations/${opId}`, {
        headers: { Authorization: `Bearer ${tenantAKeyFull}` },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.id).toBe(opId);
      expect(json.data.operationType).toBe('ENCRYPT');
      expect(json.data.status).toBe('COMPLETED');
    });

    it('Tenant B cannot inspect Tenant A operation record (returns 404)', async () => {
      const encRes = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          data: 'Cross tenant test',
          rawKey: crypto.randomBytes(32).toString('hex'),
        }),
      });
      const encData = await encRes.json();
      const opId = encData.operationId;

      // Tenant B tries to inspect opId
      const res = await fetch(`${baseUrl}/v1/operations/${opId}`, {
        headers: { Authorization: `Bearer ${tenantBKeyFull}` },
      });

      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // 10. ZERO-SECRET-LEAKAGE & AUDIT LOG INTEGRITY
  // =========================================================================
  describe('10. Zero-Secret-Leakage & Audit Log Verification', () => {
    it('confirms audit events record operation metadata without secret keys or plaintexts', async () => {
      const auditEvents = await db.getAuditEventsByOrg(tenantAOrg.id);
      expect(auditEvents.length).toBeGreaterThan(0);

      for (const ev of auditEvents) {
        const metaStr = JSON.stringify(ev.metadata || {});
        // Never contain raw key material
        expect(metaStr).not.toContain('encryptedKeyMaterial');
        expect(metaStr).not.toContain('privateKey');
        expect(metaStr).not.toContain('Sensitive customer payment data');
        expect(metaStr).not.toContain('Developer raw key direct encryption');
      }
    });
  });

  // =========================================================================
  // 11. BILLING & USAGE METERING INTEGRATION
  // =========================================================================
  describe('11. Billing Usage Metering Integration', () => {
    it('increments usage count on successful cryptographic operation', async () => {
      const initialUsage = await billableUsage(tenantAOrg.id);
      const initialCount = initialUsage.operationCount;

      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          data: 'Billing increment test',
          rawKey: crypto.randomBytes(32).toString('hex'),
        }),
      });

      expect(res.status).toBe(200);

      // Allow async audit sink / usage meter to persist
      let postUsage = await billableUsage(tenantAOrg.id);
      for (let i = 0; i < 10 && postUsage.operationCount <= initialCount; i++) {
        await new Promise((r) => setTimeout(r, 50));
        postUsage = await billableUsage(tenantAOrg.id);
      }
      expect(postUsage.operationCount).toBeGreaterThan(initialCount);
    });

    it('does NOT increment usage when request is rejected with validation error', async () => {
      // Ensure any previous background operations have fully settled
      await new Promise((r) => setTimeout(r, 150));

      const beforeUsage = await billableUsage(tenantAOrg.id);
      const beforeCount = beforeUsage.operationCount;

      const res = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          // Missing data and key
        }),
      });

      expect(res.status).toBe(400);

      await new Promise((r) => setTimeout(r, 150));
      const afterUsage = await billableUsage(tenantAOrg.id);
      expect(afterUsage.operationCount).toBe(beforeCount);
    });
  });
});
