import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import {
  Amaracus,
  AmaracusError,
  AmaracusAuthenticationError,
  AmaracusAuthorizationError,
  AmaracusValidationError,
  AmaracusNotFoundError,
} from '@amaracus/sdk';

describe('Phase 13 — Official AMARACUS SDK (@amaracus/sdk) Contract Test Suite', () => {
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

  // Tenant B Context
  let tenantBOrg: any;
  let tenantBUser: any;
  let tenantBProject: any;
  let tenantBEnv: any;
  let tenantBKeyFull: string;
  let tenantBLogicalKeyId: string;

  // SDK Clients
  let sdkTenantA: Amaracus;
  let sdkTenantAEncryptOnly: Amaracus;
  let sdkTenantAHashOnly: Amaracus;
  let sdkTenantB: Amaracus;
  let sdkInvalidKey: Amaracus;

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
      name: 'Tenant A SDK Corp',
      slug: `tenant-a-sdk-${Date.now()}`,
    });

    tenantAUser = await db.createUser({
      email: `alice_sdk_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Alice SDK',
    });

    await db.addMember({
      organizationId: tenantAOrg.id,
      userId: tenantAUser.id,
      role: 'OWNER',
    });

    tenantAProject = await db.createProject({
      organizationId: tenantAOrg.id,
      name: 'SDK Payments System',
      slug: 'sdk-payments',
    });

    tenantAEnv = await db.createEnvironment({
      projectId: tenantAProject.id,
      name: 'Production',
      slug: 'production',
      type: 'PRODUCTION',
    });

    await db.upsertBillingSubscription({
      organizationId: tenantAOrg.id,
      plan: 'BUSINESS',
      status: 'ACTIVE',
      polarSubscriptionId: `sub_sdk_a_${Date.now()}`,
    });

    // Keys for Tenant A
    const genFull = generateAmaracusApiKey('live');
    tenantAKeyFull = genFull.fullKey;
    await db.createApiCredential({
      organizationId: tenantAOrg.id,
      projectId: tenantAProject.id,
      environmentId: tenantAEnv.id,
      name: 'Tenant A SDK Full Key',
      prefix: genFull.prefix,
      keyHash: genFull.keyHash,
      scopes: ['*'],
    });

    const genEncOnly = generateAmaracusApiKey('live');
    tenantAKeyEncryptOnly = genEncOnly.fullKey;
    await db.createApiCredential({
      organizationId: tenantAOrg.id,
      projectId: tenantAProject.id,
      environmentId: tenantAEnv.id,
      name: 'Tenant A SDK Encrypt Only',
      prefix: genEncOnly.prefix,
      keyHash: genEncOnly.keyHash,
      scopes: ['crypto:encrypt'],
    });

    const genHashOnly = generateAmaracusApiKey('live');
    tenantAKeyHashOnly = genHashOnly.fullKey;
    await db.createApiCredential({
      organizationId: tenantAOrg.id,
      projectId: tenantAProject.id,
      environmentId: tenantAEnv.id,
      name: 'Tenant A SDK Hash Only',
      prefix: genHashOnly.prefix,
      keyHash: genHashOnly.keyHash,
      scopes: ['crypto:hash'],
    });

    // 3. Setup Tenant B
    tenantBOrg = await db.createOrganization({
      name: 'Tenant B SDK Logistics',
      slug: `tenant-b-sdk-${Date.now()}`,
    });

    tenantBUser = await db.createUser({
      email: `bob_sdk_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Bob SDK',
    });

    await db.addMember({
      organizationId: tenantBOrg.id,
      userId: tenantBUser.id,
      role: 'OWNER',
    });

    tenantBProject = await db.createProject({
      organizationId: tenantBOrg.id,
      name: 'Logistics Project',
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
      polarSubscriptionId: `sub_sdk_b_${Date.now()}`,
    });

    const genB = generateAmaracusApiKey('live');
    tenantBKeyFull = genB.fullKey;
    await db.createApiCredential({
      organizationId: tenantBOrg.id,
      projectId: tenantBProject.id,
      environmentId: tenantBEnv.id,
      name: 'Tenant B SDK Full Key',
      prefix: genB.prefix,
      keyHash: genB.keyHash,
      scopes: ['*'],
    });

    // Create a key for Tenant B
    sdkTenantB = new Amaracus({ apiKey: tenantBKeyFull, baseUrl });
    const bKey = await sdkTenantB.keys.create({
      name: 'tenant-b-isolated-key',
      algorithm: 'AES-256-GCM',
      purpose: 'ENCRYPT_DECRYPT',
    });
    tenantBLogicalKeyId = bKey.id;

    // 4. Initialize SDK Instances for Tenant A
    sdkTenantA = new Amaracus({ apiKey: tenantAKeyFull, baseUrl });
    sdkTenantAEncryptOnly = new Amaracus({ apiKey: tenantAKeyEncryptOnly, baseUrl });
    sdkTenantAHashOnly = new Amaracus({ apiKey: tenantAKeyHashOnly, baseUrl });
    sdkInvalidKey = new Amaracus({ apiKey: 'am_live_invalid_key_1234567890abcdef1234567890', baseUrl });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  // =========================================================================
  // 1. CAPABILITY & ALGORITHM DISCOVERY
  // =========================================================================
  describe('1. Capability Discovery via SDK', () => {
    it('amaracus.capabilities.get() retrieves platform cryptographic capabilities', async () => {
      const caps = await sdkTenantA.capabilities.get();
      expect(caps).toBeDefined();
      expect(caps.version).toBe('1.0.0');
      expect(caps.supportedOperations).toContain('ENCRYPT');
      expect(caps.supportedOperations).toContain('DECRYPT');
      expect(caps.supportedOperations).toContain('HASH');
      expect(caps.supportedOperations).toContain('SIGN');
      expect(caps.supportedOperations).toContain('VERIFY');
      expect(caps.features.zeroSecretLeakage).toBe(true);
      expect(caps.features.billingUsageProtection).toBe(true);
    });

    it('amaracus.algorithms.list() retrieves algorithm catalog', async () => {
      const algos = await sdkTenantA.algorithms.list();
      expect(Array.isArray(algos)).toBe(true);
      expect(algos.length).toBeGreaterThanOrEqual(10);
      const ids = algos.map((a) => a.id);
      expect(ids).toContain('AES-256-GCM');
      expect(ids).toContain('ED25519');
      expect(ids).toContain('SHA-256');
    });
  });

  // =========================================================================
  // 2. AUTHENTICATION & ERROR TRANSLATION
  // =========================================================================
  describe('2. Authentication & Typed Error Translation', () => {
    it('throws AmaracusAuthenticationError on invalid API key', async () => {
      await expect(
        sdkInvalidKey.encrypt({
          rawKey: crypto.randomBytes(32).toString('hex'),
          data: 'sensitive data',
        })
      ).rejects.toThrow(AmaracusAuthenticationError);
    });

    it('throws AmaracusAuthorizationError when key lacks required scope', async () => {
      await expect(
        sdkTenantAHashOnly.encrypt({
          rawKey: crypto.randomBytes(32).toString('hex'),
          data: 'sensitive data',
        })
      ).rejects.toThrow(AmaracusAuthorizationError);
    });

    it('error instance contains status, statusCode, code, and requestId', async () => {
      try {
        await sdkInvalidKey.encrypt({
          rawKey: crypto.randomBytes(32).toString('hex'),
          data: 'test',
        });
        fail('Should have thrown');
      } catch (err: any) {
        expect(err).toBeInstanceOf(AmaracusError);
        expect(err).toBeInstanceOf(AmaracusAuthenticationError);
        expect(err.status).toBe(401);
        expect(err.statusCode).toBe(401);
        expect(err.code).toBe('INVALID_API_KEY');
        expect(err.requestId).toBeDefined();
        expect(err.retryable).toBe(false);
      }
    });

    it('throws AmaracusValidationError when required parameters are missing', async () => {
      await expect(
        sdkTenantA.encrypt({
          data: undefined as any,
          rawKey: crypto.randomBytes(32).toString('hex'),
        })
      ).rejects.toThrow(AmaracusValidationError);
    });
  });

  // =========================================================================
  // 3. LOGICAL KEY MANAGEMENT LIFECYCLE
  // =========================================================================
  describe('3. Logical Key Management via SDK (keys.*)', () => {
    let createdKey: any;

    it('amaracus.keys.create() creates AES-256-GCM managed key without secret leakage', async () => {
      createdKey = await sdkTenantA.keys.create({
        name: `sdk-key-${Date.now()}`,
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
        description: 'Key created via SDK integration tests',
      });

      expect(createdKey.id).toBeDefined();
      expect(createdKey.algorithm).toBe('AES-256-GCM');
      expect(createdKey.currentVersion).toBe(1);
      expect(createdKey.status).toBe('ACTIVE');

      // Zero Secret Leakage check
      expect((createdKey as any).encryptedKeyMaterial).toBeUndefined();
      expect((createdKey as any).privateKey).toBeUndefined();
    });

    it('amaracus.keys.list() lists keys for the authenticated tenant', async () => {
      const keys = await sdkTenantA.keys.list({ limit: 10 });
      expect(Array.isArray(keys)).toBe(true);
      expect(keys.length).toBeGreaterThanOrEqual(1);
      const found = keys.find((k) => k.id === createdKey.id);
      expect(found).toBeDefined();
    });

    it('amaracus.keys.get() retrieves specific key metadata', async () => {
      const key = await sdkTenantA.keys.get(createdKey.id);
      expect(key.id).toBe(createdKey.id);
      expect(key.currentVersion).toBe(1);
    });

    it('amaracus.keys.rotate() rotates key to version 2', async () => {
      const rotated = await sdkTenantA.keys.rotate(createdKey.id);
      expect(rotated.currentVersion).toBe(2);
    });

    it('amaracus.keys.update() updates key description', async () => {
      const updated = await sdkTenantA.keys.update(createdKey.id, {
        description: 'New description updated via SDK',
      });
      expect(updated.description).toBe('New description updated via SDK');
    });

    it('amaracus.keys.providers() retrieves KMS provider health reports', async () => {
      const providers = await sdkTenantA.keys.providers();
      expect(Array.isArray(providers)).toBe(true);
      expect(providers.length).toBeGreaterThan(0);
    });

    it('amaracus.keys.delete() destroys key', async () => {
      const res = await sdkTenantA.keys.delete(createdKey.id);
      expect(res.status).toBe('DESTROYED');
    });
  });

  // =========================================================================
  // 4. TENANT ISOLATION & IDOR DEFENSE VIA SDK
  // =========================================================================
  describe('4. Tenant Isolation & IDOR Defense via SDK', () => {
    it('Tenant A client cannot get Tenant B key (throws AmaracusNotFoundError)', async () => {
      await expect(sdkTenantA.keys.get(tenantBLogicalKeyId)).rejects.toThrow(AmaracusNotFoundError);
    });

    it('Tenant A client cannot rotate Tenant B key (throws AmaracusNotFoundError)', async () => {
      await expect(sdkTenantA.keys.rotate(tenantBLogicalKeyId)).rejects.toThrow(AmaracusNotFoundError);
    });

    it('Tenant A client cannot encrypt using Tenant B key (throws error)', async () => {
      await expect(
        sdkTenantA.encrypt({
          key: tenantBLogicalKeyId,
          data: 'Cross-tenant illegal plaintext',
        })
      ).rejects.toThrow(AmaracusError);
    });

    it('Tenant A client cannot delete Tenant B key (throws AmaracusNotFoundError)', async () => {
      await expect(sdkTenantA.keys.delete(tenantBLogicalKeyId)).rejects.toThrow(AmaracusNotFoundError);
    });
  });

  // =========================================================================
  // 5. ENCRYPT & DECRYPT OPERATIONS VIA SDK
  // =========================================================================
  describe('5. Universal Encryption & Decryption via SDK', () => {
    let logicalKey: any;

    beforeAll(async () => {
      logicalKey = await sdkTenantA.keys.create({
        name: `sdk-ops-key-${Date.now()}`,
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
      });
    });

    it('encrypts plaintext string and decrypts envelope successfully', async () => {
      const plaintext = 'Confidential Patient Health Record #10923';

      const enc = await sdkTenantA.encrypt({
        key: logicalKey.id,
        data: plaintext,
        aad: 'tenant-hospital-phi',
      });

      expect(enc.ciphertext).toBeDefined();
      expect(enc.iv).toBeDefined();
      expect(enc.tag).toBeDefined();
      expect(enc.algorithm).toBe('AES-256-GCM');
      expect(enc.keyId).toBe(logicalKey.id);
      expect(enc.operationId).toBeDefined();
      expect(enc.status).toBe('COMPLETED');
      expect(enc.requestId).toBeDefined();

      // Decrypt using explicit parameters
      const dec1 = await sdkTenantA.decrypt({
        key: logicalKey.id,
        ciphertext: enc.ciphertext,
        iv: enc.iv,
        tag: enc.tag,
        aad: 'tenant-hospital-phi',
      });
      expect(dec1.plaintext).toBe(plaintext);
      expect(dec1.operationId).toBeDefined();

      // Decrypt using envelope object
      const dec2 = await sdkTenantA.decrypt({
        key: logicalKey.id,
        envelope: enc,
      });
      expect(dec2.plaintext).toBe(plaintext);
    });

    it('transparently handles binary Buffer inputs and roundtrips', async () => {
      const rawSecretBytes = Buffer.from('Binary buffer cryptographic payload with symbols: €£¥§ and null byte \x00', 'utf-8');

      const enc = await sdkTenantA.encrypt({
        key: logicalKey.id,
        data: rawSecretBytes,
      });

      const dec = await sdkTenantA.decrypt({
        key: logicalKey.id,
        ciphertext: enc.ciphertext,
        iv: enc.iv,
        tag: enc.tag,
      });

      expect(dec.plaintext).toBe(rawSecretBytes.toString('utf-8'));
    });

    it('supports direct rawKey roundtrip without logical key registration', async () => {
      const rawKey = crypto.randomBytes(32).toString('hex');
      const testSecret = 'Raw key direct ephemeral encryption payload';

      const enc = await sdkTenantA.encrypt({
        rawKey,
        data: testSecret,
      });

      const dec = await sdkTenantA.decrypt({
        rawKey,
        ciphertext: enc.ciphertext,
        iv: enc.iv,
        tag: enc.tag,
      });

      expect(dec.plaintext).toBe(testSecret);
    });

    it('throws error when ciphertext is tampered with', async () => {
      const enc = await sdkTenantA.encrypt({
        key: logicalKey.id,
        data: 'Authentic Data',
      });

      const tamperedCt = enc.ciphertext.startsWith('A')
        ? 'B' + enc.ciphertext.slice(1)
        : 'A' + enc.ciphertext.slice(1);

      await expect(
        sdkTenantA.decrypt({
          key: logicalKey.id,
          ciphertext: tamperedCt,
          iv: enc.iv,
          tag: enc.tag,
        })
      ).rejects.toThrow(AmaracusError);
    });
  });

  // =========================================================================
  // 6. CRYPTOGRAPHIC HASHING VIA SDK
  // =========================================================================
  describe('6. Cryptographic Hashing via SDK (amaracus.hash)', () => {
    it('hashes data with SHA-256 producing exact expected digest', async () => {
      const message = 'The quick brown fox jumps over the lazy dog';
      const expectedDigest = crypto.createHash('sha256').update(message).digest('hex');

      const result = await sdkTenantA.hash({
        data: message,
        algorithm: 'SHA-256',
      });

      expect(result.digest).toBe(expectedDigest);
      expect(result.algorithm).toBe('SHA-256');
      expect(result.byteLength).toBe(32);
      expect(result.operationId).toBeDefined();
    });

    it('hashes data with SHA-512 producing 64-byte digest', async () => {
      const message = 'High-integrity security log entry';
      const expectedDigest = crypto.createHash('sha512').update(message).digest('hex');

      const result = await sdkTenantA.hash({
        data: message,
        algorithm: 'SHA-512',
      });

      expect(result.digest).toBe(expectedDigest);
      expect(result.byteLength).toBe(64);
    });

    it('rejects unsupported insecure algorithms with AmaracusValidationError', async () => {
      await expect(
        sdkTenantA.hash({
          data: 'test payload',
          algorithm: 'MD5',
        })
      ).rejects.toThrow(AmaracusValidationError);
    });
  });

  // =========================================================================
  // 7. DIGITAL SIGNATURES VIA SDK
  // =========================================================================
  describe('7. Digital Signatures via SDK (amaracus.sign & verify)', () => {
    let signingKey: any;
    const documentToSign = 'Official Contract: AMARACUS SLA Agreement 2026';
    let signatureStr: string;

    beforeAll(async () => {
      signingKey = await sdkTenantA.keys.create({
        name: `sdk-signer-${Date.now()}`,
        algorithm: 'ED25519',
        purpose: 'SIGN_VERIFY',
      });
    });

    it('signs document using ED25519 managed key', async () => {
      const signRes = await sdkTenantA.sign({
        key: signingKey.id,
        data: documentToSign,
      });

      expect(signRes.signature).toBeDefined();
      expect(signRes.algorithm).toBe('ED25519');
      expect(signRes.keyId).toBe(signingKey.id);
      expect(signRes.operationId).toBeDefined();
      signatureStr = signRes.signature;
    });

    it('verifies valid signature returning valid: true', async () => {
      const verifyRes = await sdkTenantA.verify({
        key: signingKey.id,
        data: documentToSign,
        signature: signatureStr,
      });

      expect(verifyRes.valid).toBe(true);
      expect(verifyRes.keyId).toBe(signingKey.id);
    });

    it('verifies tampered document returning valid: false', async () => {
      const verifyRes = await sdkTenantA.verify({
        key: signingKey.id,
        data: 'Tampered contract content',
        signature: signatureStr,
      });

      expect(verifyRes.valid).toBe(false);
    });
  });

  // =========================================================================
  // 8. IDEMPOTENCY & OBSERVABILITY VIA SDK
  // =========================================================================
  describe('8. Idempotency & Operation Observability via SDK', () => {
    it('safe retries with Idempotency-Key return cached response', async () => {
      const idempKey = `idemp_sdk_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const payload = {
        data: 'Unique financial transaction record',
        rawKey: crypto.randomBytes(32).toString('hex'),
      };

      const res1 = await sdkTenantA.encrypt(payload, { idempotencyKey: idempKey });
      const res2 = await sdkTenantA.encrypt(payload, { idempotencyKey: idempKey });

      expect(res2.operationId).toBe(res1.operationId);
      expect(res2.ciphertext).toBe(res1.ciphertext);
    });

    it('amaracus.operations.get() retrieves operation record by ID', async () => {
      const enc = await sdkTenantA.encrypt({
        rawKey: crypto.randomBytes(32).toString('hex'),
        data: 'Observability check payload',
      });

      const op = await sdkTenantA.operations.get(enc.operationId);
      expect(op.id).toBe(enc.operationId);
      expect(op.operationType).toBe('ENCRYPT');
      expect(op.status).toBe('COMPLETED');
    });
  });
});
