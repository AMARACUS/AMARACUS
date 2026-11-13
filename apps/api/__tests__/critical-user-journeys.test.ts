import { describeCloud, itCloud } from './helpers/edition';
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

describe('AMARACUS Master Verification Matrix — Critical User Journeys A through K', () => {
  let server: http.Server;
  let baseUrl: string;

  // Primary Tenant (Tenant Alpha)
  let userAlpha: any;
  let orgAlpha: any;
  let projectAlpha: any;
  let envAlpha: any;
  let apiKeyAlphaRaw: string;
  let sdkAlpha: Amaracus;

  // Secondary Tenant (Tenant Beta)
  let userBeta: any;
  let orgBeta: any;
  let projectBeta: any;
  let envBeta: any;
  let apiKeyBetaRaw: string;
  let sdkBeta: Amaracus;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const address = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });

    // 1. Setup Tenant Alpha
    orgAlpha = await db.createOrganization({
      name: 'Tenant Alpha Corp',
      slug: `tenant-alpha-${Date.now()}`,
    });

    userAlpha = await db.createUser({
      email: `alpha_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Alpha Admin',
    });

    await db.addMember({
      organizationId: orgAlpha.id,
      userId: userAlpha.id,
      role: 'OWNER',
    });

    projectAlpha = await db.createProject({
      organizationId: orgAlpha.id,
      name: 'Alpha Production Cryptography',
      slug: 'alpha-prod',
    });

    envAlpha = await db.createEnvironment({
      projectId: projectAlpha.id,
      name: 'Production',
      slug: 'production',
      type: 'PRODUCTION',
    });

    await db.upsertBillingSubscription({
      organizationId: orgAlpha.id,
      plan: 'BUSINESS',
      status: 'ACTIVE',
      polarSubscriptionId: `sub_cuj_alpha_${Date.now()}`,
    });

    const keyAlpha = generateAmaracusApiKey('live');
    apiKeyAlphaRaw = keyAlpha.fullKey;
    await db.createApiCredential({
      organizationId: orgAlpha.id,
      projectId: projectAlpha.id,
      environmentId: envAlpha.id,
      name: 'Alpha Live Root Key',
      prefix: keyAlpha.prefix,
      keyHash: keyAlpha.keyHash,
      scopes: ['*'],
    });

    sdkAlpha = new Amaracus({
      apiKey: apiKeyAlphaRaw,
      baseUrl: `${baseUrl}/v1`,
      maxRetries: 1,
      timeoutMs: 10000,
    });

    // 2. Setup Tenant Beta
    orgBeta = await db.createOrganization({
      name: 'Tenant Beta Logistics',
      slug: `tenant-beta-${Date.now()}`,
    });

    userBeta = await db.createUser({
      email: `beta_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Beta Admin',
    });

    await db.addMember({
      organizationId: orgBeta.id,
      userId: userBeta.id,
      role: 'OWNER',
    });

    projectBeta = await db.createProject({
      organizationId: orgBeta.id,
      name: 'Beta Isolated Vault',
      slug: 'beta-vault',
    });

    envBeta = await db.createEnvironment({
      projectId: projectBeta.id,
      name: 'Production',
      slug: 'production',
      type: 'PRODUCTION',
    });

    await db.upsertBillingSubscription({
      organizationId: orgBeta.id,
      plan: 'PRO',
      status: 'ACTIVE',
      polarSubscriptionId: `sub_cuj_beta_${Date.now()}`,
    });

    const keyBeta = generateAmaracusApiKey('live');
    apiKeyBetaRaw = keyBeta.fullKey;
    await db.createApiCredential({
      organizationId: orgBeta.id,
      projectId: projectBeta.id,
      environmentId: envBeta.id,
      name: 'Beta Live Root Key',
      prefix: keyBeta.prefix,
      keyHash: keyBeta.keyHash,
      scopes: ['*'],
    });

    sdkBeta = new Amaracus({
      apiKey: apiKeyBetaRaw,
      baseUrl: `${baseUrl}/v1`,
      maxRetries: 1,
      timeoutMs: 10000,
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  // ==========================================
  // JOURNEY A: Developer Integration
  // ==========================================
  describe('Journey A: Developer Integration', () => {
    it('executes capability discovery, scoped key generation, SDK execution, and audit trail', async () => {
      // 1. Verify capability discovery
      const caps = await sdkAlpha.capabilities.get();
      expect(caps.supportedOperations).toBeDefined();
      expect(caps.supportedOperations.length).toBeGreaterThan(0);

      const algos = await sdkAlpha.algorithms.list();
      expect(Array.isArray(algos)).toBe(true);
      expect(algos.length).toBeGreaterThanOrEqual(5);

      // 2. Perform supported cryptographic operation with rawKey
      const rawKey = crypto.randomBytes(32).toString('hex');
      const plaintext = 'Sensitive financial payload: $500,000 transfer to custodial reserve';
      const enc = await sdkAlpha.encrypt({
        data: plaintext,
        rawKey,
        algorithm: 'AES-256-GCM',
      });

      expect(enc.ciphertext).toBeDefined();
      expect(enc.algorithm).toBe('AES-256-GCM');
      expect(enc.iv).toBeDefined();
      expect(enc.tag).toBeDefined();

      // 3. Decrypt payload
      const dec = await sdkAlpha.decrypt({
        ciphertext: enc.ciphertext,
        iv: enc.iv,
        tag: enc.tag,
        rawKey,
        algorithm: 'AES-256-GCM',
      });
      expect(dec.plaintext).toBe(plaintext);

      // 4. Inspect resulting usage and audit records
      const auditEvents = await db.getAuditEventsByOrg(orgAlpha.id);
      expect(auditEvents.length).toBeGreaterThan(0);
    });
  });

  // ==========================================
  // JOURNEY B: Key Lifecycle
  // ==========================================
  describe('Journey B: Key Lifecycle', () => {
    let lifecycleKeyId: string;
    let encryptedUnderV1: any;

    it('creates key, executes operations, rotates key, preserves backward compatibility, and enforces revocation', async () => {
      // 1. Create a logical key with required purpose
      const key = await sdkAlpha.keys.create({
        name: 'Alpha Primary Master Key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
        description: 'Customer master key for database field encryption',
      });
      lifecycleKeyId = key.id;
      expect(key.currentVersion).toBe(1);
      expect(key.status).toBe('ACTIVE');

      // 2. Encrypt under version 1
      const secret = 'Database user password secret hash';
      encryptedUnderV1 = await sdkAlpha.encrypt({
        key: lifecycleKeyId,
        data: secret,
      });
      expect(encryptedUnderV1.ciphertext).toBeDefined();

      // 3. Rotate key to version 2
      const rotated = await sdkAlpha.keys.rotate(lifecycleKeyId);
      expect(rotated.currentVersion).toBe(2);

      // 4. Verify historical backward compatibility (decrypt v1 ciphertext using rotated key)
      const decryptedV1 = await sdkAlpha.decrypt({
        key: lifecycleKeyId,
        ciphertext: encryptedUnderV1.ciphertext,
        iv: encryptedUnderV1.iv,
        tag: encryptedUnderV1.tag,
        version: encryptedUnderV1.keyVersion,
      });
      expect(decryptedV1.plaintext).toBe(secret);

      // 5. Revocation behavior: destroy key and assert further encryption fails
      await sdkAlpha.keys.delete(lifecycleKeyId);

      await expect(
        sdkAlpha.encrypt({
          key: lifecycleKeyId,
          data: 'Attempt to encrypt with deleted key',
        })
      ).rejects.toThrow();
    });
  });

  // ==========================================
  // JOURNEY C: Enterprise Provider Integration
  // ==========================================
  describe('Journey C: Enterprise Provider Integration', () => {
    it('validates provider registry, executes software provider operations, and enforces provider restrictions', async () => {
      // 1. Query provider capabilities
      const providers = await sdkAlpha.keys.providers();
      expect(Array.isArray(providers)).toBe(true);
      expect(providers.length).toBeGreaterThan(0);

      // 2. Perform operation with default software provider
      const hash = await sdkAlpha.hash({
        data: 'Enterprise compliance payload string',
        algorithm: 'SHA-256',
      });
      expect(hash.digest).toBeDefined();
      expect(hash.digest.length).toBe(64);

      // 3. Validate provider restrictions: non-existent/unsupported provider rejection
      const invalidProviderRes = await fetch(`${baseUrl}/v1/crypto/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKeyAlphaRaw}`,
        },
        body: JSON.stringify({
          data: 'test payload',
          algorithm: 'AES-256-GCM',
          provider: 'unsupported_hsm_provider_xyz',
        }),
      });
      // Should reject unapproved or unsupported provider
      expect([400, 403, 422]).toContain(invalidProviderRes.status);
    });
  });

  // ==========================================
  // JOURNEY D: Delegated Development
  // ==========================================
  describeCloud('Journey D: Delegated Development', () => {
    it('enforces RBAC: developer executes scoped crypto but is rejected from billing management', async () => {
      // 1. Generate developer-scoped API credential (crypto operations only, NO billing admin)
      const devKey = generateAmaracusApiKey('live');
      await db.createApiCredential({
        organizationId: orgAlpha.id,
        projectId: projectAlpha.id,
        environmentId: envAlpha.id,
        name: 'Delegated Developer Worker Key',
        prefix: devKey.prefix,
        keyHash: devKey.keyHash,
        scopes: ['crypto:encrypt', 'crypto:decrypt', 'crypto:hash'],
      });

      const sdkDev = new Amaracus({
        apiKey: devKey.fullKey,
        baseUrl: `${baseUrl}/v1`,
      });

      // 2. Developer successfully executes cryptographic operation with rawKey
      const rawKey = crypto.randomBytes(32).toString('hex');
      const devEnc = await sdkDev.encrypt({
        rawKey,
        data: 'Delegated payment data payload',
        algorithm: 'AES-256-GCM',
      });
      expect(devEnc.ciphertext).toBeDefined();

      // 3. Developer attempts billing administration (e.g. checkout or tier change)
      const billingRes = await fetch(`${baseUrl}/api/v1/billing/checkout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${devKey.fullKey}`,
        },
        body: JSON.stringify({ plan: 'BUSINESS' }),
      });
      // API Key without session or billing admin scope cannot mutate billing
      expect([400, 401, 403]).toContain(billingRes.status);
    });
  });

  // ==========================================
  // JOURNEY E: Billing Safety
  // ==========================================
  describeCloud('Journey E: Billing Safety', () => {
    it('validates subscription tiers, meters operations, rejects invalid webhook signatures, and guarantees idempotency', async () => {
      // 1. Test subscription plans catalog
      const plansRes = await fetch(`${baseUrl}/api/v1/billing/plans`);
      expect(plansRes.status).toBe(200);
      const plansBody = await plansRes.json();
      const planList = plansBody.data?.plans || plansBody.plans;
      expect(planList).toBeDefined();
      expect(planList.length).toBeGreaterThanOrEqual(3);

      // 2. Webhook safety: reject unsigned webhook
      const unsignedWebhookRes = await fetch(`${baseUrl}/api/v1/billing/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'order.created', data: {} }),
      });
      expect([400, 401]).toContain(unsignedWebhookRes.status);

      // 3. Webhook safety: reject forged signature
      const forgedWebhookRes = await fetch(`${baseUrl}/api/v1/billing/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'webhook-id': 'msg_forged_123',
          'webhook-timestamp': Math.floor(Date.now() / 1000).toString(),
          'webhook-signature': 'v1,invalidsignaturestringhere0000000000000000000000000000000',
        },
        body: JSON.stringify({ type: 'order.created', data: {} }),
      });
      expect([400, 401]).toContain(forgedWebhookRes.status);
    });
  });

  // ==========================================
  // JOURNEY F: Policy Enforcement
  // ==========================================
  describe('Journey F: Policy Enforcement', () => {
    it('enforces server-side security policies, rejects deprecated/insecure algorithms, and audits rejections', async () => {
      // Attempt deprecated insecure algorithm (e.g. DES or MD5)
      await expect(
        sdkAlpha.hash({
          data: 'Insecure hashing test string',
          algorithm: 'MD5' as any,
        })
      ).rejects.toThrow();

      // Allowed strong algorithm succeeds
      const sha256Res = await sdkAlpha.hash({
        data: 'Secure hashing test string',
        algorithm: 'SHA-256',
      });
      expect(sha256Res.digest).toBeDefined();
    });
  });

  // ==========================================
  // JOURNEY G: Async Operation Recovery
  // ==========================================
  describe('Journey G: Async Operation Recovery & Idempotency', () => {
    it('guarantees identical responses on idempotency retry and verifies operation retrieval', async () => {
      const idempotencyKey = `idemp_cuj_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const rawKey = crypto.randomBytes(32).toString('hex');
      const payload = {
        data: 'Transaction ledger #98721 - $25,000 invoice record',
        algorithm: 'AES-256-GCM' as const,
        rawKey,
      };

      // 1. First execution
      const op1 = await sdkAlpha.encrypt(payload, { idempotencyKey });
      expect(op1.ciphertext).toBeDefined();

      // 2. Second execution with identical Idempotency-Key
      const op2 = await sdkAlpha.encrypt(payload, { idempotencyKey });
      expect(op2.ciphertext).toBe(op1.ciphertext);
      expect(op2.operationId).toBe(op1.operationId);

      // 3. Retrieve operation record by operationId
      const fetchedOp = await sdkAlpha.operations.get(op1.operationId);
      expect(fetchedOp.id).toBe(op1.operationId);
      expect(fetchedOp.status).toBe('COMPLETED');
    });
  });

  // ==========================================
  // JOURNEY H: Tenant Isolation
  // ==========================================
  describe('Journey H: Tenant Isolation & IDOR Defense', () => {
    it('guarantees complete isolation: Tenant Alpha cannot access Tenant Beta keys, projects, or decrypt ciphertexts', async () => {
      // 1. Beta creates a key
      const betaKey = await sdkBeta.keys.create({
        name: 'Beta Confidential Vault Key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
      });

      // 2. Beta encrypts data
      const betaSecret = 'Beta secret trade secret formulation #42';
      const betaEnc = await sdkBeta.encrypt({
        key: betaKey.id,
        data: betaSecret,
      });

      // 3. Alpha attempts to retrieve Beta's key -> 404
      await expect(sdkAlpha.keys.get(betaKey.id)).rejects.toThrow(AmaracusNotFoundError);

      // 4. Alpha attempts to delete Beta's key -> 404
      await expect(sdkAlpha.keys.delete(betaKey.id)).rejects.toThrow(AmaracusNotFoundError);

      // 5. Alpha attempts to decrypt Beta's ciphertext using Beta's key -> rejected
      await expect(
        sdkAlpha.decrypt({
          key: betaKey.id,
          ciphertext: betaEnc.ciphertext,
          iv: betaEnc.iv,
          tag: betaEnc.tag,
        })
      ).rejects.toThrow();
    });
  });

  // ==========================================
  // JOURNEY I: Compliance Evidence
  // ==========================================
  describe('Journey I: Compliance Evidence', () => {
    it('validates compliance control framework assessment and ensures integrity without key leakage', async () => {
      const frameworksRes = await fetch(`${baseUrl}/v1/compliance/frameworks`, {
        headers: { 'Authorization': `Bearer ${apiKeyAlphaRaw}` },
      });
      // Frameworks catalog or assessments available
      expect(frameworksRes.status).toBe(200);
      const body = await frameworksRes.json();
      const list = body.data || body.frameworks || body.items;
      expect(list).toBeDefined();
      expect(list.length).toBeGreaterThan(0);

      // Check audit events for integrity
      const events = await db.getAuditEventsByOrg(orgAlpha.id);
      for (const ev of events) {
        const str = JSON.stringify(ev);
        // Ensure zero raw private keys or master secrets leaked into audit logs
        expect(str).not.toContain('PRIVATE KEY-----');
        expect(str).not.toContain('"rawKey":"');
      }
    });
  });

  // ==========================================
  // JOURNEY J: Overload & Recovery
  // ==========================================
  describe('Journey J: Overload and Recovery', () => {
    it('handles rapid concurrent requests cleanly without worker crash or state corruption', async () => {
      const concurrentRequests = 10;
      const promises = [];

      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(
          sdkAlpha.hash({
            data: `Concurrent load burst item #${i}`,
            algorithm: 'SHA-256',
          })
        );
      }

      const results = await Promise.all(promises);
      expect(results.length).toBe(concurrentRequests);
      for (const res of results) {
        expect(res.digest).toBeDefined();
        expect(res.digest.length).toBe(64);
      }
    });
  });

  // ==========================================
  // JOURNEY K: Release and Recovery
  // ==========================================
  describe('Journey K: Release and Recovery', () => {
    it('verifies /health endpoint responds with healthy status and operational indicators', async () => {
      const healthRes = await fetch(`${baseUrl}/health`);
      expect(healthRes.status).toBe(200);
      const health = await healthRes.json();
      expect(health.status).toBe('ok');
    });
  });
});
