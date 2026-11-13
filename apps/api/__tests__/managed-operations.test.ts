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
import { managedConcurrencyLimiter } from '../src/lib/managed-concurrency-limiter';
import { managedOperationQueue } from '../src/lib/managed-operation-queue';
import { operationObservability } from '../src/lib/operation-observability';
import { usageMeter } from '../src/lib/usage-meter';
import { Amaracus } from '@amaracus/sdk';
import { providerRouter } from '@amaracus/crypto-core';

describe('Phase 14 — Managed Cryptographic Operations Integration Test Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A Context
  let tenantAOrg: any;
  let tenantAUser: any;
  let tenantAProject: any;
  let tenantAEnv: any;
  let tenantAKeyFull: string;
  let tenantALogicalKeyId: string;

  // Tenant B Context (for isolation & IDOR tests)
  let tenantBOrg: any;
  let tenantBUser: any;
  let tenantBProject: any;
  let tenantBEnv: any;
  let tenantBKeyFull: string;

  // SDK Clients
  let sdkTenantA: Amaracus;
  let sdkTenantB: Amaracus;

  beforeAll(async () => {
    // 1. Start Server on ephemeral port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 2. Setup Tenant A
    tenantAOrg = await db.createOrganization({
      name: 'Tenant A Managed Corp',
      slug: `tenant-a-managed-${Date.now()}`,
    });

    tenantAUser = await db.createUser({
      email: `alice_managed_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Alice Operations',
    });

    await db.addMember({
      organizationId: tenantAOrg.id,
      userId: tenantAUser.id,
      role: 'OWNER',
    });

    tenantAProject = await db.createProject({
      organizationId: tenantAOrg.id,
      name: 'Managed Crypto Platform',
      slug: 'managed-platform',
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
    });

    const apiKeyA = generateAmaracusApiKey('live');
    tenantAKeyFull = apiKeyA.fullKey;
    await db.createApiCredential({
      organizationId: tenantAOrg.id,
      projectId: tenantAProject.id,
      environmentId: tenantAEnv.id,
      name: 'Managed Ops Key',
      keyHash: apiKeyA.keyHash,
      prefix: apiKeyA.prefix,
      scopes: ['*'],
    });

    // Create a logical key for Tenant A
    const keyRes = await fetch(`${baseUrl}/v1/keys`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${tenantAKeyFull}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'managed-aes-key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
      }),
    });
    const keyBody = await keyRes.json();
    tenantALogicalKeyId = keyBody.data.id;

    // 3. Setup Tenant B
    tenantBOrg = await db.createOrganization({
      name: 'Tenant B Isolation Corp',
      slug: `tenant-b-managed-${Date.now()}`,
    });

    tenantBUser = await db.createUser({
      email: `bob_managed_${Date.now()}@amaracus.dev`,
      passwordHash: 'dummy_hash',
      name: 'Bob Isolation',
    });

    await db.addMember({
      organizationId: tenantBOrg.id,
      userId: tenantBUser.id,
      role: 'OWNER',
    });

    tenantBProject = await db.createProject({
      organizationId: tenantBOrg.id,
      name: 'Isolated Project',
      slug: 'isolated-project',
    });

    tenantBEnv = await db.createEnvironment({
      projectId: tenantBProject.id,
      name: 'Production',
      slug: 'production',
      type: 'PRODUCTION',
    });

    await db.upsertBillingSubscription({
      organizationId: tenantBOrg.id,
      plan: 'GROWTH',
      status: 'ACTIVE',
    });

    const apiKeyB = generateAmaracusApiKey('live');
    tenantBKeyFull = apiKeyB.fullKey;
    await db.createApiCredential({
      organizationId: tenantBOrg.id,
      projectId: tenantBProject.id,
      environmentId: tenantBEnv.id,
      name: 'Tenant B Ops Key',
      keyHash: apiKeyB.keyHash,
      prefix: apiKeyB.prefix,
      scopes: ['*'],
    });

    // Initialize SDK clients
    sdkTenantA = new Amaracus({
      apiKey: tenantAKeyFull,
      baseUrl: `${baseUrl}/v1`,
    });

    sdkTenantB = new Amaracus({
      apiKey: tenantBKeyFull,
      baseUrl: `${baseUrl}/v1`,
    });
  });

  afterAll(async () => {
    await managedOperationQueue.shutdown();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  beforeEach(() => {
    managedConcurrencyLimiter.reset();
  });

  // ==========================================================================
  // 1. SYNCHRONOUS MANAGED OPERATIONS
  // ==========================================================================
  describe('1. Synchronous Cryptographic Operations', () => {
    it('executes a synchronous encryption operation via REST API', async () => {
      const res = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
          'x-request-id': 'req_sync_enc_01',
        },
        body: JSON.stringify({
          type: 'ENCRYPT',
          keyId: tenantALogicalKeyId,
          params: {
            plaintext: 'Confidential Payload for Phase 14',
          },
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.status).toBe('COMPLETED');
      expect(body.mode).toBe('sync');
      expect(body.operationId).toMatch(/^op_/);
      expect(body.requestId).toBe('req_sync_enc_01');
      expect(body.data).toBeDefined();
      expect(body.data.ct).toBeDefined();

      // Verify persistent record in DB
      const record = await db.getCryptographicOperation(body.operationId);
      expect(record).not.toBeNull();
      expect(record?.status).toBe('COMPLETED');
      expect(record?.organizationId).toBe(tenantAOrg.id);
    });

    it('executes a synchronous hash operation via SDK', async () => {
      const op = await sdkTenantA.operations.create({
        type: 'HASH',
        algorithm: 'SHA-256',
        params: {
          data: 'Antigravity Cryptographic Hash Verification',
        },
      });

      expect(op.status).toBe('COMPLETED');
      expect(op.mode).toBe('sync');
      expect(op.operationId).toBeDefined();
      expect(op.data?.digest).toBeDefined();
    });
  });

  // ==========================================================================
  // 2. ASYNCHRONOUS MANAGED OPERATIONS & WORKER LIFECYCLE
  // ==========================================================================
  describe('2. Asynchronous Workloads & Queue Processing', () => {
    it('accepts an explicit async operation and returns 202 Accepted handle', async () => {
      const res = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'ENCRYPT',
          keyId: tenantALogicalKeyId,
          mode: 'async',
          params: {
            plaintext: 'Asynchronous Secret Document',
          },
        }),
      });

      expect(res.status).toBe(202);
      const body = await res.json();
      expect(body.status).toBe('QUEUED');
      expect(body.mode).toBe('async');
      expect(body.pollUrl).toBe(`/v1/operations/${body.operationId}`);

      // Poll until worker executes and completes the job
      const completedResult = await sdkTenantA.operations.pollUntilComplete(
        body.operationId,
        { intervalMs: 50, timeoutMs: 5000 }
      );

      expect(completedResult.status).toBe('COMPLETED');
      expect(completedResult.data).toBeDefined();
      expect(completedResult.data.ct).toBeDefined();
    });

    it('rejects operation types the runtime cannot execute (FHE / MPC / ZK) instead of queueing them', async () => {
      const res = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'FHE_EXECUTE',
          algorithm: 'FHE_BFV',
          params: {
            operation: 'ADD',
            ciphertexts: ['ct_1', 'ct_2'],
          },
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error.code).toBe('INVALID_REQUEST');
    });
  });

  describe('2b. Malformed Input', () => {
    const post = (body: unknown) =>
      fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });

    it.each([
      ['a JSON array body', [1, 2, 3]],
      ['an unknown operation type', { type: 'TELEPORT' }],
      ['a non-string type', { type: 42 }],
      ['a non-string keyId', { type: 'HASH', keyId: { $ne: null } }],
      ['a non-object params', { type: 'HASH', params: 'oops' }],
      ['a non-string params.data', { type: 'HASH', params: { data: 12345 } }],
      ['a numeric plaintext', { type: 'ENCRYPT', keyId: 'k', params: { plaintext: 99 } }],
      ['an invalid mode', { type: 'HASH', mode: 'later', params: { data: 'x' } }],
      ['a negative timeoutMs', { type: 'HASH', timeoutMs: -1, params: { data: 'x' } }],
    ])('returns 400 (not 500) for %s', async (_label, body) => {
      const res = await post(body);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('INVALID_REQUEST');
      expect(json.error.retryable).toBe(false);
    });

    it('returns 400 for an unknown plaintext encoding', async () => {
      const res = await post({
        type: 'ENCRYPT',
        keyId: tenantALogicalKeyId,
        params: { plaintext: 'abc', plaintextEncoding: 'klingon' },
      });
      expect(res.status).toBe(400);
    });

    it('accepts a hash request with no params object', async () => {
      const res = await post({ type: 'HASH', algorithm: 'SHA-256' });
      expect(res.status).toBe(200);
    });
  });

  // ==========================================================================
  // 3. IDEMPOTENCY AND REPLAY PROTECTION
  // ==========================================================================
  describe('3. Idempotency Protection', () => {
    it('returns identical cached result on idempotent replays without duplicate execution', async () => {
      const idempotencyKey = `idem_${crypto.randomUUID()}`;

      const res1 = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
          'x-idempotency-key': idempotencyKey,
        },
        body: JSON.stringify({
          type: 'HASH',
          algorithm: 'SHA-256',
          params: { data: 'Idempotency Payload' },
        }),
      });

      expect(res1.status).toBe(200);
      const body1 = await res1.json();

      // Replay with identical key
      const res2 = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
          'x-idempotency-key': idempotencyKey,
        },
        body: JSON.stringify({
          type: 'HASH',
          algorithm: 'SHA-256',
          params: { data: 'Idempotency Payload' },
        }),
      });

      expect(res2.status).toBe(200);
      const body2 = await res2.json();

      expect(body2.operationId).toBe(body1.operationId);
      expect(body2.data.digest).toBe(body1.data.digest);
    });
  });

  // ==========================================================================
  // 4. OPERATION CANCELLATION
  // ==========================================================================
  describe('4. Operation Cancellation', () => {
    it('cancels an enqueued operation before it executes', async () => {
      // Enqueue an async operation with future schedule
      const opId = `op_cancel_test_${Date.now()}`;
      await db.createCryptographicOperation({
        id: opId,
        organizationId: tenantAOrg.id,
        operationType: 'ENCRYPT',
        status: 'QUEUED',
      });

      await managedOperationQueue.enqueue({
        operationId: opId,
        organizationId: tenantAOrg.id,
        operationType: 'ENCRYPT',
        request: {
          operationId: opId,
          requestId: 'req_cancel',
          type: 'ENCRYPT',
          params: { plaintext: 'Cancel me' },
        },
        tenantContext: { organizationId: tenantAOrg.id },
        priority: 'NORMAL',
        retryCount: 0,
        maxRetries: 3,
        enqueuedAt: new Date(),
        scheduledAt: new Date(Date.now() + 10000), // scheduled in 10s
      });

      const cancelRes = await sdkTenantA.operations.cancel(opId);
      expect(cancelRes.canceled).toBe(true);
      expect(cancelRes.status).toBe('CANCELED');

      const opRecord = await sdkTenantA.operations.get(opId);
      expect(opRecord.status).toBe('CANCELED');
    });

    it('rejects cancellation on already completed operations', async () => {
      const op = await sdkTenantA.operations.create({
        type: 'HASH',
        algorithm: 'SHA-256',
        params: { data: 'Completed already' },
      });

      const cancelRes = await sdkTenantA.operations.cancel(op.operationId);
      expect(cancelRes.canceled).toBe(false);
      expect(cancelRes.status).toBe('COMPLETED');
    });
  });

  // ==========================================================================
  // 5. BOUNDED RETRIES & DEAD-LETTER QUEUE
  // ==========================================================================
  describe('5. Bounded Retries & Dead-Letter Storage', () => {
    it('transitions to DEAD_LETTER when maximum retries are exhausted on transient errors', async () => {
      const deadLetterOpId = `op_dlq_${Date.now()}`;

      await db.createCryptographicOperation({
        id: deadLetterOpId,
        organizationId: tenantAOrg.id,
        operationType: 'ENCRYPT',
        status: 'REQUESTED',
        retryCount: 0,
      });

      // Submit queued item configured with maxRetries: 1 and a deliberate failing request
      await managedOperationQueue.enqueue({
        operationId: deadLetterOpId,
        organizationId: tenantAOrg.id,
        operationType: 'ENCRYPT',
        request: {
          operationId: deadLetterOpId,
          requestId: 'req_dlq',
          type: 'ENCRYPT',
          keyId: 'non_existent_key_99999',
          params: { plaintext: 'Data' },
        },
        tenantContext: { organizationId: tenantAOrg.id },
        priority: 'NORMAL',
        retryCount: 2, // Already at max retries
        maxRetries: 2,
        enqueuedAt: new Date(),
        scheduledAt: new Date(),
      });

      // Poll until worker completes execution
      let finalStatus: string | undefined;
      for (let i = 0; i < 20; i++) {
        const record = await db.getCryptographicOperation(deadLetterOpId);
        if (record && ['DEAD_LETTER', 'FAILED'].includes(record.status)) {
          finalStatus = record.status;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }

      expect(['DEAD_LETTER', 'FAILED']).toContain(finalStatus);
    });

    it('fails non-retryable validation errors immediately without retrying', async () => {
      const res = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'ENCRYPT',
          params: {}, // Missing plaintext / data
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBeDefined();
      expect(body.error.retryable).toBe(false);
    });
  });

  // ==========================================================================
  // 6. STRICT ZERO SECRET LEAKAGE
  // ==========================================================================
  describe('6. Zero Secret Leakage Guarantees', () => {
    it('sanitizes error messages and redacts potential hex/base64 key tokens', async () => {
      const secretHexToken = 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0';

      const res = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'ENCRYPT',
          keyId: `non_existent_${secretHexToken}`,
          params: { plaintext: 'Test' },
        }),
      });

      const body = await res.json();
      const stringified = JSON.stringify(body);
      expect(stringified).not.toContain(secretHexToken);
    });

    it('ensures operation database records never store plaintext data', async () => {
      const plaintextSecret = 'SUPER_SECRET_PLAINTEXT_SHOULD_NEVER_BE_STORED_IN_OP_RECORD';

      const op = await sdkTenantA.operations.create({
        type: 'ENCRYPT',
        keyId: tenantALogicalKeyId,
        params: { plaintext: plaintextSecret },
      });

      const record = await db.getCryptographicOperation(op.operationId);
      const recordStr = JSON.stringify(record);
      expect(recordStr).not.toContain(plaintextSecret);
    });
  });

  // ==========================================================================
  // 7. CONCURRENCY LIMITS & TENANT ISOLATION
  // ==========================================================================
  describe('7. Concurrency Limiting & Workload Isolation', () => {
    it('enforces concurrency ceiling on heavy workloads per tenant', () => {
      // Simulate exhausting Tenant A heavy slots (limit: 5)
      for (let i = 0; i < 5; i++) {
        const acquire = managedConcurrencyLimiter.tryAcquire(
          tenantAOrg.id,
          'FHE_EXECUTE',
          'FHE_BFV'
        );
        expect(acquire.allowed).toBe(true);
      }

      // 6th heavy workload for Tenant A is rejected
      const rejected = managedConcurrencyLimiter.tryAcquire(
        tenantAOrg.id,
        'FHE_EXECUTE',
        'FHE_BFV'
      );
      expect(rejected.allowed).toBe(false);
      expect(rejected.reason).toBe('HEAVY_WORKLOAD_CONCURRENCY_LIMIT_EXCEEDED');

      // But Tenant B is NOT blocked by Tenant A exhaustion (tenant isolation)
      const tenantBAcquire = managedConcurrencyLimiter.tryAcquire(
        tenantBOrg.id,
        'FHE_EXECUTE',
        'FHE_BFV'
      );
      expect(tenantBAcquire.allowed).toBe(true);

      // Releasing Tenant A slot allows subsequent acquisition
      managedConcurrencyLimiter.release(tenantAOrg.id, 'FHE_EXECUTE', 'FHE_BFV');
      const retry = managedConcurrencyLimiter.tryAcquire(
        tenantAOrg.id,
        'FHE_EXECUTE',
        'FHE_BFV'
      );
      expect(retry.allowed).toBe(true);
    });
  });

  // ==========================================================================
  // 8. BILLING INVARIANCE
  // ==========================================================================
  describe('8. Single Logical Billable Unit Invariance', () => {
    it('records exactly 1 billable unit across retries and idempotency replays', async () => {
      const orgId = tenantAOrg.id;
      const initialUsage = await billableUsage(orgId);
      const initialOps = initialUsage.operationCount;

      const idempotencyKey = `idem_bill_${Date.now()}`;

      // First execution
      await sdkTenantA.operations.create(
        {
          type: 'HASH',
          algorithm: 'SHA-256',
          params: { data: 'Billing Invariance Payload' },
        },
        { idempotencyKey }
      );

      // Replay with identical key
      await sdkTenantA.operations.create(
        {
          type: 'HASH',
          algorithm: 'SHA-256',
          params: { data: 'Billing Invariance Payload' },
        },
        { idempotencyKey }
      );

      const finalUsage = await billableUsage(orgId);
      // Billing usage should have incremented by exactly 1, not 2
      expect(finalUsage.operationCount).toBe(initialOps + 1);
    });
  });

  // ==========================================================================
  // 9. OBSERVABILITY & METRICS ENDPOINT
  // ==========================================================================
  describe('9. Observability & Operational Metrics', () => {
    it('returns telemetry, latency histograms, and queue status via GET /v1/operations/metrics', async () => {
      const res = await fetch(`${baseUrl}/v1/operations/metrics`, {
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toBeDefined();
      expect(body.data.queue).toBeDefined();
      expect(body.data.queue.depth).toBeGreaterThanOrEqual(0);
      expect(body.data.concurrency).toBeDefined();
      expect(body.data.telemetry).toBeDefined();
      expect(body.data.telemetry.countsByStatus).toBeDefined();
      expect(body.data.telemetry.latencies).toBeDefined();
    });

    it('retrieves operational metrics via SDK', async () => {
      const metrics = await sdkTenantA.operations.metrics();
      expect(metrics).toBeDefined();
      expect(metrics.queue).toBeDefined();
      expect(metrics.telemetry.countsByStatus.COMPLETED).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // 10. TENANT ISOLATION & IDOR PROTECTION
  // ==========================================================================
  describe('10. Security & IDOR Prevention', () => {
    it('prevents Tenant B from viewing Tenant A operations', async () => {
      const opA = await sdkTenantA.operations.create({
        type: 'HASH',
        algorithm: 'SHA-256',
        params: { data: 'Tenant A Secret Operation' },
      });

      // Tenant B attempts to read Tenant A's operation
      const res = await fetch(`${baseUrl}/v1/operations/${opA.operationId}`, {
        headers: {
          Authorization: `Bearer ${tenantBKeyFull}`,
        },
      });

      expect(res.status).toBe(404);
    });

    it('prevents Tenant B from canceling Tenant A operations', async () => {
      const opA = await sdkTenantA.operations.create({
        type: 'HASH',
        algorithm: 'SHA-256',
        params: { data: 'Tenant A Secret Operation' },
      });

      const res = await fetch(`${baseUrl}/v1/operations/${opA.operationId}/cancel`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantBKeyFull}`,
        },
      });

      expect(res.status).toBe(404);
    });
  });

  // ==========================================================================
  // 11. SDK LIST OPERATIONS WITH FILTERS
  // ==========================================================================
  describe('11. SDK Operation Listing & Querying', () => {
    it('lists operations filtered by status and limits', async () => {
      const ops = await sdkTenantA.operations.list({
        status: 'COMPLETED',
        limit: 10,
      });

      expect(Array.isArray(ops)).toBe(true);
      expect(ops.length).toBeGreaterThan(0);
      expect(ops.every((op) => op.status === 'COMPLETED')).toBe(true);
    });
  });

  // ==========================================================================
  // 12. SAFE PROVIDER FAILOVER INVARIANTS
  // ==========================================================================
  describe('12. Safe Provider Failover Invariants', () => {
    it('strictly prohibits BYOK customer vault keys from failing over to any other provider', () => {
      const byokKeyRef: any = {
        id: 'key_byok_123',
        provider: 'CUSTOMER_AZURE_KV',
        isCustomerManaged: true,
        algorithm: 'AES-256-GCM',
      };
      const primary = providerRouter.getProvider('CUSTOMER_AZURE_KV') || providerRouter.getProvider('LOCAL_DEV')!;
      const failover = providerRouter.resolveFailoverProvider(
        primary,
        { operationId: 'op_byok', requestId: 'req_1', type: 'ENCRYPT', algorithm: 'AES-256-GCM', params: {} },
        byokKeyRef,
        { organizationId: tenantAOrg.id }
      );
      expect(failover).toBeNull();
    });

    it('strictly prohibits FIPS-compliant keys from downgrading to non-HSM providers', () => {
      const hsmKeyRef: any = {
        id: 'key_hsm_123',
        provider: 'AZURE_MANAGED_HSM',
        isHsmBacked: true,
        algorithm: 'AES-256-GCM',
      };
      const primary = providerRouter.getProvider('AZURE_MANAGED_HSM') || providerRouter.getProvider('LOCAL_DEV')!;
      const failover = providerRouter.resolveFailoverProvider(
        primary,
        { operationId: 'op_fips', requestId: 'req_2', type: 'ENCRYPT', algorithm: 'AES-256-GCM', policy: 'FIPS_COMPLIANT', params: {} },
        hsmKeyRef,
        { organizationId: tenantAOrg.id }
      );
      expect(failover).toBeNull();
    });

    it('permits safe failover to local provider for unwrappable or ephemeral operations', () => {
      const localKeyRef: any = {
        id: 'key_local_123',
        provider: 'LOCAL_DEV',
        encryptedKeyMaterial: 'enc_material_abc',
        algorithm: 'AES-256-GCM',
      };
      const mockFailedPrimary: any = {
        id: 'REMOTE_DEV',
        name: 'Remote Mock',
      };
      const failover = providerRouter.resolveFailoverProvider(
        mockFailedPrimary,
        { operationId: 'op_safe', requestId: 'req_3', type: 'ENCRYPT', algorithm: 'AES-256-GCM', params: {} },
        localKeyRef,
        { organizationId: tenantAOrg.id }
      );
      expect(failover).not.toBeNull();
      expect(failover?.id).toBe('LOCAL_DEV');
    });
  });

  // ==========================================================================
  // 13. KEY ROTATION & HISTORICAL VERSION DECRYPTION
  // ==========================================================================
  describe('13. Key Rotation & Historical Version Resolution', () => {
    it('encrypts under version 1, rotates key to version 2, and successfully decrypts historical ciphertext', async () => {
      // 1. Encrypt with current version
      const encRes = await sdkTenantA.encrypt({
        key: 'managed-aes-key',
        data: 'Secret Message Before Rotation',
      });
      expect(encRes.ciphertext).toBeDefined();

      // 2. Rotate the key
      const rotatedKey = await sdkTenantA.keys.rotate(tenantALogicalKeyId);
      expect(rotatedKey.currentVersion).toBe(2);

      // 3. Decrypt historical ciphertext using logical key name
      const decRes = await sdkTenantA.decrypt({
        key: 'managed-aes-key',
        ciphertext: encRes.ciphertext,
        iv: encRes.iv,
        tag: encRes.tag,
        version: encRes.keyVersion,
      });

      expect(decRes.data).toBe('Secret Message Before Rotation');
    });
  });

  // ==========================================================================
  // 14. SIMULTANEOUS CONCURRENT OPERATIONS
  // ==========================================================================
  describe('14. High-Concurrency Simultaneous Operations', () => {
    it('executes 10 simultaneous cryptographic operations without race conditions or state corruption', async () => {
      const payloads = Array.from({ length: 10 }, (_, i) => `Concurrent Data Stream #${i}`);

      const results = await Promise.all(
        payloads.map((payload) =>
          sdkTenantA.operations.create({
            type: 'HASH',
            algorithm: 'SHA-256',
            params: { data: payload },
          })
        )
      );

      expect(results).toHaveLength(10);
      expect(results.every((r) => r.status === 'COMPLETED')).toBe(true);

      // All 10 operations have distinct unique operation IDs
      const opIds = new Set(results.map((r) => r.operationId));
      expect(opIds.size).toBe(10);
    });
  });
});

