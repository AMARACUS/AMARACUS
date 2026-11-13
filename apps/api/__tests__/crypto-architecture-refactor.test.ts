import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import {
  CryptographicRuntime,
  providerRouter,
  capabilityDiscovery,
  CryptographicOperationRequest,
  TenantContext,
  KeyReference,
  OperationStatus,
} from '@amaracus/crypto-core';
import { cryptographicRuntime } from '../src/lib/runtime-service';

describe('Phase 10.5 — AMARACUS Cryptographic Infrastructure Architecture Refactor', () => {
  let server: http.Server;
  let baseUrl: string;

  let testUser: any;
  let testSession: any;
  let testOrg: any;
  let testProject: any;
  let testEnvironment: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    testUser = await db.createUser({
      email: `arch_refactor_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Architect Lead',
    });

    testOrg = await db.createOrganization({
      name: 'Cryptographic Infrastructure Org',
      slug: `crypto-infra-${Date.now()}`,
    });

    await db.addMember({
      organizationId: testOrg.id,
      userId: testUser.id,
      role: 'OWNER',
    });

    testSession = await db.createSession({
      userId: testUser.id,
      activeOrgId: testOrg.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    testProject = await db.createProject({
      organizationId: testOrg.id,
      name: 'Infrastructure Core',
      slug: 'infra-core',
    });

    testEnvironment = await db.createEnvironment({
      projectId: testProject.id,
      name: 'Production',
      slug: 'production',
      type: 'PRODUCTION',
    });

    // Seed Pro plan with allowance so billing guard passes cleanly
    await db.upsertBillingSubscription({
      organizationId: testOrg.id,
      plan: 'PRO',
      status: 'ACTIVE',
      polarSubscriptionId: `sub_arch_${Date.now()}`,
    });
  });

  afterAll((done) => {
    if (server) {
      server.close(done);
    } else {
      done();
    }
  });

  // ==========================================================================
  // 1. OPERATION MODEL & LIFECYCLE TESTS
  // ==========================================================================
  describe('1. Universal Cryptographic Operation Model & Lifecycle', () => {
    it('executes through all 6 canonical lifecycle states (REQUESTED -> VALIDATING -> AUTHORIZING -> RESOLVING -> EXECUTING -> COMPLETED)', async () => {
      const transitions: OperationStatus[] = [];
      const runtime = new CryptographicRuntime(providerRouter, {
        stateObserver: {
          onTransition: (opId, status) => {
            transitions.push(status);
          },
        },
      });

      const context: TenantContext = {
        organizationId: testOrg.id,
        projectId: testProject.id,
        environmentId: testEnvironment.id,
        actorId: testUser.id,
        actorType: 'USER_SESSION',
      };

      const result = await runtime.execute(
        {
          type: 'ENCRYPT',
          algorithm: 'AES-256-GCM',
          params: {
            key: crypto.randomBytes(32).toString('base64'),
            plaintext: 'Amaracus Infrastructure Refactor Test',
          },
        },
        context
      );

      expect(result.success).toBe(true);
      expect(result.status).toBe('COMPLETED');
      expect(result.data).toBeDefined();
      expect(result.metadata.durationMs).toBeGreaterThanOrEqual(0);
      expect(result.metadata.providerId).toBe('LOCAL_DEV');

      // Verify the progression of lifecycle states
      expect(transitions).toContain('REQUESTED');
      expect(transitions).toContain('VALIDATING');
      expect(transitions).toContain('RESOLVING');
      expect(transitions).toContain('AUTHORIZING');
      expect(transitions).toContain('EXECUTING');
      expect(transitions).toContain('COMPLETED');
    });

    it('transitions to FAILED on invalid tenant context and fails closed', async () => {
      const transitions: OperationStatus[] = [];
      const runtime = new CryptographicRuntime(providerRouter, {
        stateObserver: {
          onTransition: (opId, status) => {
            transitions.push(status);
          },
        },
      });

      // Context missing organizationId
      const invalidContext = {
        organizationId: '',
      } as TenantContext;

      const failResult = await runtime.execute(
        {
          type: 'ENCRYPT',
          algorithm: 'AES-256-GCM',
          params: { key: 'invalid', plaintext: 'fail' },
        },
        invalidContext
      );

      expect(failResult.success).toBe(false);
      expect(failResult.status).toBe('FAILED');
      expect(failResult.error).toBeDefined();
      expect(transitions).toContain('FAILED');
    });
  });

  // ==========================================================================
  // 2. PROVIDER ABSTRACTION & CAPABILITY DISCOVERY
  // ==========================================================================
  describe('2. Provider Abstraction & Capability Discovery', () => {
    it('discovers capabilities across all internal providers with 3-state reporting', async () => {
      const summary = await capabilityDiscovery.discoverAll();
      expect(summary.providers.length).toBeGreaterThanOrEqual(5);

      const localProv = summary.providers.find((p) => p.id === 'LOCAL_DEV');
      expect(localProv).toBeDefined();
      expect(localProv?.capabilities.encryption).toBe(true);
      expect(localProv?.capabilities.hardwareBacked).toBe(false);

      const pqcProv = summary.providers.find((p) => p.id === 'PQC_ENGINE');
      expect(pqcProv).toBeDefined();
      expect(pqcProv?.capabilities.pqc).toBe(true);

      const hsmProv = summary.providers.find((p) => p.id === 'AZURE_MANAGED_HSM');
      expect(hsmProv).toBeDefined();
      expect(hsmProv?.capabilities.hardwareBacked).toBe(true);
    });

    it('queries provider by ID and checks capability support accurately', () => {
      const local = capabilityDiscovery.getProvider('LOCAL_DEV');
      expect(local).toBeDefined();
      expect(local?.supportsOperation('ENCRYPT', 'AES-256-GCM')).toBe(true);
      expect(local?.supportsOperation('ENCRYPT', 'UNSUPPORTED_ALGORITHM_XYZ')).toBe(false);

      const pqc = capabilityDiscovery.getProvider('PQC_ENGINE');
      expect(pqc).toBeDefined();
      expect(pqc?.supportsOperation('PQC_SIGN', 'ML-DSA-65')).toBe(true);
    });
  });

  // ==========================================================================
  // 3. PROVIDER ROUTING ENGINE
  // ==========================================================================
  describe('3. Intelligent Cryptographic Provider Routing', () => {
    const context: TenantContext = {
      organizationId: 'org_test_route',
      actorType: 'SYSTEM',
    };

    it('routes standard symmetric encryption to Local Software Provider by default', async () => {
      const provider = await providerRouter.route(
        { type: 'ENCRYPT', algorithm: 'AES-256-GCM' },
        null,
        context
      );
      expect(provider.id).toBe('LOCAL_DEV');
    });

    it('routes Azure Key Vault key references to Azure Key Vault Provider', async () => {
      const keyRef: KeyReference = {
        id: 'key_kv_01',
        name: 'test-kv-key',
        organizationId: context.organizationId,
        algorithm: 'RSA-2048',
        purpose: 'ENCRYPT_DECRYPT',
        provider: 'AZURE_KEY_VAULT',
        providerKeyId: 'https://vault.vault.azure.net/keys/test-kv-key/v1',
        currentVersion: 1,
        status: 'ACTIVE',
        isHsmBacked: false,
        isCustomerManaged: false,
      };

      const provider = await providerRouter.route(
        { type: 'ENCRYPT', keyReference: keyRef },
        keyRef,
        context
      );
      expect(provider.id).toBe('AZURE_KEY_VAULT');
    });

    it('routes Azure Managed HSM key references to Azure Managed HSM Provider', async () => {
      const keyRef: KeyReference = {
        id: 'key_hsm_01',
        name: 'test-hsm-key',
        organizationId: context.organizationId,
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
        provider: 'AZURE_MANAGED_HSM',
        providerKeyId: 'https://hsm.managedhsm.azure.net/keys/test-hsm-key/v1',
        currentVersion: 1,
        status: 'ACTIVE',
        isHsmBacked: true,
        isCustomerManaged: false,
      };

      const provider = await providerRouter.route(
        { type: 'ENCRYPT', keyReference: keyRef },
        keyRef,
        context
      );
      expect(provider.id).toBe('AZURE_MANAGED_HSM');
    });

    it('routes Customer BYOK key references to Customer Azure Provider', async () => {
      const keyRef: KeyReference = {
        id: 'key_byok_01',
        name: 'test-byok-key',
        organizationId: context.organizationId,
        algorithm: 'RSA-4096',
        purpose: 'SIGN_VERIFY',
        provider: 'CUSTOMER_AZURE_KEY_VAULT',
        providerKeyId: 'https://cust-vault.vault.azure.net/keys/test-byok-key/v1',
        currentVersion: 1,
        status: 'ACTIVE',
        isHsmBacked: false,
        isCustomerManaged: true,
      };

      const provider = await providerRouter.route(
        { type: 'SIGN', keyReference: keyRef },
        keyRef,
        context
      );
      expect(provider.id).toBe('CUSTOMER_AZURE_BYOK');
    });

    it('routes PQC operations to Post-Quantum Provider', async () => {
      const provider = await providerRouter.route(
        { type: 'PQC_SIGN', algorithm: 'ML-DSA-65' },
        null,
        context
      );
      expect(provider.id).toBe('PQC_ENGINE');
    });

    it('routes Advanced operations (ZK, FHE, MPC) to Advanced Provider', async () => {
      const zkProvider = await providerRouter.route(
        { type: 'ZK_PROVE', algorithm: 'GROTH16-BN254' },
        null,
        context
      );
      expect(zkProvider.id).toBe('ADVANCED_CRYPTO');

      const fheProvider = await providerRouter.route(
        { type: 'FHE_ENCRYPT', algorithm: 'CKKS' },
        null,
        context
      );
      expect(fheProvider.id).toBe('ADVANCED_CRYPTO');
    });
  });

  // ==========================================================================
  // 4. LOGICAL KEY ABSTRACTION (KeyReference)
  // ==========================================================================
  describe('4. Unified Logical Key Abstraction (KeyReference)', () => {
    it('resolves logical key and encrypts/decrypts without exposing key material', async () => {
      // 1. Generate local key material
      const localProvider = providerRouter.getProvider('LOCAL_DEV') as any;
      const keyGen = await localProvider.generateKey({
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
      });

      // 2. Persist managed key in database
      const key = await db.createKey({
        name: `managed-key-${Date.now()}`,
        organizationId: testOrg.id,
        projectId: testProject.id,
        environmentId: testEnvironment.id,
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPT_DECRYPT',
        provider: 'LOCAL_DEV',
      });

      await db.createKeyVersion({
        keyId: key.id,
        version: 1,
        providerKeyId: keyGen.providerKeyId,
        status: 'ACTIVE',
        publicKey: keyGen.publicKey,
        encryptedKeyMaterial: keyGen.encryptedKeyMaterial,
        keyFingerprint: keyGen.keyFingerprint,
      });

      const context: TenantContext = {
        organizationId: testOrg.id,
        projectId: testProject.id,
        environmentId: testEnvironment.id,
        actorId: testUser.id,
        actorType: 'USER_SESSION',
      };

      // 3. Encrypt referencing ONLY keyId (caller has no raw key material)
      const encResult = await cryptographicRuntime.execute(
        {
          type: 'ENCRYPT',
          keyId: key.id,
          params: {
            plaintext: 'Sensitive Business Secret 42',
          },
        },
        context
      );

      expect(encResult.success).toBe(true);
      expect(encResult.metadata.keyId).toBe(key.id);
      expect(encResult.data).toBeDefined();
      expect(encResult.data.ct).toBeDefined();

      // 4. Decrypt referencing the same keyId
      const decResult = await cryptographicRuntime.execute(
        {
          type: 'DECRYPT',
          keyId: key.id,
          params: {
            envelope: encResult.data,
          },
        },
        context
      );

      expect(decResult.success).toBe(true);
      expect(decResult.data).toBe('Sensitive Business Secret 42');
    });
  });

  // ==========================================================================
  // 5. POLICY ENFORCEMENT & INTEGRITY
  // ==========================================================================
  describe('5. Cryptographic Policy Enforcement', () => {
    it('rejects deprecated algorithms under DEFAULT_SECURE policy with POLICY_DENIED', async () => {
      const context: TenantContext = {
        organizationId: testOrg.id,
        actorType: 'SYSTEM',
      };

      const res = await cryptographicRuntime.execute(
        {
          type: 'ENCRYPT',
          algorithm: 'DES',
          policy: 'DEFAULT_SECURE',
          params: { key: 'invalid', plaintext: 'data' },
        },
        context
      );

      expect(res.success).toBe(false);
      expect(res.status).toBe('FAILED');
      expect(res.error?.code).toBe('POLICY_DENIED');
    });

    it('rejects non-FIPS compliant algorithms under FIPS_COMPLIANT policy', async () => {
      const context: TenantContext = {
        organizationId: testOrg.id,
        actorType: 'SYSTEM',
      };

      const res = await cryptographicRuntime.execute(
        {
          type: 'ENCRYPT',
          algorithm: 'CHACHA20-POLY1305',
          policy: 'FIPS_COMPLIANT',
          params: { key: 'invalid', plaintext: 'data' },
        },
        context
      );

      expect(res.success).toBe(false);
      expect(res.status).toBe('FAILED');
      expect(res.error?.code).toBe('POLICY_DENIED');
    });
  });

  // ==========================================================================
  // 6. IDEMPOTENCY & DEDUPLICATION
  // ==========================================================================
  describe('6. Idempotency Guarantees', () => {
    it('returns cached result on duplicate idempotency key without recomputing', async () => {
      const idempotencyKey = `idem_${Date.now()}_${Math.random()}`;
      const context: TenantContext = {
        organizationId: testOrg.id,
        actorType: 'USER_SESSION',
      };

      const request: CryptographicOperationRequest = {
        type: 'ENCRYPT',
        algorithm: 'AES-256-GCM',
        idempotencyKey,
        params: {
          key: crypto.randomBytes(32).toString('base64'),
          plaintext: 'Idempotency Payload Validation',
        },
      };

      const result1 = await cryptographicRuntime.execute(request, context);
      expect(result1.success).toBe(true);

      const result2 = await cryptographicRuntime.execute(request, context);
      expect(result2.success).toBe(true);
      expect(result2.data.ct).toEqual(result1.data.ct);
      expect(result2.data.iv).toEqual(result1.data.iv);
      expect(result2.data.tag).toEqual(result1.data.tag);
    });
  });

  // ==========================================================================
  // 7. SECURITY & ZERO SECRET LEAKAGE
  // ==========================================================================
  describe('7. Security & Zero Secret Leakage', () => {
    it('ensures cryptographic result metadata and envelopes never leak private keys or plaintext in audit logs', async () => {
      const rawPlaintext = 'Top Secret Plaintext Not In Logs';
      const key = crypto.randomBytes(32).toString('base64');

      const context: TenantContext = {
        organizationId: testOrg.id,
        actorId: testUser.id,
        actorType: 'USER_SESSION',
      };

      const result = await cryptographicRuntime.execute(
        {
          type: 'ENCRYPT',
          algorithm: 'AES-256-GCM',
          params: { key, plaintext: rawPlaintext },
        },
        context
      );

      // Verify returned result metadata has zero plaintext or key material
      const serializedMeta = JSON.stringify(result.metadata);
      expect(serializedMeta).not.toContain(rawPlaintext);
      expect(serializedMeta).not.toContain(key);

      // Verify audit logs generated for this operation also contain zero plaintext or key material
      const audits = await db.getAuditEventsByOrg(testOrg.id, 10);
      const matchingAudit = audits.find((a) => a.metadata?.operationId === result.operationId);
      if (matchingAudit) {
        const serializedAudit = JSON.stringify(matchingAudit);
        expect(serializedAudit).not.toContain(rawPlaintext);
        expect(serializedAudit).not.toContain(key);
      }
    });
  });

  // ==========================================================================
  // 8. UNIVERSAL API ENDPOINT INTEGRATION
  // ==========================================================================
  describe('8. Universal Execution & Observability REST Endpoints', () => {
    it('POST /v1/organizations/:orgId/crypto/execute executes canonical operation via API', async () => {
      const rawKey = crypto.randomBytes(32).toString('base64');
      const res = await fetch(`${baseUrl}/v1/organizations/${testOrg.id}/crypto/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${testSession.sessionToken}`,
        },
        body: JSON.stringify({
          type: 'ENCRYPT',
          algorithm: 'AES-256-GCM',
          params: {
            key: rawKey,
            plaintext: 'API-First Cryptographic Infrastructure',
          },
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.status).toBe('COMPLETED');
      expect(json.data.ct).toBeDefined();
      expect(json.meta.providerId).toBe('LOCAL_DEV');
    });

    it('GET /v1/organizations/:orgId/crypto/operations retrieves authoritative persisted operation records', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${testOrg.id}/crypto/operations`, {
        headers: {
          Authorization: `Bearer ${testSession.sessionToken}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThan(0);
      expect(json.data[0].status).toBeDefined();
    });
  });
});
