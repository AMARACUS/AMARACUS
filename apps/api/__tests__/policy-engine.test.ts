import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { Amaracus } from '@amaracus/sdk';
import {
  CryptographicPolicyEngine,
  PolicyConflictDetector,
  PolicyAiBoundary,
  GLOBAL_AMARACUS_SAFETY_POLICY,
  PolicyDocument,
} from '@amaracus/crypto-core';

describe('Phase 15 — Intelligent Cryptography & Policy Engine Test Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A Context
  let tenantAOrg: any;
  let tenantAUser: any;
  let tenantAProject: any;
  let tenantAEnv: any;
  let tenantAKeyFull: string;
  let tenantALogicalKey: any;

  // Tenant B Context (for IDOR isolation)
  let tenantBOrg: any;
  let tenantBUser: any;
  let tenantBKeyFull: string;

  // SDK Clients
  let sdkTenantA: Amaracus;
  let sdkTenantB: Amaracus;

  beforeAll(async () => {
    // 1. Start Server on dynamic port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 2. Setup Tenant A
    tenantAOrg = await db.createOrganization({
      name: 'Tenant A Policy Corp',
      slug: `tenant-a-policy-${Date.now()}`,
    });

    tenantAUser = await db.createUser({
      email: `admin-policy-a-${Date.now()}@amaracus.test`,
      passwordHash: 'dummy_hash',
      name: 'Policy Admin A',
    });

    await db.addMember({
      organizationId: tenantAOrg.id,
      userId: tenantAUser.id,
      role: 'ADMIN',
    });

    tenantAProject = await db.createProject({
      organizationId: tenantAOrg.id,
      name: 'Project Quantum Guard',
      slug: 'project-qguard',
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
      name: 'Tenant A Policy Key',
      keyHash: apiKeyA.keyHash,
      prefix: apiKeyA.prefix,
      scopes: ['*'],
    });

    // Create a logical key for Tenant A via API
    const keyRes = await fetch(`${baseUrl}/v1/keys`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${tenantAKeyFull}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'prod-primary-sym-key',
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
      }),
    });
    const keyBody = await keyRes.json();
    tenantALogicalKey = keyBody.data;

    // 3. Setup Tenant B
    tenantBOrg = await db.createOrganization({
      name: 'Tenant B Policy Corp',
      slug: `tenant-b-policy-${Date.now()}`,
    });

    tenantBUser = await db.createUser({
      email: `admin-policy-b-${Date.now()}@amaracus.test`,
      passwordHash: 'dummy_hash',
      name: 'Policy Admin B',
    });

    await db.addMember({
      organizationId: tenantBOrg.id,
      userId: tenantBUser.id,
      role: 'ADMIN',
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
      name: 'Tenant B Policy Key',
      keyHash: apiKeyB.keyHash,
      prefix: apiKeyB.prefix,
      scopes: ['*'],
    });

    // 4. Initialize SDKs
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
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  // ==========================================================================
  // SECTION A: Core Cryptographic Policy Engine & Invariants
  // ==========================================================================

  describe('Core Cryptographic Policy Engine & Invariants', () => {
    test('1. Global Safety Baseline rejects obsolete/broken algorithms (MD5, SHA-1, DES, RC4)', () => {
      const md5Result = CryptographicPolicyEngine.evaluate({
        organizationId: tenantAOrg.id,
        operationType: 'HASH',
        algorithm: 'MD5',
      });
      expect(md5Result.allowed).toBe(false);
      expect(md5Result.decision).toBe('DENY');
      expect(md5Result.reasons.some((r) => r.toLowerCase().includes('prohibited'))).toBe(true);
      expect(md5Result.trace[0].level).toBe('GLOBAL');

      const rc4Result = CryptographicPolicyEngine.evaluate({
        organizationId: tenantAOrg.id,
        operationType: 'ENCRYPT',
        algorithm: 'RC4',
      });
      expect(rc4Result.allowed).toBe(false);
      expect(rc4Result.decision).toBe('DENY');
    });

    test('2. Global Safety Baseline enforces minimum RSA and ECC key sizes', () => {
      const rsa1024Result = CryptographicPolicyEngine.evaluate({
        organizationId: tenantAOrg.id,
        operationType: 'SIGN',
        algorithm: 'RSA-1024',
      });
      expect(rsa1024Result.allowed).toBe(false);
      expect(rsa1024Result.decision).toBe('DENY');
      expect(rsa1024Result.reasons.some((r) => r.toLowerCase().includes('prohibited') || r.includes('minimum'))).toBe(true);

      const rsa2048Result = CryptographicPolicyEngine.evaluate({
        organizationId: tenantAOrg.id,
        operationType: 'SIGN',
        algorithm: 'RSA-2048',
      });
      expect(rsa2048Result.allowed).toBe(true);
      expect(rsa2048Result.decision).toBe('ALLOW');
    });

    test('3. Non-weakening invariant: PolicyConflictDetector rejects attempts to allow prohibited algorithms', () => {
      const maliciousDoc: PolicyDocument = {
        id: 'pol_weaken',
        name: 'Weaken Security Policy',
        scope: 'ORGANIZATION',
        version: 1,
        status: 'ACTIVE',
        rules: [
          {
            id: 'rule_allow_md5',
            name: 'Allow Insecure MD5',
            category: 'ALGORITHM_RESTRICTION',
            effect: 'ALLOW',
            enabled: true,
            condition: {
              algorithms: ['MD5'],
            },
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const conflicts = PolicyConflictDetector.detectConflicts(maliciousDoc, GLOBAL_AMARACUS_SAFETY_POLICY);
      expect(conflicts.length).toBeGreaterThan(0);
      expect(conflicts.some((c) => c.conflictType === 'SECURITY_WEAKENING_ATTEMPT' && c.ruleB.ruleId === 'rule_allow_md5')).toBe(true);
    });

    test('4. Multi-tier hierarchy precedence: Project PQC requirement overrides general Org allowance', () => {
      const orgPolicy: PolicyDocument = {
        id: 'pol_org',
        name: 'Org Baseline',
        scope: 'ORGANIZATION',
        version: 1,
        status: 'ACTIVE',
        rules: [
          {
            id: 'rule_allow_classical',
            name: 'Allow Standard AES, RSA, and ML-DSA',
            category: 'ALGORITHM_RESTRICTION',
            effect: 'ALLOW',
            enabled: true,
            condition: {
              algorithms: ['AES-256-GCM', 'RSA-2048', 'ML-DSA-65'],
            },
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const projectPolicy: PolicyDocument = {
        id: 'pol_proj',
        name: 'Project Quantum Mandate',
        scope: 'PROJECT',
        version: 1,
        status: 'ACTIVE',
        rules: [
          {
            id: 'rule_mandate_pqc',
            name: 'PQC Mandate',
            category: 'PQC_REQUIREMENT',
            effect: 'REQUIRE',
            enabled: true,
            condition: {
              pqcMode: 'PQC_REQUIRED',
            },
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // In this project, RSA-2048 is rejected because PQC is mandated
      const rsaResult = CryptographicPolicyEngine.evaluate(
        {
          organizationId: tenantAOrg.id,
          projectId: tenantAProject.id,
          operationType: 'SIGN',
          algorithm: 'RSA-2048',
        },
        {
          organizationPolicy: orgPolicy,
          projectPolicy: projectPolicy,
        }
      );
      expect(rsaResult.allowed).toBe(false);
      expect(rsaResult.decision).toBe('REQUIRE_STRONGER_ALGORITHM');

      // But ML-DSA-65 is allowed
      const pqcResult = CryptographicPolicyEngine.evaluate(
        {
          organizationId: tenantAOrg.id,
          projectId: tenantAProject.id,
          operationType: 'SIGN',
          algorithm: 'ML-DSA-65',
        },
        {
          organizationPolicy: orgPolicy,
          projectPolicy: projectPolicy,
        }
      );
      expect(pqcResult.allowed).toBe(true);
      expect(pqcResult.decision).toBe('ALLOW');
    });

    test('5. Key Hygiene & Rotation: Key exceeding max age triggers REQUIRE_KEY_ROTATION', () => {
      const rotationPolicy: PolicyDocument = {
        id: 'pol_rotation',
        name: '90-Day Key Rotation Policy',
        scope: 'ORGANIZATION',
        version: 1,
        status: 'ACTIVE',
        rules: [
          {
            id: 'rule_rot_90',
            name: '90-Day Rotation',
            category: 'KEY_HYGIENE',
            effect: 'REQUIRE',
            enabled: true,
            condition: {
              maxKeyAgeDays: 90,
            },
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const agedKeyResult = CryptographicPolicyEngine.evaluate(
        {
          organizationId: tenantAOrg.id,
          operationType: 'ENCRYPT',
          algorithm: 'AES-256-GCM',
          keyAgeDays: 120, // 120 days old
          keyReference: {
            id: 'key_aged',
            name: 'Old Key',
            organizationId: tenantAOrg.id,
            algorithm: 'AES-256-GCM',
            purpose: 'ENCRYPT_DECRYPT',
            provider: 'LOCAL_DEV_KMS',
            providerKeyId: 'key_aged',
            currentVersion: 1,
            status: 'ACTIVE',
            isHsmBacked: false,
            isCustomerManaged: false,
          },
        },
        { organizationPolicy: rotationPolicy }
      );

      expect(agedKeyResult.allowed).toBe(false);
      expect(agedKeyResult.decision).toBe('REQUIRE_KEY_ROTATION');
      expect(agedKeyResult.requirements.some((r) => r.includes('Rotate key'))).toBe(true);

      // Historical decryption exception permits read-only decryption
      const historicalDecryptResult = CryptographicPolicyEngine.evaluate(
        {
          organizationId: tenantAOrg.id,
          operationType: 'DECRYPT',
          algorithm: 'AES-256-GCM',
          keyAgeDays: 120,
          isHistoricalDecryption: true,
          keyReference: {
            id: 'key_aged',
            name: 'Old Key',
            organizationId: tenantAOrg.id,
            algorithm: 'AES-256-GCM',
            purpose: 'ENCRYPT_DECRYPT',
            provider: 'LOCAL_DEV_KMS',
            providerKeyId: 'key_aged',
            currentVersion: 1,
            status: 'ACTIVE',
            isHsmBacked: false,
            isCustomerManaged: false,
          },
        },
        { organizationPolicy: rotationPolicy }
      );

      expect(historicalDecryptResult.allowed).toBe(true);
      expect(historicalDecryptResult.warnings.some((w) => w.includes('Historical Decryption'))).toBe(true);
    });

    test('6. Hardware-Backed / HSM requirement triggers REQUIRE_APPROVED_PROVIDER', () => {
      const hsmPolicy: PolicyDocument = {
        id: 'pol_hsm',
        name: 'Mandatory HSM Policy',
        scope: 'ORGANIZATION',
        version: 1,
        status: 'ACTIVE',
        rules: [
          {
            id: 'rule_require_hsm',
            name: 'HSM Mandate',
            category: 'PROVIDER_RESTRICTION',
            effect: 'REQUIRE',
            enabled: true,
            condition: {
              requireHardwareBacked: true,
            },
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const softKeyResult = CryptographicPolicyEngine.evaluate(
        {
          organizationId: tenantAOrg.id,
          operationType: 'ENCRYPT',
          algorithm: 'AES-256-GCM',
          keyReference: {
            id: 'key_soft',
            name: 'Soft Key',
            organizationId: tenantAOrg.id,
            algorithm: 'AES-256-GCM',
            purpose: 'ENCRYPT_DECRYPT',
            provider: 'LOCAL_DEV_KMS',
            providerKeyId: 'key_soft',
            currentVersion: 1,
            status: 'ACTIVE',
            isHsmBacked: false,
            isCustomerManaged: false,
          },
        },
        { organizationPolicy: hsmPolicy }
      );

      expect(softKeyResult.allowed).toBe(false);
      expect(softKeyResult.decision).toBe('REQUIRE_APPROVED_PROVIDER');
      expect(softKeyResult.requirements.some((r) => r.includes('Azure Managed HSM'))).toBe(true);
    });

    test('7. AI Boundary & Explainability: Explanation generation preserves decision and provides human insight', () => {
      const decision = CryptographicPolicyEngine.evaluate({
        organizationId: tenantAOrg.id,
        operationType: 'HASH',
        algorithm: 'SHA-1',
      });

      const explanation = PolicyAiBoundary.explainDecision(decision);
      expect(explanation.summary).toContain('DENIED');
      expect(explanation.disclaimer).toBeDefined();
      expect(explanation.recommendedActions.length).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // SECTION B: REST API Endpoints (/v1/policies) & Lifecycle
  // ==========================================================================

  describe('REST API Endpoints (/v1/policies) & Lifecycle', () => {
    let createdPolicyId: string;

    test('1. POST /v1/policies creates a new organization policy', async () => {
      const res = await fetch(`${baseUrl}/v1/policies`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          name: 'Corporate Cryptographic Policy',
          scope: 'ORGANIZATION',
          description: 'Production baseline requiring AES-256 and SHA-256',
          rules: [
            {
              id: 'rule_modern_symmetric',
              name: 'Modern Symmetric Only',
              category: 'ALGORITHM_RESTRICTION',
              effect: 'ALLOW',
              enabled: true,
              condition: {
                algorithms: ['AES-256-GCM', 'CHACHA20-POLY1305'],
              },
            },
          ],
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.id).toBeDefined();
      expect(json.data.name).toBe('Corporate Cryptographic Policy');
      expect(json.data.version).toBe(1);
      createdPolicyId = json.data.id;
    });

    test('2. GET /v1/policies lists policies for tenant', async () => {
      const res = await fetch(`${baseUrl}/v1/policies`, {
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.some((p: any) => p.id === createdPolicyId)).toBe(true);
    });

    test('3. GET /v1/policies/:id retrieves policy details', async () => {
      const res = await fetch(`${baseUrl}/v1/policies/${createdPolicyId}`, {
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.id).toBe(createdPolicyId);
      expect(json.data.rules.length).toBe(1);
    });

    test('4. PATCH /v1/policies/:id updates policy and creates new version', async () => {
      const res = await fetch(`${baseUrl}/v1/policies/${createdPolicyId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          description: 'Updated baseline with 180-day key rotation rule',
          rules: [
            {
              id: 'rule_modern_symmetric',
              name: 'Modern Symmetric Only',
              category: 'ALGORITHM_RESTRICTION',
              effect: 'ALLOW',
              enabled: true,
              condition: {
                algorithms: ['AES-256-GCM'],
              },
            },
            {
              id: 'rule_key_rot',
              name: '180 Day Rotation',
              category: 'KEY_HYGIENE',
              effect: 'REQUIRE',
              enabled: true,
              condition: {
                maxKeyAgeDays: 180,
              },
            },
          ],
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.version).toBe(2);
      expect(json.data.rules.length).toBe(2);
    });

    test('5. POST /v1/policies/dry-run evaluates prospective operation without execution', async () => {
      // Dry-run prospective AES-256-GCM operation -> ALLOW
      const resAllowed = await fetch(`${baseUrl}/v1/policies/dry-run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          operationType: 'ENCRYPT',
          algorithm: 'AES-256-GCM',
        }),
      });

      expect(resAllowed.status).toBe(200);
      const jsonAllowed = await resAllowed.json();
      expect(jsonAllowed.data.allowed).toBe(true);
      expect(jsonAllowed.data.decision).toBe('ALLOW');
      expect(jsonAllowed.data.trace.length).toBeGreaterThan(0);
      expect(jsonAllowed.data.explanation).toBeDefined();

      // Dry-run prospective MD5 operation -> DENY
      const resDenied = await fetch(`${baseUrl}/v1/policies/dry-run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          operationType: 'HASH',
          algorithm: 'MD5',
        }),
      });

      expect(resDenied.status).toBe(200);
      const jsonDenied = await resDenied.json();
      expect(jsonDenied.data.allowed).toBe(false);
      expect(jsonDenied.data.decision).toBe('DENY');
      expect(jsonDenied.data.reasons.length).toBeGreaterThan(0);
    });

    test('6. POST /v1/policies/:id/simulate evaluates proposed policy against active inventory', async () => {
      const res = await fetch(`${baseUrl}/v1/policies/${createdPolicyId}/simulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({}),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.summary).toBeDefined();
      expect(json.data.summary.totalEvaluated).toBeGreaterThan(0);
      expect(json.data.impacts).toBeDefined();
    });

    test('7. GET /v1/policies/metrics returns evaluation telemetry and cache stats', async () => {
      const res = await fetch(`${baseUrl}/v1/policies/metrics`, {
        headers: {
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.evaluationCount).toBeGreaterThan(0);
      expect(json.data.decisionDistribution).toBeDefined();
      expect(json.data.cacheHitRatio).toBeDefined();
    });

    test('8. Multi-tenant IDOR Security: Tenant B cannot access Tenant A policy', async () => {
      const res = await fetch(`${baseUrl}/v1/policies/${createdPolicyId}`, {
        headers: {
          Authorization: `Bearer ${tenantBKeyFull}`,
        },
      });
      expect(res.status).toBe(404);

      const patchRes = await fetch(`${baseUrl}/v1/policies/${createdPolicyId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantBKeyFull}`,
        },
        body: JSON.stringify({ name: 'Tampered Name' }),
      });
      expect(patchRes.status).toBe(404);
    });
  });

  // ==========================================================================
  // SECTION C: Zero-Bypass Runtime & Managed Operations Enforcement
  // ==========================================================================

  describe('Zero-Bypass Runtime & Managed Operations Enforcement', () => {
    test('1. Prohibited algorithm (MD5) is blocked at runtime submission with 403', async () => {
      const res = await fetch(`${baseUrl}/v1/operations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          type: 'HASH',
          algorithm: 'MD5',
          params: { data: 'test-data' },
        }),
      });

      expect(res.status).toBe(403);
      const json = await res.json();
      expect(json.error.code).toMatch(/POLICY_VIOLATION|INSUFFICIENT_SECURITY/);
    });

    test('2. Allowed algorithm (AES-256-GCM) with compliant key succeeds normally', async () => {
      const encryptRes = await fetch(`${baseUrl}/v1/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tenantAKeyFull}`,
        },
        body: JSON.stringify({
          key: tenantALogicalKey.id,
          plaintext: 'Hello Policy Engine',
        }),
      });

      expect(encryptRes.status).toBe(200);
      const json = await encryptRes.json();
      expect(json.data.ciphertext).toBeDefined();
    });
  });

  // ==========================================================================
  // SECTION D: Official SDK Client Integration (amaracus.policies.*)
  // ==========================================================================

  describe('Official SDK Client Integration (amaracus.policies.*)', () => {
    let sdkPolicyId: string;

    test('1. sdk.policies.create and sdk.policies.list', async () => {
      const policy = await sdkTenantA.policies.create({
        name: 'SDK Managed Policy',
        scope: 'ORGANIZATION',
        description: 'Created via official SDK',
        rules: [
          {
            id: 'rule_sdk_pqc',
            name: 'PQC Preferred',
            category: 'PQC_REQUIREMENT',
            effect: 'WARN',
            enabled: true,
          },
        ],
      });

      expect(policy.id).toBeDefined();
      expect(policy.name).toBe('SDK Managed Policy');
      sdkPolicyId = policy.id;

      const list = await sdkTenantA.policies.list();
      expect(list.items.some((p) => p.id === sdkPolicyId)).toBe(true);
    });

    test('2. sdk.policies.get and sdk.policies.update', async () => {
      const fetched = await sdkTenantA.policies.get(sdkPolicyId);
      expect(fetched.id).toBe(sdkPolicyId);

      const updated = await sdkTenantA.policies.update(sdkPolicyId, {
        description: 'Updated description via SDK',
      });
      expect(updated.version).toBe(2);
    });

    test('3. sdk.policies.dryRun', async () => {
      const dryRun = await sdkTenantA.policies.dryRun({
        operationType: 'ENCRYPT',
        algorithm: 'AES-256-GCM',
      });

      expect(dryRun.allowed).toBe(true);
      expect(dryRun.decision).toBe('ALLOW');
      expect(dryRun.trace.length).toBeGreaterThan(0);
    });

    test('4. sdk.policies.simulate', async () => {
      const simulation = await sdkTenantA.policies.simulate(sdkPolicyId);
      expect(simulation.summary).toBeDefined();
      expect(simulation.summary.totalEvaluated).toBeGreaterThan(0);
    });

    test('5. sdk.policies.metrics', async () => {
      const metrics = await sdkTenantA.policies.metrics();
      expect(metrics.evaluationCount).toBeGreaterThan(0);
      expect(metrics.decisionDistribution).toBeDefined();
    });

    test('6. sdk.policies.delete', async () => {
      const del = await sdkTenantA.policies.delete(sdkPolicyId);
      expect(del.success).toBe(true);
    });
  });
});
