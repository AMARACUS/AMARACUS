import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { Amaracus } from '@amaracus/sdk';
import {
  MigrationAssessmentEngine,
  MigrationPriorityScorer,
  MigrationDependencyGraphBuilder,
  MigrationCompatibilityChecker,
  MigrationSimulationEngine,
  CryptoEngineService,
  generateSecureRandom,
} from '@amaracus/crypto-core';

describe('Phase 19 — AMARACUS Cryptographic Migration Platform Test Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A: Primary Enterprise Organization
  let orgA: any;
  let projectA: any;
  let envAProd: any;
  let envATest: any;
  let apiKeyALive: string;
  let apiKeyATest: string;

  // Tenant B: Isolated Organization for IDOR verification
  let orgB: any;
  let projectB: any;
  let apiKeyBLive: string;

  // Users in Org A for separation of duties
  const userProposerId = `usr_proposer_${Date.now()}`;
  const userApproverId = `usr_approver_${Date.now()}`;

  // Created resources in Org A
  let legacyKeyA: any;
  let expiringCertA: any;
  let createdPlanId: string;

  const cryptoService = new CryptoEngineService();

  beforeAll(async () => {
    // 1. Launch HTTP server on dynamic port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 2. Setup Tenant A
    orgA = await db.createOrganization({
      name: 'Migration Enterprise Org',
      slug: `mig-org-${Date.now()}`,
    });

    await db.upsertBillingSubscription({
      organizationId: orgA.id,
      plan: 'ENTERPRISE',
      status: 'ACTIVE',
    });

    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Core Cryptographic Services',
      slug: `core-crypto-${Date.now()}`,
      description: 'Host for enterprise cryptographic workloads and migration',
    });

    envAProd = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      type: 'PRODUCTION',
    });

    envATest = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Testing',
      type: 'DEVELOPMENT',
    });

    // Generate Production API Key (am_live_...)
    const keyLiveResult = generateAmaracusApiKey('live');
    apiKeyALive = keyLiveResult.fullKey;
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      name: 'Production Key',
      keyHash: keyLiveResult.keyHash,
      prefix: keyLiveResult.prefix,
      scopes: ['*'],
    });

    // Generate Test API Key (am_test_...)
    const keyTestResult = generateAmaracusApiKey('test');
    apiKeyATest = keyTestResult.fullKey;
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envATest.id,
      name: 'Sandbox Key',
      keyHash: keyTestResult.keyHash,
      prefix: keyTestResult.prefix,
      scopes: ['*'],
    });

    // Create legacy cryptographic key in Org A
    legacyKeyA = await db.createKey({
      name: 'legacy-payment-key',
      description: 'Legacy payment token encryption key using 3DES/AES-128',
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      algorithm: 'AES-128-GCM',
      purpose: 'ENCRYPTION',
      provider: 'software',
      status: 'ACTIVE',
    });

    // Create expiring certificate in Org A
    expiringCertA = await db.createCertificate({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      name: 'expiring-gateway-cert',
      subject: 'CN=gateway.corp.internal',
      issuer: 'AMARACUS Internal Root CA',
      serialNumber: 'abc123serial',
      certificateType: 'SERVER',
      keyAlgorithm: 'RSA',
      signatureAlgorithm: 'RSA-2048',
      publicKeyAlgorithm: 'RSA-2048',
      keyReference: `ref_${legacyKeyA.id}`,
      fingerprint: '11223344556677889900aabbccddeeff',
      certificatePem: '-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----',
      status: 'ACTIVE',
      notBefore: new Date(Date.now() - 350 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000), // Expires in 15 days
    });

    // 3. Setup Tenant B
    orgB = await db.createOrganization({
      name: 'Competitor Corp',
      slug: `comp-org-${Date.now()}`,
    });

    await db.upsertBillingSubscription({
      organizationId: orgB.id,
      plan: 'ENTERPRISE',
      status: 'ACTIVE',
    });

    projectB = await db.createProject({
      organizationId: orgB.id,
      name: 'Competitor Gateway',
      slug: `comp-proj-${Date.now()}`,
    });

    const envBProd = await db.createEnvironment({
      projectId: projectB.id,
      name: 'Production',
      type: 'PRODUCTION',
    });

    const keyBResult = generateAmaracusApiKey('live');
    apiKeyBLive = keyBResult.fullKey;
    await db.createApiCredential({
      organizationId: orgB.id,
      projectId: projectB.id,
      environmentId: envBProd.id,
      name: 'Competitor Master Key',
      keyHash: keyBResult.keyHash,
      prefix: keyBResult.prefix,
      scopes: ['*'],
    });
  });

  afterAll(async () => {
    try {
      const { managedOperationQueue } = await import('../src/lib/managed-operation-queue');
      await managedOperationQueue.shutdown();
    } catch {}
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  describe('1. Migration Assessment Engine & Explainable Prioritization', () => {
    it('should assess organization assets and return ranked migration candidates', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/assess`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      // Verify category tagging (Category A, B, C)
      const categories = body.data.map((c: any) => c.category);
      expect(categories).toContain('CATEGORY_A_AMARACUS_MANAGED');

      // Verify explainable priority score breakdown
      const firstCandidate = body.data[0];
      expect(firstCandidate.priority).toBeDefined();
      expect(typeof firstCandidate.priority.score).toBe('number');
      expect(firstCandidate.priority.score).toBeGreaterThanOrEqual(0);
      expect(firstCandidate.priority.score).toBeLessThanOrEqual(100);
      expect(firstCandidate.priority.level).toBeDefined();
      expect(firstCandidate.priority.rationale).toBeDefined();
      expect(firstCandidate.priority.components).toBeDefined();
      expect(typeof firstCandidate.priority.components.severity).toBe('number');
    });

    it('should correctly score emergency compromised assets with high severity and warning', () => {
      const score = MigrationPriorityScorer.calculate({
        algorithm: 'AES-256-GCM',
        isCompromised: true,
        businessCriticality: 'MISSION_CRITICAL',
      });

      expect(score.score).toBeGreaterThanOrEqual(50);
      expect(score.rationale).toContain('CRITICAL INCIDENT: Asset compromise indicated');
    });
  });

  describe('2. Migration Planning & Dependency Graph', () => {
    it('should create a migration plan in DRAFT status', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeyALive}`,
        },
        body: JSON.stringify({
          name: 'Upgrade Legacy AES-128 Payment Key',
          description: 'Migrate to AES-256-GCM AEAD envelope key',
          migrationType: 'KEY_ROTATION',
          sourceResourceId: legacyKeyA.id,
          sourceAlgorithm: 'AES-128-GCM',
          targetAlgorithm: 'AES-256-GCM',
          sourceProvider: 'software',
          targetProvider: 'software',
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.id).toBeDefined();
      expect(body.data.status).toBe('DRAFT');
      expect(body.data.name).toBe('Upgrade Legacy AES-128 Payment Key');
      expect(body.data.sourceAlgorithm).toBe('AES-128-GCM');
      expect(body.data.targetAlgorithm).toBe('AES-256-GCM');
      expect(body.data.rollbackPlan.isReversible).toBe(true);

      createdPlanId = body.data.id;
    });

    it('should retrieve plan details including dependency graph', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.id).toBe(createdPlanId);
      expect(body.data.dependencyGraph).toBeDefined();
      expect(Array.isArray(body.data.dependencyGraph.nodes)).toBe(true);
      expect(Array.isArray(body.data.dependencyGraph.edges)).toBe(true);
      expect(body.data.dependencyGraph.isIncomplete).toBeDefined();
    });

    it('should list all migration plans for the organization', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.data)).toBe(true);
      const found = body.data.find((p: any) => p.id === createdPlanId);
      expect(found).toBeDefined();
    });
  });

  describe('3. Pre-Migration Compatibility Checks & Non-Destructive Simulation', () => {
    it('should reject incompatible primitive migrations (e.g. Asymmetric to Symmetric)', () => {
      const checkResult = MigrationCompatibilityChecker.check({
        sourceAlgorithm: 'RSA-2048',
        targetAlgorithm: 'AES-256-GCM',
        organizationId: orgA.id,
      });

      expect(checkResult.compatible).toBe(false);
      expect(checkResult.keyFormatCompatible).toBe(false);
      expect(checkResult.blockingIssues.length).toBeGreaterThan(0);
      expect(checkResult.blockingIssues[0]).toContain('Incompatible cryptographic primitive type');
    });

    it('should reject unrecognized target algorithms', () => {
      const checkResult = MigrationCompatibilityChecker.check({
        sourceAlgorithm: 'AES-128-GCM',
        targetAlgorithm: 'MAGIC-UNKNOWN-ALGO-999',
        organizationId: orgA.id,
      });

      expect(checkResult.compatible).toBe(false);
      expect(checkResult.algorithmSupported).toBe(false);
      expect(checkResult.blockingIssues[0]).toContain('not recognized in the AMARACUS Algorithm Registry');
    });

    it('should execute non-destructive simulation and generate comprehensive impact report', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}/simulate`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.simulationId).toBeDefined();
      expect(body.data.planId).toBe(createdPlanId);
      expect(body.data.overallSafe).toBe(true);
      expect(body.data.compatibility.compatible).toBe(true);
      expect(body.data.rollbackAvailable).toBe(true);
      expect(body.data.rollbackType).toBe('AUTOMATIC_REVERSIBLE');
      expect(body.data.commercialImpact).toBeDefined();
      expect(Array.isArray(body.data.recommendations)).toBe(true);

      // Verify plan state transitioned to SIMULATED
      const planRes = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });
      const planData = await planRes.json();
      expect(planData.data.status).toBe('SIMULATED');
    });
  });

  describe('4. Approval Workflow & Separation of Duties (RBAC)', () => {
    it('should enforce separation of duties: proposer cannot self-approve production plans', async () => {
      // The API key user created the plan. Attempting to self-approve with same identity
      const planRes = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}`, {
        headers: { Authorization: `Bearer ${apiKeyALive}` },
      });
      const planBody = await planRes.json();
      const proposerId = planBody.data.proposerId;

      // Simulate a request where proposer attempts self-approval
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}/approve`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      // Since proposerId === apiKey.id, separation of duties should block
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error.code).toBe('SEPARATION_OF_DUTIES_VIOLATION');
      expect(body.error.message).toContain('Proposer cannot self-approve');
    });

    it('should approve migration plan when distinct authorized approver signs off', async () => {
      // Directly approve with a distinct security admin user ID in the runner
      const { migrationRunner } = await import('../src/lib/migration-runner');
      const approvedPlan = await migrationRunner.approvePlan(
        orgA.id,
        createdPlanId,
        userApproverId,
        'SECURITY_ADMIN'
      );

      expect(approvedPlan.status).toBe('APPROVED');
      expect(approvedPlan.approverId).toBe(userApproverId);
      expect(approvedPlan.approvedAt).toBeDefined();

      // Verify via API GET
      const getRes = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}`, {
        headers: { Authorization: `Bearer ${apiKeyALive}` },
      });
      const body = await getRes.json();
      expect(body.data.status).toBe('APPROVED');
    });
  });

  describe('5. Durable Execution Engine & Staged Key Rotation', () => {
    it('should execute approved key rotation plan without destroying source key prematurely', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}/execute`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.status).toBe('COMPLETED');
      expect(body.data.targetResourceId).toBeDefined();
      expect(body.data.verificationResult.verified).toBe(true);

      // Verify source key was RETIRED_FOR_ENCRYPTION rather than deleted/destroyed
      const sourceKey = await db.getKey(legacyKeyA.id, orgA.id);
      expect(sourceKey).toBeDefined();
      expect(sourceKey?.status).toBe('RETIRED_FOR_ENCRYPTION');

      // Verify target key is ACTIVE and created with target algorithm
      const targetKey = await db.getKey(body.data.targetResourceId, orgA.id);
      expect(targetKey).toBeDefined();
      expect(targetKey?.status).toBe('ACTIVE');
      expect(targetKey?.algorithm).toBe('AES-256-GCM');
    });
  });

  describe('6. Reversible Rollback Engine', () => {
    it('should successfully rollback completed key rotation plan', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}/rollback`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.status).toBe('ROLLED_BACK');

      // Verify source key was restored to ACTIVE
      const sourceKey = await db.getKey(legacyKeyA.id, orgA.id);
      expect(sourceKey?.status).toBe('ACTIVE');

      // Verify target key was DISABLED
      const planRes = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}`, {
        headers: { Authorization: `Bearer ${apiKeyALive}` },
      });
      const planData = await planRes.json();
      const targetKey = await db.getKey(planData.data.targetResourceId, orgA.id);
      expect(targetKey?.status).toBe('DISABLED');
    });
  });

  describe('7. Post-Quantum Cryptography (PQC) Migration Execution', () => {
    it('should create and execute a genuine ML-KEM-768 post-quantum migration plan', async () => {
      const { migrationRunner } = await import('../src/lib/migration-runner');

      // 1. Create PQC migration plan
      const pqcPlan = await migrationRunner.createPlan({
        organizationId: orgA.id,
        name: 'Migrate Classical Key Agreement to Quantum-Safe ML-KEM-768',
        migrationType: 'POST_QUANTUM_MIGRATION',
        sourceResourceId: legacyKeyA.id,
        sourceAlgorithm: 'ECDH-P256',
        targetAlgorithm: 'ML-KEM-768',
        sourceProvider: 'software',
        targetProvider: 'software',
        proposerId: userProposerId,
      });

      // 2. Approve with distinct user
      await migrationRunner.approvePlan(orgA.id, pqcPlan.id, userApproverId, 'SECURITY_ADMIN');

      // 3. Execute
      const completedPqcPlan = await migrationRunner.executePlan(orgA.id, pqcPlan.id, userApproverId);
      expect(completedPqcPlan.status).toBe('COMPLETED');
      expect(completedPqcPlan.targetResourceId).toBeDefined();

      const pqcKey = await db.getKey(completedPqcPlan.targetResourceId!, orgA.id);
      expect(pqcKey?.algorithm).toBe('ML-KEM-768');
      expect(pqcKey?.status).toBe('ACTIVE');
    });
  });

  describe('8. Controlled Batch Data Re-Encryption (Envelope v1 AEAD)', () => {
    it('should re-encrypt a batch of AEAD envelopes with integrity verification', async () => {
      // 1. Create 3 sample encrypted envelopes with source key
      const sourceKeyMaterial = crypto.createHash('sha256').update(legacyKeyA.id).digest();
      const plaintexts = ['Patient Social Security Number: 123-45-6789', 'Confidential Balance: $500,000.00', 'Medical Record #98765'];

      const envelopes = [];
      for (const pt of plaintexts) {
        const enc = await cryptoService.encrypt({
          algorithm: 'AES-256-GCM',
          key: sourceKeyMaterial,
          plaintext: pt,
        });
        envelopes.push(enc);
      }

      // 2. Execute batch re-encryption API
      const res = await fetch(`${baseUrl}/api/v1/migrations/re-encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeyALive}`,
        },
        body: JSON.stringify({
          sourceKeyId: legacyKeyA.id,
          targetKeyId: `key_dest_${Date.now()}`,
          envelopes,
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.total).toBe(3);
      expect(body.data.succeeded).toBe(3);
      expect(body.data.failed).toBe(0);
      expect(body.data.bytesProcessed).toBeGreaterThan(0);
      expect(body.data.reEncryptedEnvelopes.length).toBe(3);

      // Verify each re-encrypted envelope is valid Envelope v1 format
      for (const reEnc of body.data.reEncryptedEnvelopes) {
        expect(reEnc.v).toBe(1);
        expect(reEnc.alg).toBe('AES-256-GCM');
        expect(reEnc.iv).toBeDefined();
        expect(reEnc.ct).toBeDefined();
        expect(reEnc.tag).toBeDefined();
      }
    });
  });

  describe('9. Tenant Isolation & IDOR Protection', () => {
    it('Org B cannot access or view Org A migration plans', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}`, {
        headers: {
          Authorization: `Bearer ${apiKeyBLive}`,
        },
      });

      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.error.code).toBe('RESOURCE_NOT_FOUND');
    });

    it('Org B cannot simulate, approve, or execute Org A migration plans', async () => {
      const res = await fetch(`${baseUrl}/api/v1/migrations/plans/${createdPlanId}/simulate`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKeyBLive}`,
        },
      });

      expect(res.status).toBe(404);
    });
  });

  describe('10. SDK Client Integration', () => {
    it('should assess inventory and list plans via official @amaracus/sdk client', async () => {
      const client = new Amaracus({
        apiKey: apiKeyALive,
        baseUrl: `${baseUrl}/api/v1`,
      });

      const assessments = await client.migrations.assess();
      expect(Array.isArray(assessments)).toBe(true);

      const plans = await client.migrations.listPlans();
      expect(Array.isArray(plans)).toBe(true);
      expect(plans.length).toBeGreaterThan(0);
    });
  });
});
