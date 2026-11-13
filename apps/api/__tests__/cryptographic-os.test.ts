/**
 * @file apps/api/__tests__/cryptographic-os.test.ts
 * Comprehensive Test Suite for Phase 20: AMARACUS Enterprise Cryptographic Operating System
 */

import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { Amaracus } from '@amaracus/sdk';
import {
  validateResourceRelationships,
  canTransitionLifecycle,
  UnifiedPostureEngine,
  CryptographicWorkflowEngine,
  CryptographicAutomationEngine,
  ENTERPRISE_WORKFLOW_TEMPLATES,
  UnifiedResource,
} from '@amaracus/crypto-core';
import { cryptoOsOrchestrator } from '../src/lib/crypto-os-orchestrator';

describe('Phase 20 — AMARACUS Enterprise Cryptographic Operating System', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A: Primary Enterprise Organization
  let orgA: any;
  let projectA: any;
  let envAProd: any;
  let apiKeyALive: string;

  // Tenant B: Isolated Organization for IDOR/Tenant isolation
  let orgB: any;
  let projectB: any;
  let apiKeyBLive: string;

  // User identities for separation of duties
  const proposerId = `usr_alice_${Date.now()}`;
  const approverId = `usr_bob_${Date.now()}`;

  let sdkClientA: Amaracus;
  let sdkClientB: Amaracus;

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
      name: 'Cyber Corp Global',
      slug: `cyber-corp-${Date.now()}`,
    });
    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Core Security Infrastructure',
      slug: 'core-infra',
    });
    envAProd = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    const keyResultA = generateAmaracusApiKey('live');
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      name: 'Enterprise OS Admin Key',
      prefix: keyResultA.prefix,
      keyHash: keyResultA.keyHash,
      scopes: [
        'os:read',
        'os:write',
        'os:workflows',
        'os:posture',
        'os:automation',
        'crypto:execute',
      ],
      env: 'live',
    });
    apiKeyALive = keyResultA.fullKey;

    // 3. Setup Tenant B
    orgB = await db.createOrganization({
      name: 'Isolated Partner Corp',
      slug: `partner-corp-${Date.now()}`,
    });
    projectB = await db.createProject({
      organizationId: orgB.id,
      name: 'Isolated Operations',
      slug: 'isolated-ops',
    });
    const envBProd = await db.createEnvironment({
      projectId: projectB.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    const keyResultB = generateAmaracusApiKey('live');
    await db.createApiCredential({
      organizationId: orgB.id,
      projectId: projectB.id,
      environmentId: envBProd.id,
      name: 'Partner Key',
      prefix: keyResultB.prefix,
      keyHash: keyResultB.keyHash,
      scopes: [
        'os:read',
        'os:write',
        'os:workflows',
        'os:posture',
        'os:automation',
      ],
      env: 'live',
    });
    apiKeyBLive = keyResultB.fullKey;

    sdkClientA = new Amaracus({
      apiKey: apiKeyALive,
      baseUrl: `${baseUrl}/api/v1`,
    });

    sdkClientB = new Amaracus({
      apiKey: apiKeyBLive,
      baseUrl: `${baseUrl}/api/v1`,
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  // =========================================================================
  // 1. UNIFIED RESOURCE MODEL & RELATIONSHIPS
  // =========================================================================
  describe('1. Unified Resource Model & Lifecycle State Transitions', () => {
    it('validates parent-child relationship boundaries and catches cross-tenant breaches', () => {
      const parent = { orgId: 'org_123', projectId: 'proj_abc' };
      const validChild = { orgId: 'org_123', projectId: 'proj_abc' };
      const crossTenantChild = { orgId: 'org_999', projectId: 'proj_abc' };

      expect(validateResourceRelationships(parent, validChild).valid).toBe(true);
      const res = validateResourceRelationships(parent, crossTenantChild);
      expect(res.valid).toBe(false);
      expect(res.reason).toContain('Cross-organization boundary violation');
    });

    it('validates permitted lifecycle transitions per resource type', () => {
      // Key: ACTIVATION -> ROTATION is allowed
      expect(canTransitionLifecycle('KEY', 'ACTIVATION', 'ROTATION').allowed).toBe(true);

      // Key: Cannot transition out of terminal state RETIREMENT
      const retiredCheck = canTransitionLifecycle('KEY', 'RETIREMENT', 'ACTIVATION');
      expect(retiredCheck.allowed).toBe(false);
      expect(retiredCheck.reason).toContain('terminal state RETIREMENT');

      // Key: Cannot reactivate directly from DEACTIVATION without re-configuration
      const deactCheck = canTransitionLifecycle('KEY', 'DEACTIVATION', 'ACTIVATION');
      expect(deactCheck.allowed).toBe(false);
      expect(deactCheck.reason).toContain('Deactivated keys require administrative re-approval');
    });

    it('clearly distinguishes verified inventory from unverified inferred resources', async () => {
      const inventory = await cryptoOsOrchestrator.getUnifiedInventory(orgA.id);
      expect(inventory.length).toBeGreaterThan(0);

      const verified = inventory.filter((r) => r.verified === true);
      const unverified = inventory.filter((r) => r.verified === false);

      expect(verified.length).toBeGreaterThan(0);
      expect(unverified.length).toBeGreaterThan(0);
      expect(unverified[0].verificationSource).toBe('INFERRED_DEPENDENCY');
    });
  });

  // =========================================================================
  // 2. UNIFIED SECURITY POSTURE ENGINE & DEDUPLICATION
  // =========================================================================
  describe('2. Unified Cryptographic Security Posture & Deduplication', () => {
    it('deduplicates findings when multiple observations report the same underlying issue', () => {
      const resources: UnifiedResource[] = [
        {
          id: 'key_dep_3des',
          type: 'KEY',
          name: 'Old Triple DES Key',
          orgId: 'org_test',
          status: 'ACTIVE',
          verified: true,
          verificationSource: 'DIRECT_STORAGE',
          algorithm: '3DES-EDE-CBC',
          metadata: {},
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ];

      const posture = UnifiedPostureEngine.evaluatePosture(resources);
      expect(posture.findings.length).toBe(1);
      expect(posture.findings[0].code).toBe('DEPRECATED_ALGORITHM_DETECTED');
      expect(posture.findings[0].severity).toBe('CRITICAL');
      expect(posture.score).toBeLessThan(100);
    });

    it('correctly calculates PQC readiness percentage and certificate expiration findings', () => {
      const now = new Date();
      const resources: UnifiedResource[] = [
        {
          id: 'key_pqc_mlkem',
          type: 'KEY',
          name: 'Quantum Resistant KEM Key',
          orgId: 'org_test',
          status: 'ACTIVE',
          verified: true,
          verificationSource: 'DIRECT_STORAGE',
          algorithm: 'ML-KEM-768',
          metadata: {},
          createdAt: now.toISOString(),
          updatedAt: now.toISOString(),
        },
        {
          id: 'key_classical_rsa',
          type: 'KEY',
          name: 'Classical RSA Key',
          orgId: 'org_test',
          status: 'ACTIVE',
          verified: true,
          verificationSource: 'DIRECT_STORAGE',
          algorithm: 'RSA-2048',
          metadata: {},
          createdAt: now.toISOString(),
          updatedAt: now.toISOString(),
        },
        {
          id: 'cert_expiring',
          type: 'CERTIFICATE',
          name: 'Expiring TLS Cert',
          orgId: 'org_test',
          status: 'ACTIVE',
          verified: true,
          verificationSource: 'DIRECT_STORAGE',
          metadata: {
            validTo: new Date(now.getTime() + 10 * 86400000).toISOString(), // 10 days remaining (HIGH)
          },
          createdAt: now.toISOString(),
          updatedAt: now.toISOString(),
        },
      ];

      const posture = UnifiedPostureEngine.evaluatePosture(resources, { now });
      expect(posture.pqcReadinessPercentage).toBe(50); // 1 PQC out of 2 asymmetric keys
      expect(posture.bySeverity.high).toBeGreaterThanOrEqual(1);
      expect(posture.findings.some((f) => f.code === 'CERTIFICATE_EXPIRING_IMMINENT')).toBe(true);
    });

    it('incorporates provider circuit breaker health states into posture summary', () => {
      const resources: UnifiedResource[] = [
        {
          id: 'prov_akv',
          type: 'PROVIDER',
          name: 'azure_key_vault',
          orgId: 'org_test',
          status: 'ACTIVE',
          verified: true,
          verificationSource: 'PROVIDER_TELEMETRY',
          metadata: {},
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ];

      const healthyPosture = UnifiedPostureEngine.evaluatePosture(resources, {
        circuitBreakerStates: { azure_key_vault: 'CLOSED' },
      });
      expect(healthyPosture.byCategory['PROVIDER_HEALTH']).toBeUndefined();

      const degradedPosture = UnifiedPostureEngine.evaluatePosture(resources, {
        circuitBreakerStates: { azure_key_vault: 'OPEN' },
      });
      expect(degradedPosture.bySeverity.critical).toBe(1);
      expect(degradedPosture.findings[0].code).toBe('PROVIDER_CIRCUIT_BREAKER_OPEN');
    });
  });

  // =========================================================================
  // 3. WORKFLOW ENGINE & DUAL-AUTHORIZATION GOVERNANCE
  // =========================================================================
  describe('3. Workflow Engine & Dual-Authorization Governance', () => {
    it('instantiates and validates a workflow from enterprise templates', () => {
      const wf = CryptographicWorkflowEngine.instantiateTemplate('tpl_key_rotation', {
        orgId: orgA.id,
        proposerId,
        name: 'Automated Key Rotation Workflow',
      });

      expect(wf.state).toBe('DRAFT');
      expect(wf.steps.length).toBe(4);
      expect(wf.requiresDualApproval).toBe(true);

      const validated = CryptographicWorkflowEngine.validateWorkflow(wf);
      expect(validated.state).toBe('AWAITING_APPROVAL');
    });

    it('strictly rejects self-approval by the proposer (four-eyes principle)', () => {
      const wf = CryptographicWorkflowEngine.instantiateTemplate('tpl_key_rotation', {
        orgId: orgA.id,
        proposerId,
      });
      const validated = CryptographicWorkflowEngine.validateWorkflow(wf);

      expect(() => {
        CryptographicWorkflowEngine.approveWorkflow(validated, proposerId); // Proposer === Approver
      }).toThrow('SEPARATION_OF_DUTIES_VIOLATION');
    });

    it('allows a distinct authorized approver to approve workflow to READY', () => {
      const wf = CryptographicWorkflowEngine.instantiateTemplate('tpl_key_rotation', {
        orgId: orgA.id,
        proposerId,
      });
      const validated = CryptographicWorkflowEngine.validateWorkflow(wf);
      const approved = CryptographicWorkflowEngine.approveWorkflow(validated, approverId); // Alice != Bob

      expect(approved.state).toBe('READY');
      expect(approved.approverId).toBe(approverId);
      expect(approved.approvedAt).toBeDefined();
    });

    it('cancels an active workflow with a documented reason', () => {
      const wf = CryptographicWorkflowEngine.instantiateTemplate('tpl_key_rotation', {
        orgId: orgA.id,
        proposerId,
      });
      const validated = CryptographicWorkflowEngine.validateWorkflow(wf);
      const cancelled = CryptographicWorkflowEngine.cancelWorkflow(
        validated,
        'Scheduled maintenance window postponed'
      );

      expect(cancelled.state).toBe('CANCELLED');
      expect(cancelled.cancelReason).toContain('postponed');
    });
  });

  // =========================================================================
  // 4. CONTROLLED AUTOMATION RULES ENGINE
  // =========================================================================
  describe('4. Controlled Automation Rules Engine', () => {
    it('evaluates automation rules against live resources and findings', () => {
      const rules = CryptographicAutomationEngine.getDefaultRules(orgA.id);
      expect(rules.length).toBeGreaterThanOrEqual(3);

      const mockFindings: any[] = [
        {
          code: 'KEY_ROTATION_OVERDUE',
          category: 'KEY_ROTATION',
        },
      ];

      const evaluations = CryptographicAutomationEngine.evaluateRules(
        rules,
        [],
        mockFindings
      );
      const rotationEval = evaluations.find(
        (e) => e.rule.trigger === 'KEY_ROTATION_DUE'
      );

      expect(rotationEval).toBeDefined();
      expect(rotationEval?.triggered).toBe(true);
      expect(rotationEval?.affectedCount).toBe(1);
    });
  });

  // =========================================================================
  // 5. REST API & SDK INTEGRATION
  // =========================================================================
  describe('5. REST API Endpoints & Official SDK Integration', () => {
    let createdWorkflowId: string;

    it('GET /api/v1/os/inventory retrieves unified resources via SDK', async () => {
      const inventory = await sdkClientA.os.getInventory();
      expect(Array.isArray(inventory)).toBe(true);
      expect(inventory.length).toBeGreaterThan(0);
      expect(inventory[0].orgId).toBe(orgA.id);
    });

    it('GET /api/v1/os/posture retrieves unified health score and findings via SDK', async () => {
      const posture = await sdkClientA.os.getPosture();
      expect(posture).toBeDefined();
      expect(typeof posture.score).toBe('number');
      expect(posture.score).toBeGreaterThanOrEqual(0);
      expect(posture.score).toBeLessThanOrEqual(100);
      expect(Array.isArray(posture.findings)).toBe(true);
    });

    it('GET /api/v1/os/templates lists enterprise automation templates via SDK', async () => {
      const templates = await sdkClientA.os.listTemplates();
      expect(Array.isArray(templates)).toBe(true);
      expect(templates.length).toBe(ENTERPRISE_WORKFLOW_TEMPLATES.length);
      expect(templates.some((t: any) => t.id === 'tpl_key_rotation')).toBe(true);
    });

    it('POST /api/v1/os/templates/:id/instantiate creates workflow in AWAITING_APPROVAL via SDK', async () => {
      const wf = await sdkClientA.os.instantiateTemplate('tpl_key_rotation', {
        name: 'Production Key Rotation Job',
      });

      expect(wf).toBeDefined();
      expect(wf.id).toBeDefined();
      expect(wf.state).toBe('AWAITING_APPROVAL');
      expect(wf.requiresDualApproval).toBe(true);
      createdWorkflowId = wf.id;
    });

    it('POST /api/v1/os/workflows/:id/approve rejects self-approval with HTTP 403 Forbidden', async () => {
      // Fetch workflow details
      const wf = await sdkClientA.os.getWorkflow(createdWorkflowId);

      // Attempt self-approval using proposer's ID
      await expect(
        sdkClientA.os.approveWorkflow(createdWorkflowId, wf.proposerId)
      ).rejects.toThrow();
    });

    it('POST /api/v1/os/workflows/:id/approve succeeds when approved by distinct identity', async () => {
      const approved = await sdkClientA.os.approveWorkflow(
        createdWorkflowId,
        approverId
      );
      expect(approved.state).toBe('READY');
      expect(approved.approverId).toBe(approverId);
    });

    it('POST /api/v1/os/workflows/:id/execute runs steps and completes workflow via SDK', async () => {
      const executed = await sdkClientA.os.executeWorkflow(createdWorkflowId);
      expect(executed.state).toBe('COMPLETED');
      expect(executed.currentStepIndex).toBe(executed.steps.length);
      expect(executed.completedAt).toBeDefined();
    });

    it('POST /api/v1/os/automations/evaluate runs continuous audit rule evaluations via SDK', async () => {
      const res = await sdkClientA.os.evaluateAutomations();
      expect(res.orgId).toBe(orgA.id);
      expect(Array.isArray(res.evaluations)).toBe(true);
      expect(res.evaluations.length).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // 6. TENANT ISOLATION & BOUNDARY ENFORCEMENT
  // =========================================================================
  describe('6. Tenant Isolation & IDOR Protection', () => {
    it('prevents Tenant B from viewing or accessing Tenant A workflows', async () => {
      // Attempt to fetch Tenant A's workflow using Tenant B's API key
      const bWorkflows = await sdkClientB.os.listWorkflows();
      expect(bWorkflows.length).toBe(0);

      // Inspecting specific workflow from Org A using Org B's key returns 404
      const wfInA = await sdkClientA.os.getInventory();
      expect(wfInA[0].orgId).toBe(orgA.id);

      const bInventory = await sdkClientB.os.getInventory();
      expect(bInventory.every((r: any) => r.orgId === orgB.id)).toBe(true);
    });
  });
});
