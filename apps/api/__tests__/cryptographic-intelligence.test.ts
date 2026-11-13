/**
 * @file apps/api/__tests__/cryptographic-intelligence.test.ts
 * Comprehensive Test Suite for Phase 21: AMARACUS Cryptographic Intelligence & Autonomous Optimization
 */

import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { Amaracus } from '@amaracus/sdk';
import {
  EvidenceAnalyzer,
  RecommendationEngine,
  ImpactAnalyzer,
  EvidenceSnapshot,
  OptimizationRecommendation,
} from '@amaracus/crypto-core';
import { cryptoIntelligenceService } from '../src/lib/crypto-intelligence-service';

describe('Phase 21 — AMARACUS Cryptographic Intelligence & Autonomous Optimization', () => {
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

  // User identities for separation of duties (Four-Eyes Principle)
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
      name: 'Cyber Corp Intelligence Org',
      slug: `cyber-intel-${Date.now()}`,
    });
    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Core Production Systems',
      slug: 'core-prod',
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
      name: 'Intelligence Admin Key',
      prefix: keyResultA.prefix,
      keyHash: keyResultA.keyHash,
      scopes: [
        'intelligence:recommendations',
        'intelligence:optimize',
        'intelligence:analyze',
        'intelligence:remediate',
        'os:read',
        'os:write',
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
        'intelligence:recommendations',
        'intelligence:optimize',
        'intelligence:analyze',
      ],
      env: 'live',
    });
    apiKeyBLive = keyResultB.fullKey;

    // 4. Initialize TypeScript SDK clients
    sdkClientA = new Amaracus({
      apiKey: apiKeyALive,
      baseUrl: `${baseUrl}/api/v1`,
      environment: 'live',
    });

    sdkClientB = new Amaracus({
      apiKey: apiKeyBLive,
      baseUrl: `${baseUrl}/api/v1`,
      environment: 'live',
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  describe('1. Evidence Gathering & Normalization', () => {
    it('normalizes telemetry into verified evidence references with confidence levels', () => {
      const now = new Date().toISOString();
      const snapshot: EvidenceSnapshot = {
        orgId: orgA.id,
        keys: [
          {
            id: 'key-leg-1',
            name: 'legacy-data-key',
            orgId: orgA.id,
            algorithm: '3DES',
            provider: 'azure_key_vault',
            status: 'ACTIVE',
            createdAt: new Date(Date.now() - 120 * 86400000).toISOString(),
            lastRotatedAt: new Date(Date.now() - 120 * 86400000).toISOString(),
            rotationIntervalDays: 90,
          },
        ],
        certificates: [
          {
            id: 'cert-1',
            commonName: 'gateway.internal',
            orgId: orgA.id,
            status: 'ACTIVE',
            notBefore: new Date(Date.now() - 300 * 86400000).toISOString(),
            notAfter: new Date(Date.now() + 5 * 86400000).toISOString(), // 5 days left
            algorithm: 'RSA-2048',
          },
        ],
        circuitBreakers: [
          {
            providerId: 'akv-us-east',
            providerType: 'azure_key_vault',
            state: 'OPEN',
            failuresCount: 6,
            averageLatencyMs: 420,
          },
        ],
        policyLogs: [
          {
            id: 'log-1',
            policyId: 'pol-fips-140',
            policyName: 'FIPS Mandate',
            orgId: orgA.id,
            operationType: 'ENCRYPT',
            algorithmRequested: 'RC4',
            verdict: 'DENY',
            timestamp: now,
          },
          {
            id: 'log-2',
            policyId: 'pol-fips-140',
            policyName: 'FIPS Mandate',
            orgId: orgA.id,
            operationType: 'ENCRYPT',
            algorithmRequested: 'RC4',
            verdict: 'DENY',
            timestamp: now,
          },
          {
            id: 'log-3',
            policyId: 'pol-fips-140',
            policyName: 'FIPS Mandate',
            orgId: orgA.id,
            operationType: 'ENCRYPT',
            algorithmRequested: 'RC4',
            verdict: 'DENY',
            timestamp: now,
          },
          {
            id: 'log-4',
            policyId: 'pol-fips-140',
            policyName: 'FIPS Mandate',
            orgId: orgA.id,
            operationType: 'ENCRYPT',
            algorithmRequested: 'RC4',
            verdict: 'DENY',
            timestamp: now,
          },
          {
            id: 'log-5',
            policyId: 'pol-fips-140',
            policyName: 'FIPS Mandate',
            orgId: orgA.id,
            operationType: 'ENCRYPT',
            algorithmRequested: 'RC4',
            verdict: 'DENY',
            timestamp: now,
          },
        ],
        usage: [
          {
            orgId: orgA.id,
            periodStart: new Date(Date.now() - 30 * 86400000).toISOString(),
            periodEnd: now,
            totalOperations: 1000,
            failedOperations: 60, // 6% failure rate
            activeKeys: 1,
            billedCostUsd: 15.0,
            estimatedCostUsd: 15.0,
          },
        ],
      };

      const evidence = EvidenceAnalyzer.extractEvidence(snapshot);
      expect(evidence.length).toBeGreaterThanOrEqual(5);

      const keyAge = evidence.find((e) => e.metricOrFact === 'KEY_AGE_DAYS');
      expect(keyAge).toBeDefined();
      expect(keyAge?.observedValue).toBe(120);
      expect(keyAge?.confidence).toBe('VERIFIED_FACT');
      expect(keyAge?.isEstimate).toBe(false);

      const certExpiry = evidence.find((e) => e.metricOrFact === 'DAYS_UNTIL_EXPIRATION');
      expect(certExpiry).toBeDefined();
      expect(certExpiry?.observedValue).toBeLessThanOrEqual(5);

      const cbState = evidence.find((e) => e.metricOrFact === 'CIRCUIT_STATE');
      expect(cbState?.observedValue).toBe('OPEN');
    });

    it('distinguishes actual billed cost from estimated cost without fabricating data', () => {
      const snapshot: EvidenceSnapshot = {
        orgId: orgA.id,
        usage: [
          {
            orgId: orgA.id,
            periodStart: '2026-09-01T00:00:00.000Z',
            periodEnd: '2026-09-30T23:59:59.000Z',
            totalOperations: 5000,
            failedOperations: 0,
            activeKeys: 2,
            billedCostUsd: 49.5,
            estimatedCostUsd: 55.0,
          },
        ],
      };

      const evidence = EvidenceAnalyzer.extractEvidence(snapshot);
      const billed = evidence.find((e) => e.metricOrFact === 'BILLED_COST_USD');
      const estimated = evidence.find((e) => e.metricOrFact === 'ESTIMATED_COST_USD');

      expect(billed?.isEstimate).toBe(false);
      expect(billed?.confidence).toBe('VERIFIED_FACT');
      expect(estimated?.isEstimate).toBe(true);
      expect(estimated?.confidence).toBe('ESTIMATE');
    });
  });

  describe('2. Recommendation Engine & Prioritization Scoring', () => {
    it('detects deprecated algorithm and generates an explainable security recommendation', () => {
      const snapshot: EvidenceSnapshot = {
        orgId: orgA.id,
        keys: [
          {
            id: 'key-3des',
            name: 'payment-legacy-key',
            orgId: orgA.id,
            algorithm: '3DES',
            provider: 'azure_key_vault',
            status: 'ACTIVE',
            createdAt: new Date().toISOString(),
          },
        ],
      };

      const recommendations = RecommendationEngine.generateRecommendations(snapshot);
      const rec = recommendations.find((r) => r.category === 'SECURITY_RISK');

      expect(rec).toBeDefined();
      expect(rec?.severity).toBe('CRITICAL');
      expect(rec?.title).toContain('3DES');
      expect(rec?.explanation.observedFacts.length).toBeGreaterThan(0);
      expect(rec?.proposedAction.type).toBe('PLAN_MIGRATION');
      expect(rec?.proposedAction.requiresFourEyes).toBe(true);
    });

    it('calculates deterministic priority scores between 0 and 100', () => {
      const criticalScore = RecommendationEngine.calculatePriorityScore('CRITICAL', 3, 'VERIFIED_FACT', true);
      const lowScore = RecommendationEngine.calculatePriorityScore('LOW', 1, 'ESTIMATE', false);

      expect(criticalScore).toBeGreaterThan(70);
      expect(criticalScore).toBeLessThanOrEqual(100);
      expect(lowScore).toBeLessThan(criticalScore);
      expect(lowScore).toBeGreaterThanOrEqual(0);
    });

    it('deduplicates observations pointing to the same root cause', () => {
      const snapshot: EvidenceSnapshot = {
        orgId: orgA.id,
        keys: [
          {
            id: 'key-rot-1',
            name: 'dek-single',
            orgId: orgA.id,
            algorithm: 'AES-256-GCM',
            provider: 'azure_key_vault',
            status: 'ACTIVE',
            createdAt: new Date(Date.now() - 100 * 86400000).toISOString(),
            rotationIntervalDays: 90,
          },
        ],
      };

      const recommendations = RecommendationEngine.generateRecommendations(snapshot);
      const rotRecs = recommendations.filter((r) => r.category === 'KEY_LIFECYCLE');
      expect(rotRecs.length).toBe(1);
    });
  });

  describe('3. Non-Destructive Dry-Run Impact Simulation', () => {
    it('evaluates policy consequences, compatibility risks, and reversibility without mutating state', () => {
      const testRec: OptimizationRecommendation = {
        id: 'rec-test-rot',
        orgId: orgA.id,
        category: 'KEY_LIFECYCLE',
        severity: 'MEDIUM',
        priorityScore: 60,
        title: 'Key Rotation Recommendation',
        explanation: {
          summary: 'Rotation due',
          observedFacts: ['Age: 95 days'],
          technicalRisk: 'Cryptoperiod exhaustion',
          businessImpact: 'Audit finding',
          remediationSteps: ['Rotate key version'],
        },
        evidence: [
          {
            source: 'KEY_METADATA',
            resourceId: 'key-test',
            metricOrFact: 'ALGORITHM_CONFIGURED',
            observedValue: 'AES-256-GCM',
            timestamp: new Date().toISOString(),
            isEstimate: false,
            confidence: 'VERIFIED_FACT',
          },
        ],
        affectedResources: [{ id: 'key-test', type: 'KEY', name: 'test-dek' }],
        expectedBenefit: 'Renewed cryptoperiod',
        risks: ['None'],
        preconditions: ['Provider reachable'],
        proposedAction: {
          type: 'ROTATE_KEY',
          targetResourceId: 'key-test',
          targetResourceType: 'KEY',
          isAutomated: false,
          requiresApproval: true,
          requiresFourEyes: true,
        },
        requiredPermissions: ['keys:rotate'],
        verificationProcedure: 'Verify version active',
        status: 'DETECTED',
        deduplicationKey: 'KEY_LIFECYCLE:key-test:ROTATION_DUE',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      const dryRun = ImpactAnalyzer.analyze(testRec);

      expect(dryRun.recommendationId).toBe('rec-test-rot');
      expect(dryRun.affectedResourcesCount).toBe(1);
      expect(dryRun.potentialDowntime).toBe('NONE');
      expect(dryRun.reversibility).toBe('FULLY_REVERSIBLE');
      expect(dryRun.requiredApprovals).toContain('FOUR_EYES_SECOND_PARTY_APPROVAL');
      expect(dryRun.estimatedResourceConsumption.isEstimated).toBe(true);
    });
  });

  describe('4. REST API & Lifecycle State Transitions', () => {
    let recommendationId: string;

    it('GET /api/v1/intelligence/recommendations lists recommendations for Tenant A', async () => {
      const res = await sdkClientA.intelligence.getRecommendations();
      expect(Array.isArray(res)).toBe(true);
      expect(res.length).toBeGreaterThan(0);

      const first = res[0];
      recommendationId = first.id;
      expect(first.status).toBe('DETECTED');
      expect(first.explanation.summary).toBeDefined();
    });

    it('GET /api/v1/intelligence/recommendations/:id retrieves recommendation details', async () => {
      const rec = await sdkClientA.intelligence.getRecommendation(recommendationId);
      expect(rec.id).toBe(recommendationId);
      expect(rec.evidence.length).toBeGreaterThan(0);
    });

    it('POST /api/v1/intelligence/recommendations/:id/dry-run conducts on-demand dry run', async () => {
      const dryRun = await sdkClientA.intelligence.dryRunRecommendation(recommendationId);
      expect(dryRun.recommendationId).toBe(recommendationId);
      expect(dryRun.reversibility).toBeDefined();
    });

    it('POST /api/v1/intelligence/recommendations/:id/accept transitions recommendation to ACCEPTED', async () => {
      const updated = await sdkClientA.intelligence.acceptRecommendation(recommendationId, {
        reason: 'Approved for scheduled maintenance by security officer Alice',
      });

      expect(['ACCEPTED', 'COMPLETED']).toContain(updated.status);
      expect(updated.userFeedback?.decision).toBe('ACCEPT');
    });

    it('POST /api/v1/intelligence/recommendations/:id/reject records rejection rationale', async () => {
      // Create and reject another recommendation
      const recs = await sdkClientA.intelligence.getRecommendations();
      const detected = recs.find((r) => r.status === 'DETECTED');
      if (detected) {
        const rejected = await sdkClientA.intelligence.rejectRecommendation(detected.id, {
          reason: 'Legacy workload scheduled for decommissioning next week',
        });
        expect(rejected.status).toBe('REJECTED');
        expect(rejected.userFeedback?.decision).toBe('REJECT');
      }
    });

    it('POST /api/v1/intelligence/recommendations/:id/dismiss marks non-actionable item as DISMISSED', async () => {
      const recs = await sdkClientA.intelligence.getRecommendations();
      const available = recs.find((r) => r.status === 'DETECTED' || r.status === 'ACCEPTED');
      if (available) {
        const dismissed = await sdkClientA.intelligence.dismissRecommendation(available.id, {
          reason: 'Known test fixture in staging environment',
        });
        expect(dismissed.status).toBe('DISMISSED');
      }
    });
  });

  describe('5. Four-Eyes Principle & Safety Enforcement', () => {
    it('blocks self-execution when proposer attempts to execute their own high-impact recommendation', async () => {
      // Seed a fresh recommendation requiring four-eyes
      const recs = await sdkClientA.intelligence.getRecommendations();
      const candidate = recs.find((r) => r.proposedAction.requiresFourEyes);

      if (candidate) {
        // Accept with user Alice
        await cryptoIntelligenceService.acceptRecommendation(orgA.id, candidate.id, { reason: 'Alice accepted' }, proposerId);

        // Attempt execution with the SAME user Alice -> MUST be rejected
        await expect(
          cryptoIntelligenceService.executeRecommendation(orgA.id, candidate.id, proposerId)
        ).rejects.toThrow(/Four-eyes separation of duties violation/);
      }
    });

    it('permits execution by a distinct second-party approver', async () => {
      const recs = await sdkClientA.intelligence.getRecommendations();
      const candidate = recs.find((r) => r.status === 'ACCEPTED' && r.proposedAction.requiresFourEyes);

      if (candidate) {
        // Execute with distinct user Bob -> MUST succeed
        const executed = await cryptoIntelligenceService.executeRecommendation(orgA.id, candidate.id, approverId);
        expect(executed.status).toBe('COMPLETED');
      }
    });
  });

  describe('6. Tenant Isolation (Multi-Tenancy Integrity)', () => {
    it('prevents Tenant B from viewing or accessing Tenant A recommendations', async () => {
      const recsA = await sdkClientA.intelligence.getRecommendations();
      expect(recsA.length).toBeGreaterThan(0);
      const recIdA = recsA[0].id;

      // Tenant B requests Tenant A's recommendation ID
      await expect(
        sdkClientB.intelligence.getRecommendation(recIdA)
      ).rejects.toThrow();
    });

    it('prevents Tenant B from modifying or accepting Tenant A recommendations', async () => {
      const recsA = await sdkClientA.intelligence.getRecommendations();
      const recIdA = recsA[0].id;

      await expect(
        sdkClientB.intelligence.acceptRecommendation(recIdA, { reason: 'Unauthorized cross-tenant attempt' })
      ).rejects.toThrow();
    });
  });

  describe('7. Optimization Alias in SDK', () => {
    it('verifies client.optimization is an alias of client.intelligence', async () => {
      expect(sdkClientA.optimization).toBeDefined();
      expect(sdkClientA.optimization.getRecommendations).toBe(sdkClientA.intelligence.getRecommendations);

      const recs = await sdkClientA.optimization.getRecommendations();
      expect(Array.isArray(recs)).toBe(true);
    });
  });
});
