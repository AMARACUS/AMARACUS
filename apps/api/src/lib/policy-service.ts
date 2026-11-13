/**
 * AMARACUS Cryptographic Infrastructure — Policy Service
 *
 * Coordinates database persistence, multi-tier hierarchy resolution,
 * safe tenant-aware caching with invalidation, deterministic policy evaluation,
 * dry-run evaluation, and policy simulation.
 */

import {
  CryptographicPolicyEngine,
  PolicyDocument,
  PolicyDecision,
  PolicyEvaluationContext,
  PolicySimulationImpact,
  PolicyRule,
} from '@amaracus/crypto-core';
import { db, CryptographicPolicyRecord } from './data-store';
import { policyObservability } from './policy-observability';

interface CachedHierarchy {
  orgPolicy: PolicyDocument | null;
  projectPolicies: Map<string, PolicyDocument>;
  envPolicies: Map<string, PolicyDocument>;
  cachedAt: number;
}

export class PolicyService {
  // Tenant-aware cache: organizationId -> CachedHierarchy
  private cache: Map<string, CachedHierarchy> = new Map();
  private readonly CACHE_TTL_MS = 60000; // 60-second TTL

  /**
   * Deterministically evaluates a cryptographic operation request within tenant hierarchy.
   */
  public async evaluate(
    context: PolicyEvaluationContext,
    operationPolicyName?: string | null
  ): Promise<PolicyDecision> {
    const startTime = process.hrtime.bigint();

    try {
      const hierarchy = await this.resolveEffectiveHierarchy(
        context.organizationId,
        context.projectId,
        context.environmentId,
        operationPolicyName || context.complianceProfile
      );

      const decision = CryptographicPolicyEngine.evaluate(context, hierarchy);

      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1_000_000;

      policyObservability.recordEvaluation(decision.decision, durationMs, decision.reasons);

      return decision;
    } catch (err: any) {
      // SECTION 23 FAIL-SAFE:
      // Policy service failures fail closed on security-critical operations.
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1_000_000;
      policyObservability.recordEvaluation('DENY', durationMs, [err.message]);

      return {
        decision: 'DENY',
        allowed: false,
        policyVersion: CryptographicPolicyEngine.VERSION,
        reasons: [`Policy evaluation failure (fail-closed): ${err.message}`],
        requirements: ['Ensure policy service is reachable and configuration is valid.'],
        warnings: [],
        recommendations: [],
        evaluatedPolicies: ['FAIL_SAFE_HANDLER'],
        trace: [
          {
            level: 'GLOBAL',
            policyId: 'FAIL_SAFE',
            policyName: 'Fail-Safe Boundary',
            decision: 'DENY',
            reason: err.message,
            timestamp: new Date().toISOString(),
          },
        ],
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Resolves active policy hierarchy for an organization and optional project/environment.
   */
  public async resolveEffectiveHierarchy(
    organizationId: string,
    projectId?: string | null,
    environmentId?: string | null,
    operationPolicyName?: string | null
  ): Promise<{
    organizationPolicy?: PolicyDocument | null;
    projectPolicy?: PolicyDocument | null;
    environmentPolicy?: PolicyDocument | null;
    operationPolicy?: PolicyDocument | null;
  }> {
    let cached = this.cache.get(organizationId);
    const now = Date.now();

    if (!cached || now - cached.cachedAt > this.CACHE_TTL_MS) {
      policyObservability.recordCacheMiss();
      cached = await this.buildTenantHierarchy(organizationId);
      this.cache.set(organizationId, cached);
    } else {
      policyObservability.recordCacheHit();
    }

    const orgPolicy = cached.orgPolicy;
    const projectPolicy = projectId ? cached.projectPolicies.get(projectId) || null : null;
    const environmentPolicy = environmentId ? cached.envPolicies.get(environmentId) || null : null;

    let operationPolicy: PolicyDocument | null = null;
    if (operationPolicyName) {
      operationPolicy = this.mapPredefinedPolicy(operationPolicyName);
    }

    return {
      organizationPolicy: orgPolicy,
      projectPolicy,
      environmentPolicy,
      operationPolicy,
    };
  }

  /**
   * Simulates a proposed policy against tenant keys, certificates, and operations
   * WITHOUT executing cryptography or modifying state.
   */
  public async simulatePolicy(
    organizationId: string,
    proposedPolicy: {
      name: string;
      rules: PolicyRule[];
      scope?: string;
    }
  ): Promise<PolicySimulationImpact> {
    const proposedDoc: PolicyDocument = {
      id: 'SIMULATED_POLICY',
      name: proposedPolicy.name,
      version: 'simulated',
      scope: (proposedPolicy.scope as any) || 'ORGANIZATION',
      scopeId: organizationId,
      rules: proposedPolicy.rules,
      isActive: true,
      enforcementMode: 'ENFORCE',
    };

    const affectedKeys: Array<{ id: string; name: string; algorithm: string; reason: string }> = [];
    const affectedCertificates: Array<{ id: string; subject: string; algorithm: string; reason: string }> = [];
    const affectedOperationsSet = new Set<string>();
    const affectedProjectsSet = new Set<string>();

    let totalEvaluated = 0;
    let wouldAllow = 0;
    let wouldDeny = 0;
    let wouldRequireChange = 0;

    // 1. Evaluate against tenant keys
    const keys = await db.listKeys({ organizationId });
    for (const key of keys) {
      totalEvaluated++;
      const keyAgeDays = key.createdAt
        ? Math.floor((Date.now() - new Date(key.createdAt).getTime()) / (1000 * 60 * 60 * 24))
        : 0;

      const evalResult = CryptographicPolicyEngine.evaluate(
        {
          organizationId,
          projectId: key.projectId,
          environmentId: key.environmentId,
          operationType: 'ENCRYPT',
          algorithm: key.algorithm,
          keyId: key.id,
          keyAgeDays,
          keyReference: {
            id: key.id,
            name: key.name,
            organizationId,
            algorithm: key.algorithm,
            purpose: key.purpose,
            provider: key.provider,
            providerKeyId: key.id,
            currentVersion: key.currentVersion,
            status: key.status,
            isHsmBacked: key.provider === 'AZURE_MANAGED_HSM',
            isCustomerManaged: key.provider?.startsWith('CUSTOMER_') || false,
          },
        },
        { organizationPolicy: proposedDoc }
      );

      if (evalResult.decision === 'ALLOW') {
        wouldAllow++;
      } else if (evalResult.decision === 'DENY') {
        wouldDeny++;
        affectedKeys.push({
          id: key.id,
          name: key.name,
          algorithm: key.algorithm,
          reason: evalResult.reasons.join('; '),
        });
        if (key.projectId) affectedProjectsSet.add(key.projectId);
      } else {
        wouldRequireChange++;
        affectedKeys.push({
          id: key.id,
          name: key.name,
          algorithm: key.algorithm,
          reason: evalResult.reasons.join('; '),
        });
        if (key.projectId) affectedProjectsSet.add(key.projectId);
      }
    }

    // 2. Evaluate sample standard operations
    const standardOperations = [
      { type: 'ENCRYPT', algorithm: 'AES-256-GCM' },
      { type: 'ENCRYPT', algorithm: 'AES-128-GCM' },
      { type: 'SIGN', algorithm: 'ED25519' },
      { type: 'SIGN', algorithm: 'RSA-2048' },
      { type: 'SIGN', algorithm: 'RSA-1024' },
      { type: 'SIGN', algorithm: 'ML-DSA-65' },
      { type: 'HASH', algorithm: 'SHA-256' },
      { type: 'HASH', algorithm: 'MD5' },
      { type: 'KEY_AGREEMENT', algorithm: 'X25519+ML-KEM-768' },
    ];

    for (const op of standardOperations) {
      const opEval = CryptographicPolicyEngine.evaluate(
        {
          organizationId,
          operationType: op.type,
          algorithm: op.algorithm,
        },
        { organizationPolicy: proposedDoc }
      );

      if (!opEval.allowed) {
        affectedOperationsSet.add(`${op.type}:${op.algorithm}`);
      }
    }

    const impacts: any[] = affectedKeys.map((k) => ({
      assetId: k.id,
      assetType: 'KEY' as const,
      algorithm: k.algorithm,
      compliant: false,
      previousDecision: 'ALLOW' as const,
      simulatedDecision: 'DENY' as const,
      violations: [k.reason],
      recommendations: [],
    }));

    return {
      affectedKeys,
      affectedCertificates,
      affectedOperations: Array.from(affectedOperationsSet),
      affectedProjects: Array.from(affectedProjectsSet),
      summary: {
        totalEvaluated,
        wouldAllow,
        wouldDeny,
        wouldRequireChange,
        compliantCount: wouldAllow,
        nonCompliantCount: wouldDeny + wouldRequireChange,
        breakageCount: wouldDeny,
      },
      impacts,
      conflicts: [],
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Invalidates tenant cache when policies or assignments are created/updated/deleted.
   */
  public invalidateTenantCache(organizationId: string): void {
    this.cache.delete(organizationId);
  }

  /**
   * Builds the full hierarchy object from database records for caching.
   */
  private async buildTenantHierarchy(organizationId: string): Promise<CachedHierarchy> {
    const policies = await db.listPolicies(organizationId);
    const assignments = await db.listPolicyAssignments(organizationId);

    const policyMap = new Map<string, PolicyDocument>();
    for (const pol of policies) {
      if (!pol.isActive) continue;
      policyMap.set(pol.id, this.recordToDocument(pol));
    }

    let orgPolicy: PolicyDocument | null = null;
    const projectPolicies = new Map<string, PolicyDocument>();
    const envPolicies = new Map<string, PolicyDocument>();

    for (const assign of assignments) {
      const doc = policyMap.get(assign.policyId);
      if (!doc) continue;

      if (assign.scopeType === 'ORGANIZATION') {
        orgPolicy = doc;
      } else if (assign.scopeType === 'PROJECT') {
        projectPolicies.set(assign.scopeId, doc);
      } else if (assign.scopeType === 'ENVIRONMENT') {
        envPolicies.set(assign.scopeId, doc);
      }
    }

    // Default to the first active policy if no assignment exists yet
    if (!orgPolicy && policies.length > 0) {
      const defaultActive = policies.find((p) => p.isActive);
      if (defaultActive) {
        orgPolicy = this.recordToDocument(defaultActive);
      }
    }

    return {
      orgPolicy,
      projectPolicies,
      envPolicies,
      cachedAt: Date.now(),
    };
  }

  private recordToDocument(record: CryptographicPolicyRecord): PolicyDocument {
    return {
      id: record.id,
      name: record.name,
      version: String(record.currentVersion),
      description: record.description || undefined,
      scope: 'ORGANIZATION',
      scopeId: record.organizationId,
      rules: Array.isArray(record.rules) ? record.rules : [],
      isActive: record.isActive,
      enforcementMode: (record.enforcementMode as any) || 'ENFORCE',
      metadata: record.metadata,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  private mapPredefinedPolicy(name: string): PolicyDocument | null {
    const upper = name.toUpperCase();
    if (upper === 'FIPS_COMPLIANT') {
      return {
        id: 'FIPS_COMPLIANT_PROFILE',
        name: 'FIPS-Approved Algorithms Only (not a FIPS 140-3 validation)',
        version: '1.0.0',
        scope: 'OPERATION',
        rules: [
          {
            id: 'FIPS_BLOCK_NON_APPROVED',
            category: 'ALGORITHM_POLICY',
            name: 'Require FIPS-Approved Cryptography',
            effect: 'DENY',
            condition: {
              prohibitedAlgorithms: ['CHACHA20-POLY1305', 'MD5', 'SHA-1', 'DES', '3DES', 'RC4'],
              minRsaBits: 2048,
              minEccBits: 256,
              requireFips: true,
            },
          },
        ],
      };
    }

    if (upper === 'PQC_PREFERRED' || upper === 'PQC_REQUIRED') {
      return {
        id: 'PQC_PROFILE',
        name: 'Post-Quantum Cryptography Policy Profile',
        version: '1.0.0',
        scope: 'OPERATION',
        rules: [
          {
            id: 'PQC_ENFORCE',
            category: 'PQC_POLICY',
            name: 'Require or Prefer Post-Quantum Primitives',
            effect: upper === 'PQC_REQUIRED' ? 'REQUIRE' : 'ALLOW',
            condition: {
              pqcMode: upper === 'PQC_REQUIRED' ? 'PQC_REQUIRED' : 'PQC_PREFERRED',
            },
          },
        ],
      };
    }

    return null;
  }
}

export const policyService = new PolicyService();
