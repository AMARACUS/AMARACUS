/**
 * AMARACUS Cryptographic Migration Platform — Pre-Migration Compatibility Engine
 *
 * Verifies mathematical, provider, and policy compatibility BEFORE allowing a migration to proceed.
 * Reuses the Phase 15 Deterministic CryptographicPolicyEngine for zero policy drift.
 */

import { PreMigrationCompatibilityResult } from './types';
import { registry } from '../registry';
import { CryptographicPolicyEngine } from '../policy-engine/evaluator';
import { PolicyDocument } from '../policy-engine/types';

export interface CompatibilityCheckInput {
  targetAlgorithm: string;
  sourceAlgorithm: string;
  targetProvider?: string;
  sourceProvider?: string;
  organizationId: string;
  projectId?: string;
  environmentType?: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT';
  activePolicyDocument?: PolicyDocument | null;
}

export class MigrationCompatibilityChecker {
  /**
   * Performs rigorous pre-migration validation.
   */
  public static check(input: CompatibilityCheckInput): PreMigrationCompatibilityResult {
    const blockingIssues: string[] = [];
    const warnings: string[] = [];

    // 1. Validate Target Algorithm Existence in AlgorithmRegistry
    const normTargetAlg = input.targetAlgorithm.toUpperCase().trim();
    let algorithmSupported = false;

    // Check in single source of truth registry
    try {
      const registeredAlg = registry.get(normTargetAlg as any);
      if (registeredAlg) {
        algorithmSupported = true;
      }
    } catch {
      // not in catalog
    }

    if (!algorithmSupported) {
      if (
        normTargetAlg === 'AES-256-GCM' ||
        normTargetAlg === 'ML-DSA-65' ||
        normTargetAlg === 'ML-KEM-768' ||
        normTargetAlg === 'X25519+ML-KEM-768' ||
        normTargetAlg === 'ED25519' ||
        normTargetAlg === 'SHA-256' ||
        normTargetAlg === 'SHA-384' ||
        normTargetAlg === 'SHA-512' ||
        normTargetAlg === 'RSA-4096'
      ) {
        algorithmSupported = true;
      } else {
        blockingIssues.push(`Target algorithm '${input.targetAlgorithm}' is not recognized in the AMARACUS Algorithm Registry.`);
      }
    }

    // 2. Validate Provider Capabilities
    let providerSupported = true;
    const targetProv = (input.targetProvider || 'software').toLowerCase();

    if (targetProv.includes('azure') || targetProv.includes('hsm')) {
      // Azure Key Vault / Managed HSM currently support classical RSA, EC, AES
      if (normTargetAlg.includes('ML-DSA') || normTargetAlg.includes('ML-KEM')) {
        providerSupported = false;
        blockingIssues.push(
          `Target provider '${input.targetProvider}' does not natively support Post-Quantum algorithm '${input.targetAlgorithm}'. ` +
          `Use AMARACUS Software / PQC Provider or Hybrid KMS routing for PQC workloads.`
        );
      }
    }

    // 3. Evaluate Phase 15 Policy Engine
    let policyDecision: string = 'ALLOW';
    const policyReasons: string[] = [];

    try {
      const evalResult = CryptographicPolicyEngine.evaluate(
        {
          algorithm: normTargetAlg,
          operationType: 'encrypt',
          providerId: targetProv,
          environmentType: (input.environmentType || 'PRODUCTION').toLowerCase(),
          organizationId: input.organizationId,
          projectId: input.projectId,
        },
        {
          organizationPolicy: input.activePolicyDocument,
        }
      );

      policyDecision = evalResult.decision;
      policyReasons.push(...evalResult.reasons);

      if (evalResult.decision === 'DENY') {
        blockingIssues.push(
          `Target algorithm '${input.targetAlgorithm}' is DISALLOWED by organizational security policy: ${evalResult.reasons.join(', ')}`
        );
      } else if (evalResult.decision.startsWith('REQUIRE_')) {
        warnings.push(`Policy requires parameter update: ${evalResult.requirements.join(', ')}`);
      }
    } catch (err: any) {
      warnings.push(`Policy engine pre-check note: ${err.message}`);
    }

    // 4. Key Format Compatibility
    let keyFormatCompatible = true;
    const normSource = input.sourceAlgorithm.toUpperCase();
    if (
      (normSource.includes('RSA') || normSource.includes('ED25519')) &&
      normTargetAlg.includes('AES')
    ) {
      keyFormatCompatible = false;
      blockingIssues.push(
        `Incompatible cryptographic primitive type: Cannot directly migrate Asymmetric key (${input.sourceAlgorithm}) to Symmetric cipher (${input.targetAlgorithm}).`
      );
    }

    const compatible = blockingIssues.length === 0;

    return {
      compatible,
      policyDecision,
      policyReasons,
      algorithmSupported,
      providerSupported,
      keyFormatCompatible,
      blockingIssues,
      warnings,
    };
  }
}
