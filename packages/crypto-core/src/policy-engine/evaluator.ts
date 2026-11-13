/**
 * AMARACUS Cryptographic Infrastructure — Cryptographic Policy Engine
 *
 * Centralized, deterministic, explainable, testable, and versioned evaluation engine.
 *
 * Enforces the strict 5-tier policy hierarchy:
 *  1. GLOBAL AMARACUS SAFETY POLICY (Mandatory security floor; can NEVER be weakened)
 *  2. ORGANIZATION POLICY
 *  3. PROJECT POLICY
 *  4. ENVIRONMENT POLICY
 *  5. OPERATION-SPECIFIC POLICY
 */

import {
  PolicyDecision,
  PolicyDecisionType,
  PolicyDocument,
  PolicyEvaluationContext,
  PolicyTraceStep,
  PolicyRule,
} from './types';
import { GLOBAL_AMARACUS_SAFETY_POLICY } from './global-baseline';
import { CryptographicRecommendationEngine } from './recommendation-engine';
import { registry } from '../registry';

export class CryptographicPolicyEngine {
  public static readonly VERSION = '15.0.0';

  /**
   * Deterministically evaluates a cryptographic request and context against the policy hierarchy.
   */
  public static evaluate(
    context: PolicyEvaluationContext,
    hierarchy: {
      organizationPolicy?: PolicyDocument | null;
      projectPolicy?: PolicyDocument | null;
      environmentPolicy?: PolicyDocument | null;
      operationPolicy?: PolicyDocument | null;
    } = {}
  ): PolicyDecision {
    const timestamp = new Date().toISOString();
    const trace: PolicyTraceStep[] = [];
    const reasons: string[] = [];
    const requirements: string[] = [];
    const warnings: string[] = [];
    const evaluatedPolicies: string[] = [GLOBAL_AMARACUS_SAFETY_POLICY.id];

    let currentDecision: PolicyDecisionType = 'ALLOW';

    // 1. EVALUATE TIER 1: GLOBAL AMARACUS SAFETY BASELINE (Highest Authority)
    const globalEval = this.evaluatePolicyDocument(
      GLOBAL_AMARACUS_SAFETY_POLICY,
      context,
      trace
    );
    if (!globalEval.allowed) {
      currentDecision = globalEval.decision;
      reasons.push(...globalEval.reasons);
      requirements.push(...globalEval.requirements);
      warnings.push(...globalEval.warnings);

      // Higher-level security restriction strictly terminates with DENY or REQUIRE_*
      const recommendations = CryptographicRecommendationEngine.generateRecommendations(context);
      return {
        decision: currentDecision,
        allowed: false,
        policyVersion: this.VERSION,
        reasons,
        requirements,
        warnings,
        recommendations,
        evaluatedPolicies,
        trace,
        timestamp,
      };
    }

    // 2. EVALUATE TIER 2: ORGANIZATION POLICY
    if (hierarchy.organizationPolicy && hierarchy.organizationPolicy.isActive !== false) {
      evaluatedPolicies.push(hierarchy.organizationPolicy.id);
      const orgEval = this.evaluatePolicyDocument(hierarchy.organizationPolicy, context, trace);
      if (!orgEval.allowed) {
        currentDecision = this.mergeDecisions(currentDecision, orgEval.decision);
        reasons.push(...orgEval.reasons);
        requirements.push(...orgEval.requirements);
        warnings.push(...orgEval.warnings);

        // If organization policy denies or requires change, lower policies cannot override it to ALLOW
        if (currentDecision !== 'ALLOW') {
          // Check if historical decryption is permitted under key rotation requirement
          if (currentDecision === 'REQUIRE_KEY_ROTATION' && context.isHistoricalDecryption) {
            warnings.push('[Historical Decryption] Permitted to decrypt historical data using aged key.');
          } else {
            const recommendations = CryptographicRecommendationEngine.generateRecommendations(context);
            return {
              decision: currentDecision,
              allowed: false,
              policyVersion: this.VERSION,
              reasons,
              requirements,
              warnings,
              recommendations,
              evaluatedPolicies,
              trace,
              timestamp,
            };
          }
        }
      } else {
        warnings.push(...orgEval.warnings);
      }
    }

    // 3. EVALUATE TIER 3: PROJECT POLICY
    if (hierarchy.projectPolicy && hierarchy.projectPolicy.isActive !== false) {
      evaluatedPolicies.push(hierarchy.projectPolicy.id);
      const projEval = this.evaluatePolicyDocument(hierarchy.projectPolicy, context, trace);
      if (!projEval.allowed) {
        currentDecision = this.mergeDecisions(currentDecision, projEval.decision);
        reasons.push(...projEval.reasons);
        requirements.push(...projEval.requirements);
        warnings.push(...projEval.warnings);

        if (currentDecision !== 'ALLOW') {
          if (currentDecision === 'REQUIRE_KEY_ROTATION' && context.isHistoricalDecryption) {
            warnings.push('[Historical Decryption] Permitted to decrypt historical data using aged key.');
          } else {
            const recommendations = CryptographicRecommendationEngine.generateRecommendations(context);
            return {
              decision: currentDecision,
              allowed: false,
              policyVersion: this.VERSION,
              reasons,
              requirements,
              warnings,
              recommendations,
              evaluatedPolicies,
              trace,
              timestamp,
            };
          }
        }
      } else {
        warnings.push(...projEval.warnings);
      }
    }

    // 4. EVALUATE TIER 4: ENVIRONMENT POLICY (e.g. Production vs Development)
    if (hierarchy.environmentPolicy && hierarchy.environmentPolicy.isActive !== false) {
      evaluatedPolicies.push(hierarchy.environmentPolicy.id);
      const envEval = this.evaluatePolicyDocument(hierarchy.environmentPolicy, context, trace);
      if (!envEval.allowed) {
        currentDecision = this.mergeDecisions(currentDecision, envEval.decision);
        reasons.push(...envEval.reasons);
        requirements.push(...envEval.requirements);
        warnings.push(...envEval.warnings);

        if (currentDecision !== 'ALLOW') {
          const recommendations = CryptographicRecommendationEngine.generateRecommendations(context);
          return {
            decision: currentDecision,
            allowed: false,
            policyVersion: this.VERSION,
            reasons,
            requirements,
            warnings,
            recommendations,
            evaluatedPolicies,
            trace,
            timestamp,
          };
        }
      } else {
        warnings.push(...envEval.warnings);
      }
    }

    // 5. EVALUATE TIER 5: OPERATION-SPECIFIC POLICY (e.g. request.policy === 'FIPS_COMPLIANT')
    if (hierarchy.operationPolicy && hierarchy.operationPolicy.isActive !== false) {
      evaluatedPolicies.push(hierarchy.operationPolicy.id);
      const opEval = this.evaluatePolicyDocument(hierarchy.operationPolicy, context, trace);
      if (!opEval.allowed) {
        currentDecision = this.mergeDecisions(currentDecision, opEval.decision);
        reasons.push(...opEval.reasons);
        requirements.push(...opEval.requirements);
        warnings.push(...opEval.warnings);
      } else {
        warnings.push(...opEval.warnings);
      }
    }

    // Generate explainable recommendations (which never block an ALLOW decision)
    const recommendations = CryptographicRecommendationEngine.generateRecommendations(context);

    const isAllowed = currentDecision === 'ALLOW' || (currentDecision === 'REQUIRE_KEY_ROTATION' && !!context.isHistoricalDecryption);

    return {
      decision: currentDecision,
      allowed: isAllowed,
      policyVersion: this.VERSION,
      reasons: reasons.length > 0 ? reasons : ['All cryptographic operations and parameters satisfy active policies.'],
      requirements,
      warnings,
      recommendations,
      evaluatedPolicies,
      trace,
      timestamp,
    };
  }

  /**
   * Evaluates a single policy document against the supplied context.
   */
  private static evaluatePolicyDocument(
    policy: PolicyDocument,
    context: PolicyEvaluationContext,
    trace: PolicyTraceStep[]
  ): {
    decision: PolicyDecisionType;
    allowed: boolean;
    reasons: string[];
    requirements: string[];
    warnings: string[];
  } {
    const reasons: string[] = [];
    const requirements: string[] = [];
    const warnings: string[] = [];
    let decision: PolicyDecisionType = 'ALLOW';

    const normalizedAlg = (context.algorithm || context.keyReference?.algorithm || '')
      .toUpperCase()
      .replace(/_/g, '-');

    for (const rule of (policy.rules || [])) {
      const cond: any = {
        ...(rule.condition || {}),
        ...rule,
      };
      if (cond.allowedAlgorithms && !cond.algorithms) {
        cond.algorithms = cond.allowedAlgorithms;
      }
      if (cond.minRsaKeyBits && !cond.minRsaBits) {
        cond.minRsaBits = cond.minRsaKeyBits;
      }
      if (cond.minEccKeyBits && !cond.minEccBits) {
        cond.minEccBits = cond.minEccKeyBits;
      }
      if (cond.requirePqc && !cond.pqcMode) {
        cond.pqcMode = 'PQC_REQUIRED';
      }

      // 1. Prohibited Algorithms
      if (normalizedAlg && cond.prohibitedAlgorithms && cond.prohibitedAlgorithms.length > 0) {
        const isProhibited = (cond.prohibitedAlgorithms as string[]).some((p: string) => {
          const upperP = p.toUpperCase().replace(/_/g, '-');
          return normalizedAlg === upperP || normalizedAlg.startsWith(`${upperP}-`);
        });

        if (isProhibited) {
          decision = 'DENY';
          const reason = `Algorithm '${normalizedAlg}' is prohibited by policy '${policy.name}' (${rule.id}). ${rule.remediation || ''}`.trim();
          reasons.push(reason);
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'DENY',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // 2. Whitelist / Allowed Algorithms
      if (normalizedAlg && cond.algorithms && cond.algorithms.length > 0) {
        const isAllowed = (cond.algorithms as string[]).some((a: string) => {
          const upperA = a.toUpperCase().replace(/_/g, '-');
          return normalizedAlg === upperA;
        });

        if (!isAllowed) {
          decision = 'DENY';
          const reason = `Algorithm '${normalizedAlg}' is not permitted by allowed algorithms list in policy '${policy.name}'.`;
          reasons.push(reason);
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'DENY',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // 3. Minimum Asymmetric / Symmetric Bit Lengths
      if (normalizedAlg) {
        if (cond.minRsaBits && normalizedAlg.startsWith('RSA-')) {
          const bitsMatch = normalizedAlg.match(/RSA-(\d+)/);
          const bits = bitsMatch ? parseInt(bitsMatch[1], 10) : 0;
          if (bits > 0 && bits < cond.minRsaBits) {
            decision = 'DENY';
            const reason = `RSA key length (${bits} bits) falls below mandatory policy minimum (${cond.minRsaBits} bits).`;
            reasons.push(reason);
            trace.push({
              level: policy.scope,
              policyId: policy.id,
              policyName: policy.name,
              ruleId: rule.id,
              decision: 'DENY',
              reason,
              timestamp: new Date().toISOString(),
            });
            continue;
          }
        }

        if (cond.minEccBits && (normalizedAlg.startsWith('ECDSA-') || normalizedAlg.startsWith('EC-'))) {
          const bitsMatch = normalizedAlg.match(/(?:ECDSA-P|EC-)(\d+)/);
          const bits = bitsMatch ? parseInt(bitsMatch[1], 10) : 0;
          if (bits > 0 && bits < cond.minEccBits) {
            decision = 'DENY';
            const reason = `ECC curve size (${bits} bits) falls below mandatory policy minimum (${cond.minEccBits} bits).`;
            reasons.push(reason);
            trace.push({
              level: policy.scope,
              policyId: policy.id,
              policyName: policy.name,
              ruleId: rule.id,
              decision: 'DENY',
              reason,
              timestamp: new Date().toISOString(),
            });
            continue;
          }
        }
      }

      // 4. Key Status Checks (Inactive, Disabled, Destroyed, Revoked)
      if (context.keyReference) {
        const keyStatus = (context.keyReference.status || 'ACTIVE').toUpperCase();
        // Same rules as KeyLifecycleValidator: disabled/deprecated keys may still decrypt and
        // verify existing data, revoked keys may only verify, destroyed/suspended keys nothing
        const op = String(context.operationType || '').toUpperCase();
        const readsExistingData = ['DECRYPT', 'VERIFY', 'PQC_VERIFY', 'HMAC_VERIFY', 'KEM_DECAPSULATE'].includes(op);
        const denied =
          ['SUSPENDED', 'DESTROYED'].includes(keyStatus) ||
          (keyStatus === 'REVOKED' && !['VERIFY', 'PQC_VERIFY'].includes(op)) ||
          (['DISABLED', 'DEPRECATED'].includes(keyStatus) && !readsExistingData);
        if (denied) {
          decision = 'DENY';
          const reason = `Key '${context.keyReference.id}' lifecycle status is '${keyStatus}'; '${op || 'this operation'}' is not permitted.`;
          reasons.push(reason);
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'DENY',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // 5. Key Rotation & Maximum Age Policy
      if (cond.maxKeyAgeDays !== undefined && context.keyAgeDays !== undefined) {
        if (context.keyAgeDays > cond.maxKeyAgeDays) {
          decision = 'REQUIRE_KEY_ROTATION';
          const reason = `Key exceeds configured maximum age (${context.keyAgeDays} days > ${cond.maxKeyAgeDays} days max). Key rotation is required.`;
          reasons.push(reason);
          requirements.push('Rotate key to a newly generated active key version before executing new operations.');
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'REQUIRE_KEY_ROTATION',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // 6. Hardware-Backed / HSM Policy
      if (cond.requireHardwareBacked && context.keyReference) {
        if (!context.keyReference.isHsmBacked) {
          decision = 'REQUIRE_APPROVED_PROVIDER';
          const reason = `Policy '${policy.name}' mandates hardware-backed (Cloud HSM) keys, but key '${context.keyReference.id}' is software-backed.`;
          reasons.push(reason);
          requirements.push('Configure and route operation through Azure Managed HSM or customer-managed HSM vault.');
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'REQUIRE_APPROVED_PROVIDER',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // 7. Post-Quantum Cryptography (PQC) Policy
      if (cond.pqcMode === 'PQC_REQUIRED' && normalizedAlg) {
        const isPqc =
          normalizedAlg.startsWith('ML-KEM-') ||
          normalizedAlg.startsWith('ML-DSA-') ||
          normalizedAlg.startsWith('X25519+ML-KEM-') ||
          normalizedAlg.includes('HYBRID');

        const isAsymmetric =
          normalizedAlg.startsWith('RSA-') ||
          normalizedAlg.startsWith('ECDSA-') ||
          normalizedAlg === 'ED25519' ||
          normalizedAlg === 'X25519';

        if (!isPqc && isAsymmetric) {
          decision = 'REQUIRE_STRONGER_ALGORITHM';
          const reason = `Policy '${policy.name}' mandates Post-Quantum Cryptography (PQC_REQUIRED), but algorithm '${normalizedAlg}' is classical.`;
          reasons.push(reason);
          requirements.push('Select ML-KEM for key exchange or ML-DSA / Hybrid for digital signatures.');
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'REQUIRE_STRONGER_ALGORITHM',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // 8. BYOK / Customer Vault Isolation Policy
      if (cond.requireCustomerVault && context.keyReference) {
        if (!context.keyReference.isCustomerManaged) {
          decision = 'DENY';
          const reason = `Policy '${policy.name}' mandates customer-managed vault keys (BYOK), but key '${context.keyReference.id}' is AMARACUS-managed.`;
          reasons.push(reason);
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'DENY',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // 9. Deprecated Algorithm Blocking
      if (cond.blockDeprecated && normalizedAlg) {
        const isDeprecated = ['MD5', 'SHA-1', 'DES', '3DES', 'RC4', 'RSA-1024'].some((d) =>
          normalizedAlg.includes(d)
        );
        if (isDeprecated) {
          decision = 'DENY';
          const reason = `Deprecated algorithm '${normalizedAlg}' is blocked by policy '${policy.name}'.`;
          reasons.push(reason);
          trace.push({
            level: policy.scope,
            policyId: policy.id,
            policyName: policy.name,
            ruleId: rule.id,
            decision: 'DENY',
            reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }
      }

      // Rule Passed
      trace.push({
        level: policy.scope,
        policyId: policy.id,
        policyName: policy.name,
        ruleId: rule.id,
        decision: 'ALLOW',
        reason: `Complied with rule '${rule.name}'.`,
        timestamp: new Date().toISOString(),
      });
    }

    return {
      decision,
      allowed: decision === 'ALLOW',
      reasons,
      requirements,
      warnings,
    };
  }

  /**
   * Merges decision types enforcing non-weakening precedence:
   * DENY > REQUIRE_* > ALLOW
   */
  private static mergeDecisions(
    current: PolicyDecisionType,
    incoming: PolicyDecisionType
  ): PolicyDecisionType {
    if (current === 'DENY' || incoming === 'DENY') return 'DENY';
    if (incoming.startsWith('REQUIRE_')) return incoming;
    if (current.startsWith('REQUIRE_')) return current;
    return 'ALLOW';
  }
}
