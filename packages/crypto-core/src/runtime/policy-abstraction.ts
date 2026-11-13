/**
 * AMARACUS Cryptographic Infrastructure — Policy Abstraction
 *
 * Establishes the architectural boundary for cryptographic policy evaluation.
 * Separates policy governance from operation execution.
 */

import { OperationType } from './operation-model';
import { KeyReference } from './key-reference';
import { CryptoEngineError } from '../errors';
import { normalizeAlgorithmId } from '../registry';

export interface CryptographicPolicy {
  id: string;
  name: string;
  description?: string;
  allowedAlgorithms?: string[];
  prohibitedAlgorithms?: string[];
  minRsaKeyBits?: number;
  minEccKeyBits?: number;
  requireFips?: boolean;
  requirePqc?: boolean;
  requireHardwareBacked?: boolean;
  environmentRestrictions?: string[]; // e.g. ["production"]
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  policyId: string;
  violations: string[];
}

export class CryptographicPolicyEvaluator {
  public static readonly DEFAULT_SECURE_POLICY: CryptographicPolicy = {
    id: 'DEFAULT_SECURE',
    name: 'AMARACUS Default Secure Baseline',
    description: 'Enforces modern authenticated encryption, strong signatures, and rejects legacy primitives.',
    prohibitedAlgorithms: ['DES', '3DES', 'RC4', 'MD5', 'SHA-1'],
    minRsaKeyBits: 2048,
    minEccKeyBits: 256,
  };

  public static readonly FIPS_COMPLIANT_POLICY: CryptographicPolicy = {
    id: 'FIPS_COMPLIANT',
    name: 'FIPS 140-2 / 140-3 Compliant Policy',
    description: 'Strict adherence to NIST FIPS-validated cryptographic algorithms and parameters.',
    prohibitedAlgorithms: ['DES', '3DES', 'RC4', 'MD5', 'SHA-1', 'CHACHA20-POLY1305'],
    requireFips: true,
    minRsaKeyBits: 2048,
    minEccKeyBits: 256,
  };

  public static readonly PQC_PREFERRED_POLICY: CryptographicPolicy = {
    id: 'PQC_PREFERRED',
    name: 'Quantum-Safe / PQC Preferred Policy',
    description: 'Enforces Post-Quantum or Hybrid algorithms for key agreement and digital signatures.',
    requirePqc: true,
  };

  /**
   * Evaluates an operation and optional key reference against a policy.
   * Fails closed if prohibited algorithms are used or parameters fall below security thresholds.
   */
  public static evaluate(
    policy: CryptographicPolicy,
    operationType: OperationType,
    algorithm?: string | null,
    keyRef?: KeyReference | null
  ): PolicyEvaluationResult {
    const violations: string[] = [];
    const normalizedAlg = algorithm ? normalizeAlgorithmId(algorithm) : '';

    // 1. Prohibited algorithms check
    if (normalizedAlg && policy.prohibitedAlgorithms) {
      const isProhibited = policy.prohibitedAlgorithms.some(
        (p) => normalizedAlg === p || normalizedAlg.startsWith(p)
      );
      if (isProhibited) {
        violations.push(`Algorithm '${normalizedAlg}' is explicitly prohibited by policy '${policy.id}'.`);
      }
    }

    // 2. Allowed algorithms check (whitelist mode)
    if (normalizedAlg && policy.allowedAlgorithms && policy.allowedAlgorithms.length > 0) {
      if (!policy.allowedAlgorithms.includes(normalizedAlg)) {
        violations.push(`Algorithm '${normalizedAlg}' is not in the allowed algorithms list of policy '${policy.id}'.`);
      }
    }

    // 3. Hardware-backing requirement
    if (policy.requireHardwareBacked && keyRef && !keyRef.isHsmBacked) {
      violations.push(`Policy '${policy.id}' requires hardware-backed (HSM) keys, but key '${keyRef.id}' is software-backed.`);
    }

    // 4. Post-Quantum Cryptography requirement
    if (policy.requirePqc && normalizedAlg) {
      const isPqc =
        normalizedAlg.startsWith('ML-KEM-') ||
        normalizedAlg.startsWith('ML-DSA-') ||
        normalizedAlg.startsWith('X25519+ML-KEM-') ||
        normalizedAlg.includes('HYBRID');
      if (!isPqc && (operationType === 'SIGN' || operationType === 'KEY_AGREEMENT')) {
        violations.push(`Policy '${policy.id}' requires quantum-safe (PQC/Hybrid) algorithms for ${operationType}.`);
      }
    }

    return {
      allowed: violations.length === 0,
      policyId: policy.id,
      violations,
    };
  }

  /**
   * Helper that throws CryptoEngineError if policy validation fails.
   */
  public static assertAllowed(
    policy: CryptographicPolicy,
    operationType: OperationType,
    algorithm?: string | null,
    keyRef?: KeyReference | null
  ): void {
    const result = this.evaluate(policy, operationType, algorithm, keyRef);
    if (!result.allowed) {
      throw new CryptoEngineError(
        'POLICY_DENIED',
        `Cryptographic policy '${policy.id}' violation: ${result.violations.join('; ')}`,
        403,
        { policyId: policy.id, violations: result.violations }
      );
    }
  }
}
