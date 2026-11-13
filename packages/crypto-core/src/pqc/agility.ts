import { AlgorithmId, CryptoOperation } from '../types';
import { registry } from '../registry';
import { CRYPTO_POLICIES } from '../policy';
import { CryptoEngineError } from '../errors';

export interface AgilitySelectionCriteria {
  operation: 'key_encapsulation' | 'digital_signature' | 'key_agreement' | 'symmetric_encryption';
  policy?: string;
  minSecurityLevel?: number;
  preferQuantumResistant?: boolean;
  preferHybrid?: boolean;
}

export interface MigrationAdvice {
  currentAlgorithm: AlgorithmId;
  status: string;
  isDeprecated: boolean;
  recommendedReplacement: AlgorithmId;
  migrationReason: string;
}

export class CryptoAgilityEngine {
  /**
   * Selects the most appropriate cryptographic algorithm based on intent, policy, and security requirements.
   * Enables application code to avoid hardcoding specific cryptographic primitives.
   */
  public static selectAlgorithm(criteria: AgilitySelectionCriteria): AlgorithmId {
    const policyName = criteria.policy || 'DEFAULT_SECURE';
    const policy = CRYPTO_POLICIES[policyName] || CRYPTO_POLICIES['DEFAULT_SECURE'];

    if (criteria.operation === 'key_encapsulation') {
      if (policy.requiredSecurityClass === 'HYBRID_REQUIRED' || criteria.preferHybrid) {
        if (policy.allowedAlgorithms.includes('X25519+ML-KEM-768')) {
          return 'X25519+ML-KEM-768';
        }
      }
      if (criteria.minSecurityLevel && criteria.minSecurityLevel >= 5) {
        if (policy.allowedAlgorithms.includes('ML-KEM-1024')) return 'ML-KEM-1024';
      }
      if (policy.allowedAlgorithms.includes('ML-KEM-768')) {
        return 'ML-KEM-768';
      }
      if (policy.allowedAlgorithms.includes('ML-KEM-512')) {
        return 'ML-KEM-512';
      }
      throw new CryptoEngineError(
        'UNSUPPORTED_ALGORITHM',
        `No supported Key Encapsulation Mechanism available under active policy '${policy.name}'.`,
        400
      );
    }

    if (criteria.operation === 'digital_signature') {
      if (policy.requiredSecurityClass === 'PQC_ONLY' || criteria.preferQuantumResistant) {
        if (criteria.minSecurityLevel && criteria.minSecurityLevel >= 5) {
          if (policy.allowedAlgorithms.includes('ML-DSA-87')) return 'ML-DSA-87';
        }
        if (policy.allowedAlgorithms.includes('ML-DSA-65')) return 'ML-DSA-65';
        if (policy.allowedAlgorithms.includes('ML-DSA-44')) return 'ML-DSA-44';
      }
      // Classical fallback if permitted
      if (policy.allowedAlgorithms.includes('ED25519')) {
        return 'ED25519';
      }
      if (policy.allowedAlgorithms.includes('ML-DSA-65')) {
        return 'ML-DSA-65';
      }
      throw new CryptoEngineError(
        'UNSUPPORTED_ALGORITHM',
        `No supported Digital Signature algorithm available under active policy '${policy.name}'.`,
        400
      );
    }

    if (criteria.operation === 'key_agreement') {
      if (policy.allowedAlgorithms.includes('X25519')) return 'X25519';
      throw new CryptoEngineError(
        'UNSUPPORTED_ALGORITHM',
        `No supported Key Agreement algorithm available under active policy '${policy.name}'.`,
        400
      );
    }

    if (criteria.operation === 'symmetric_encryption') {
      if (policy.allowedAlgorithms.includes('AES-256-GCM')) return 'AES-256-GCM';
      throw new CryptoEngineError(
        'UNSUPPORTED_ALGORITHM',
        `No supported Symmetric Encryption algorithm available under active policy '${policy.name}'.`,
        400
      );
    }

    throw new CryptoEngineError('INVALID_INPUT', `Unknown operation '${criteria.operation}' for algorithm selection.`);
  }

  /**
   * Assesses cryptographic obsolescence and returns migration paths for aging algorithms.
   */
  public static getMigrationAdvice(algorithm: AlgorithmId): MigrationAdvice {
    const meta = registry.get(algorithm);

    if (algorithm === 'ED25519') {
      return {
        currentAlgorithm: algorithm,
        status: meta.status,
        isDeprecated: false,
        recommendedReplacement: 'ML-DSA-65',
        migrationReason: 'Ed25519 is classically secure but vulnerable to Shor algorithm on quantum computers. Prepare migration to NIST FIPS 204 ML-DSA.',
      };
    }

    if (algorithm === 'X25519') {
      return {
        currentAlgorithm: algorithm,
        status: meta.status,
        isDeprecated: false,
        recommendedReplacement: 'X25519+ML-KEM-768',
        migrationReason: 'X25519 is vulnerable to Store-Now-Decrypt-Later quantum threats. Migrate to X25519+ML-KEM-768 hybrid key encapsulation.',
      };
    }

    return {
      currentAlgorithm: algorithm,
      status: meta.status,
      isDeprecated: meta.status === 'DEPRECATED',
      recommendedReplacement: algorithm,
      migrationReason: 'Current algorithm is within modern security baselines.',
    };
  }

  public selectAlgorithm(criteria: AgilitySelectionCriteria): AlgorithmId {
    return CryptoAgilityEngine.selectAlgorithm(criteria);
  }

  public getMigrationAdvice(algorithm: AlgorithmId): MigrationAdvice {
    return CryptoAgilityEngine.getMigrationAdvice(algorithm);
  }
}

export const cryptoAgilityEngine = new CryptoAgilityEngine();
