import crypto from 'crypto';
import { CryptoMigrationPlanItem, MigrationStatus } from './types';
import { AlgorithmId, CryptoOperation } from '../types';
import { CRYPTO_POLICIES } from '../policy';

export interface MigrationRecommendation {
  currentAlgorithm: string;
  recommendedAlgorithm: string;
  strategy: 'DIRECT_REPLACEMENT' | 'HYBRID_DUAL_RUN' | 'PHASED_ROTATION';
  rationale: string;
  interoperabilityNotes: string;
  standardReference: string;
}

export class CryptoMigrationEngine {
  /**
   * Recommend replacement algorithm based on cryptographic operation, current algorithm, and context.
   */
  static getMigrationRecommendation(currentAlgo: string, operation?: string): MigrationRecommendation {
    const norm = (currentAlgo || '').toUpperCase().trim();

    // 1. Digital Signatures (RSA, ECDSA, Ed25519)
    if (norm.includes('RSA') || norm.includes('ECDSA') || norm.includes('ED25519')) {
      return {
        currentAlgorithm: currentAlgo,
        recommendedAlgorithm: 'ML-DSA-65',
        strategy: 'HYBRID_DUAL_RUN',
        rationale: 'ML-DSA-65 (NIST FIPS 204) provides NIST Security Level 3 post-quantum digital signature security based on Module Learning With Errors.',
        interoperabilityNotes: 'Dual-signature / hybrid X.509 or composite signatures are recommended during transition to ensure backward compatibility with legacy TLS clients.',
        standardReference: 'NIST FIPS 204 / IETF draft-ietf-lamps-pq-composite-sigs',
      };
    }

    // 2. Key Exchange / Key Encapsulation (ECDH, X25519, RSA-OAEP)
    if (norm.includes('ECDH') || norm.includes('X25519') || norm.includes('DIFFIE-HELLMAN') || norm.includes('OAEP')) {
      return {
        currentAlgorithm: currentAlgo,
        recommendedAlgorithm: 'X25519+ML-KEM-768',
        strategy: 'HYBRID_DUAL_RUN',
        rationale: 'Combines classical X25519 with post-quantum ML-KEM-768 (NIST FIPS 203) using a HKDF dual-combiner. Guarantees protection against Store-Now-Decrypt-Later (SNDL) attacks.',
        interoperabilityNotes: 'Supported by modern OpenSSL 3.5, BoringSSL, and cloud KMS providers. Low performance overhead.',
        standardReference: 'NIST FIPS 203 / IETF RFC 9180',
      };
    }

    // 3. Broken Hashing / Insecure MAC (MD5, SHA-1)
    if (norm.includes('MD5') || norm.includes('SHA-1')) {
      return {
        currentAlgorithm: currentAlgo,
        recommendedAlgorithm: 'SHA-256',
        strategy: 'DIRECT_REPLACEMENT',
        rationale: 'Upgrade from broken legacy hash to NIST standard SHA-256 (FIPS 180-4) with 256 bits of collision resistance.',
        interoperabilityNotes: 'Universally supported across all programming languages, platforms, and cryptographic libraries.',
        standardReference: 'NIST FIPS 180-4',
      };
    }

    // 4. Symmetric Ciphers with Short Keys (AES-128, 3DES, DES)
    if (norm.includes('DES') || (norm.includes('AES') && norm.includes('128'))) {
      return {
        currentAlgorithm: currentAlgo,
        recommendedAlgorithm: 'AES-256-GCM',
        strategy: 'DIRECT_REPLACEMENT',
        rationale: 'Upgrades symmetric encryption to 256-bit key length with authenticated encryption (AEAD). Retains >=128 bits post-quantum security under Grover bounds.',
        interoperabilityNotes: 'Standard hardware-accelerated AES-NI instruction support on all modern CPUs.',
        standardReference: 'NIST FIPS 197 / NIST SP 800-38D',
      };
    }

    return {
      currentAlgorithm: currentAlgo,
      recommendedAlgorithm: 'AES-256-GCM',
      strategy: 'PHASED_ROTATION',
      rationale: 'Default enterprise high-security replacement.',
      interoperabilityNotes: 'Verify consuming application requirements before rotation.',
      standardReference: 'NIST SP 800-57',
    };
  }

  /**
   * Policy-driven algorithm selection:
   * Decouples applications from hardcoded algorithms by resolving the optimal algorithm
   * for a requested operation under the organization's active policy.
   */
  static selectAlgorithmForOperation(
    operation: CryptoOperation | 'signature' | 'key_exchange' | 'encryption' | 'hash',
    policyName: string = 'DEFAULT_SECURE'
  ): AlgorithmId {
    const policy = CRYPTO_POLICIES[policyName] || CRYPTO_POLICIES['DEFAULT_SECURE'];

    if (operation === 'signature' || operation === 'sign' || operation === 'pqc_sign') {
      if (policy.requiredSecurityClass === 'PQC_ONLY') {
        return 'ML-DSA-65';
      }
      if (policy.allowedAlgorithms.includes('ML-DSA-65')) {
        return 'ML-DSA-65';
      }
      return 'ED25519';
    }

    if (operation === 'key_exchange' || operation === 'key_agreement' || operation === 'kem_encapsulate') {
      if (policy.requiredSecurityClass === 'PQC_ONLY') {
        return 'ML-KEM-768';
      }
      if (policy.requiredSecurityClass === 'HYBRID_REQUIRED') {
        return 'X25519+ML-KEM-768';
      }
      return 'X25519';
    }

    if (operation === 'encryption' || operation === 'encrypt') {
      return 'AES-256-GCM';
    }

    if (operation === 'hash') {
      return 'SHA-256';
    }

    return 'AES-256-GCM';
  }

  /**
   * Helper to construct a validated CryptoMigrationPlanItem.
   */
  static createMigrationPlan(params: {
    organizationId: string;
    name: string;
    description?: string;
    affectedAssetIds: string[];
    currentAlgorithm: string;
    targetAlgorithm?: string;
    migrationStrategy?: 'DIRECT_REPLACEMENT' | 'HYBRID_DUAL_RUN' | 'PHASED_ROTATION';
    owner?: string;
    environmentId?: string;
  }): CryptoMigrationPlanItem {
    const rec = this.getMigrationRecommendation(params.currentAlgorithm);
    const targetAlgorithm = params.targetAlgorithm || rec.recommendedAlgorithm;
    const migrationStrategy = params.migrationStrategy || rec.strategy;
    const now = new Date();
    const id = `plan_${crypto.randomUUID()}`;

    return {
      id,
      organizationId: params.organizationId,
      name: params.name,
      description: params.description || `Migration from ${params.currentAlgorithm} to ${targetAlgorithm}`,
      affectedAssetIds: params.affectedAssetIds,
      currentAlgorithm: params.currentAlgorithm,
      targetAlgorithm,
      migrationStrategy,
      dependencies: ['Key Provider Readiness', 'Client Compatibility Audit'],
      blockers: [],
      owner: params.owner || null,
      environmentId: params.environmentId || null,
      status: 'IDENTIFIED',
      validationRequirements: ['Validate in Staging environment', 'Verify ciphertext/signature interoperability'],
      metadata: {
        recommendationRationale: rec.rationale,
        standardReference: rec.standardReference,
      },
      createdAt: now,
      updatedAt: now,
    };
  }
}

export { CryptoMigrationEngine as CryptoIntelligenceAgility };
