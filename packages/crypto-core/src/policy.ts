import { AlgorithmId, CryptoOperation } from './types';
import { registry } from './registry';
import { CryptoEngineError } from './errors';

export type SecurityClass =
  | 'CLASSICAL_ONLY'
  | 'PQC_ONLY'
  | 'HYBRID_REQUIRED'
  | 'PQC_PREFERRED'
  | 'CLASSICAL_ALLOWED'
  | 'PERMISSIVE';

export interface CryptoPolicy {
  name: string;
  description?: string;
  requiredSecurityClass?: SecurityClass;
  allowedAlgorithms: AlgorithmId[];
  minSymmetricKeyBits: number;
  allowExperimental: boolean;
  requireAead: boolean;
  blockDeprecatedAlgorithms?: boolean;
}

export const CRYPTO_POLICIES: Record<string, CryptoPolicy> = {
  'DEFAULT_SECURE': {
    name: 'Default Production Security',
    description: 'Standard enterprise policy with classical and post-quantum algorithms permitted.',
    requiredSecurityClass: 'CLASSICAL_ALLOWED',
    allowedAlgorithms: [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      'AES-256-GCM',
      'ED25519',
      'X25519',
    ],
    minSymmetricKeyBits: 256,
    allowExperimental: false,
    requireAead: true,
    blockDeprecatedAlgorithms: true,
  },
  'PQC_ONLY': {
    name: 'Post-Quantum Exclusivity',
    description: 'Enforces pure NIST-standardized Post-Quantum Cryptography (FIPS 203 & FIPS 204). Classical asymmetric primitives are prohibited.',
    requiredSecurityClass: 'PQC_ONLY',
    allowedAlgorithms: [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      'AES-256-GCM',
      'ML-KEM-512',
      'ML-KEM-768',
      'ML-KEM-1024',
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
    ],
    minSymmetricKeyBits: 256,
    allowExperimental: false,
    requireAead: true,
    blockDeprecatedAlgorithms: true,
  },
  'HYBRID_REQUIRED': {
    name: 'Hybrid Key Exchange Mandate',
    description: 'Mandates hybrid post-quantum key exchange (X25519 + ML-KEM-768) to protect against Store-Now-Decrypt-Later threats while retaining classical assurance.',
    requiredSecurityClass: 'HYBRID_REQUIRED',
    allowedAlgorithms: [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      'AES-256-GCM',
      'ED25519',
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
      'X25519+ML-KEM-768',
    ],
    minSymmetricKeyBits: 256,
    allowExperimental: false,
    requireAead: true,
    blockDeprecatedAlgorithms: true,
  },
  'PQC_PREFERRED': {
    name: 'Post-Quantum Preferred',
    description: 'Permits classical primitives while prioritizing and encouraging PQC primitives across all domains.',
    requiredSecurityClass: 'PQC_PREFERRED',
    allowedAlgorithms: [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      'AES-256-GCM',
      'ED25519',
      'X25519',
      'ML-KEM-512',
      'ML-KEM-768',
      'ML-KEM-1024',
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
      'X25519+ML-KEM-768',
    ],
    minSymmetricKeyBits: 256,
    allowExperimental: false,
    requireAead: true,
    blockDeprecatedAlgorithms: true,
  },
  'CLASSICAL_ONLY': {
    name: 'Legacy Classical Only',
    description: 'Permits only pre-quantum classical cryptographic primitives. PQC primitives are rejected.',
    requiredSecurityClass: 'CLASSICAL_ONLY',
    allowedAlgorithms: [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      'AES-256-GCM',
      'ED25519',
      'X25519',
    ],
    minSymmetricKeyBits: 256,
    allowExperimental: false,
    requireAead: true,
    blockDeprecatedAlgorithms: true,
  },
  'FIPS_COMPLIANT': {
    name: 'FIPS Validated Profile',
    description: 'Enforces algorithms specified in NIST FIPS 140-3, FIPS 197, FIPS 198-1, FIPS 202, FIPS 203, and FIPS 204.',
    requiredSecurityClass: 'CLASSICAL_ALLOWED',
    allowedAlgorithms: [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      'AES-256-GCM',
      'ML-KEM-512',
      'ML-KEM-768',
      'ML-KEM-1024',
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
    ],
    minSymmetricKeyBits: 256,
    allowExperimental: false,
    requireAead: true,
    blockDeprecatedAlgorithms: true,
  },
  'PERMISSIVE_DEV': {
    name: 'Developer Sandbox (All Supported)',
    description: 'Allows all registered cryptographic algorithms for development and testing.',
    requiredSecurityClass: 'PERMISSIVE',
    allowedAlgorithms: [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      'AES-256-GCM',
      'ED25519',
      'X25519',
      'ML-KEM-512',
      'ML-KEM-768',
      'ML-KEM-1024',
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
      'X25519+ML-KEM-768',
    ],
    minSymmetricKeyBits: 128,
    allowExperimental: true,
    requireAead: false,
    blockDeprecatedAlgorithms: false,
  },
};

export class CryptoPolicyEngine {
  public static validateOperation(
    policyName = 'DEFAULT_SECURE',
    algorithm: AlgorithmId,
    operation: CryptoOperation
  ): void {
    const policy = CRYPTO_POLICIES[policyName] || CRYPTO_POLICIES['DEFAULT_SECURE'];
    const meta = registry.validate(algorithm, operation);
    // Compare policies against the canonical ID ('HMAC-SHA256' -> 'HMAC-SHA-256')
    algorithm = meta.id;

    // 1. Allowed algorithms check
    if (!policy.allowedAlgorithms.includes(algorithm)) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `Algorithm '${algorithm}' is prohibited under active cryptographic policy '${policy.name}'.`,
        403,
        { policy: policy.name, algorithm, allowed: policy.allowedAlgorithms }
      );
    }

    // 2. Algorithm lifecycle status enforcement
    if (meta.status === 'DISABLED' || meta.status === 'UNSUPPORTED') {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `Algorithm '${algorithm}' has status '${meta.status}' and cannot be used.`,
        403
      );
    }

    if (policy.blockDeprecatedAlgorithms && meta.status === 'DEPRECATED') {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `Deprecated algorithm '${algorithm}' is blocked under policy '${policy.name}'.`,
        403
      );
    }

    // 3. Experimental enforcement
    if (!policy.allowExperimental && (meta.securityStatus === 'experimental' || meta.status === 'EXPERIMENTAL')) {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `Experimental algorithm '${algorithm}' is not permitted under policy '${policy.name}'.`,
        403
      );
    }

    // 4. Security class enforcement
    if (policy.requiredSecurityClass === 'PQC_ONLY') {
      const isPqc = meta.category === 'PQC_KEM' || meta.category === 'PQC_SIG';
      const isSymmetricSafe = meta.category === 'AEAD' || meta.category === 'HASH' || meta.category === 'MAC';
      if (!isPqc && !isSymmetricSafe) {
        throw new CryptoEngineError(
          'POLICY_VIOLATION',
          `Policy '${policy.name}' strictly mandates Post-Quantum Cryptography (ML-KEM or ML-DSA). Classical algorithm '${algorithm}' is rejected.`,
          403,
          { policy: policy.name, algorithm, requiredSecurityClass: policy.requiredSecurityClass }
        );
      }
    }

    if (policy.requiredSecurityClass === 'HYBRID_REQUIRED') {
      const isKeyExchange = operation === 'key_agreement' || operation === 'kem_encapsulate' || operation === 'hybrid_encapsulate';
      if (isKeyExchange && meta.category !== 'HYBRID_KEM') {
        throw new CryptoEngineError(
          'POLICY_VIOLATION',
          `Policy '${policy.name}' mandates Hybrid Key Encapsulation (X25519+ML-KEM-768). Algorithm '${algorithm}' is rejected for key exchange.`,
          403,
          { policy: policy.name, algorithm, requiredSecurityClass: policy.requiredSecurityClass }
        );
      }
    }

    if (policy.requiredSecurityClass === 'CLASSICAL_ONLY') {
      const isPqcOrHybrid = meta.category === 'PQC_KEM' || meta.category === 'PQC_SIG' || meta.category === 'HYBRID_KEM';
      if (isPqcOrHybrid) {
        throw new CryptoEngineError(
          'POLICY_VIOLATION',
          `Policy '${policy.name}' allows classical algorithms only. Post-quantum algorithm '${algorithm}' is rejected.`,
          403,
          { policy: policy.name, algorithm, requiredSecurityClass: policy.requiredSecurityClass }
        );
      }
    }

    // 5. Symmetric AEAD requirement
    if (operation === 'encrypt' && policy.requireAead && meta.category !== 'AEAD') {
      throw new CryptoEngineError(
        'POLICY_VIOLATION',
        `Policy '${policy.name}' requires Authenticated Encryption with Associated Data (AEAD).`,
        403
      );
    }
  }

  /**
   * Validate certificate issuance parameters against cryptographic policy
   */
  validateCertificateIssuance(params: {
    certificateType: string;
    keyAlgorithm: string;
    validityDays?: number;
    san?: { dns?: string[]; ip?: string[]; uri?: string[]; email?: string[] };
    policyName?: string;
  }): void {
    const keyAlg = params.keyAlgorithm.toUpperCase();

    // 1. Truthful PQC gating: reject non-standardized PQC X.509 certificates
    if (keyAlg.startsWith('ML-DSA') || keyAlg.startsWith('ML-KEM') || keyAlg.includes('HYBRID')) {
      throw new CryptoEngineError(
        'UNSUPPORTED_PQC_X509',
        `Standard X.509 certificates for post-quantum algorithm '${params.keyAlgorithm}' are pending IETF LAMPS standardization (draft-ietf-lamps-dilithium-certificates). AMARACUS strictly refuses to generate non-standard proprietary X.509 formats.`,
        400
      );
    }

    // 2. Minimum RSA key length: 2048 bits
    if (keyAlg.startsWith('RSA')) {
      if (keyAlg.includes('1024') || keyAlg.includes('512')) {
        throw new CryptoEngineError(
          'POLICY_VIOLATION',
          `RSA key length below 2048 bits is prohibited for certificate issuance.`,
          403
        );
      }
    }

    // 3. Maximum validity lifetime
    const validity = params.validityDays || 397;
    if (params.certificateType === 'SERVER' || params.certificateType === 'CLIENT' || params.certificateType === 'CODE_SIGNING') {
      if (validity > 825) {
        throw new CryptoEngineError(
          'POLICY_VIOLATION',
          `Certificate validity period of ${validity} days exceeds the maximum policy limit of 825 days for end-entity certificates.`,
          403
        );
      }
    } else if (params.certificateType === 'INTERMEDIATE_CA') {
      if (validity > 3650) {
        throw new CryptoEngineError(
          'POLICY_VIOLATION',
          `Intermediate CA validity period of ${validity} days exceeds the maximum policy limit of 10 years (3650 days).`,
          403
        );
      }
    } else if (params.certificateType === 'ROOT_CA') {
      if (validity > 7300) {
        throw new CryptoEngineError(
          'POLICY_VIOLATION',
          `Root CA validity period of ${validity} days exceeds the maximum policy limit of 20 years (7300 days).`,
          403
        );
      }
    }
  }
}

