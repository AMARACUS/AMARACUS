import { AlgorithmId, AlgorithmMetadata, AlgorithmCategory, CryptoOperation, AlgorithmStatus, PqcSecurityLevel } from './types';
import { CryptoEngineError } from './errors';

export const ALGORITHM_CATALOG: Record<AlgorithmId, AlgorithmMetadata> = {
  // --- HASHING ---
  'SHA-256': {
    id: 'SHA-256',
    displayName: 'SHA-256 Secure Hash Algorithm',
    family: 'SHA-2',
    category: 'HASH',
    primitiveType: 'digest',
    supportedOperations: ['hash'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-180-4',
    digestSizeBits: 256,
    provider: 'node-crypto',
    description: 'NIST standard cryptographic hash producing a 256-bit (32-byte) digest. Highly collision-resistant.',
    standardReference: 'NIST FIPS 180-4',
  },
  'SHA-384': {
    id: 'SHA-384',
    displayName: 'SHA-384 Secure Hash Algorithm',
    family: 'SHA-2',
    category: 'HASH',
    primitiveType: 'digest',
    supportedOperations: ['hash'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-180-4',
    digestSizeBits: 384,
    provider: 'node-crypto',
    description: 'NIST standard cryptographic hash producing a 384-bit (48-byte) digest. Suitable for high-security environments.',
    standardReference: 'NIST FIPS 180-4',
  },
  'SHA-512': {
    id: 'SHA-512',
    displayName: 'SHA-512 Secure Hash Algorithm',
    family: 'SHA-2',
    category: 'HASH',
    primitiveType: 'digest',
    supportedOperations: ['hash'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-180-4',
    digestSizeBits: 512,
    provider: 'node-crypto',
    description: 'NIST standard cryptographic hash producing a 512-bit (64-byte) digest with maximum classical security margin.',
    standardReference: 'NIST FIPS 180-4',
  },
  'SHA3-256': {
    id: 'SHA3-256',
    displayName: 'SHA3-256 Keccak Permutation Hash',
    family: 'SHA-3',
    category: 'HASH',
    primitiveType: 'digest',
    supportedOperations: ['hash'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-202',
    digestSizeBits: 256,
    provider: 'node-crypto',
    description: 'NIST FIPS 202 Keccak sponge construction offering algorithmic diversity from SHA-2.',
    standardReference: 'NIST FIPS 202',
  },
  'SHA3-384': {
    id: 'SHA3-384',
    displayName: 'SHA3-384 Keccak Permutation Hash',
    family: 'SHA-3',
    category: 'HASH',
    primitiveType: 'digest',
    supportedOperations: ['hash'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-202',
    digestSizeBits: 384,
    provider: 'node-crypto',
    description: 'NIST FIPS 202 384-bit sponge hash algorithm.',
    standardReference: 'NIST FIPS 202',
  },
  'SHA3-512': {
    id: 'SHA3-512',
    displayName: 'SHA3-512 Keccak Permutation Hash',
    family: 'SHA-3',
    category: 'HASH',
    primitiveType: 'digest',
    supportedOperations: ['hash'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-202',
    digestSizeBits: 512,
    provider: 'node-crypto',
    description: 'NIST FIPS 202 512-bit sponge hash algorithm.',
    standardReference: 'NIST FIPS 202',
  },

  // --- HMAC ---
  'HMAC-SHA-256': {
    id: 'HMAC-SHA-256',
    displayName: 'HMAC using SHA-256',
    family: 'HMAC',
    category: 'MAC',
    primitiveType: 'symmetric',
    supportedOperations: ['hmac', 'hmac_verify'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-198-1',
    keyRequirements: { minBits: 128, maxBits: 4096 },
    digestSizeBits: 256,
    provider: 'node-crypto',
    description: 'Keyed-hash message authentication code using SHA-256. RFC 2104 / FIPS 198-1 standard.',
    standardReference: 'NIST FIPS 198-1 / RFC 2104',
  },
  'HMAC-SHA-384': {
    id: 'HMAC-SHA-384',
    displayName: 'HMAC using SHA-384',
    family: 'HMAC',
    category: 'MAC',
    primitiveType: 'symmetric',
    supportedOperations: ['hmac', 'hmac_verify'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-198-1',
    keyRequirements: { minBits: 192, maxBits: 4096 },
    digestSizeBits: 384,
    provider: 'node-crypto',
    description: 'Keyed-hash message authentication code using SHA-384.',
    standardReference: 'NIST FIPS 198-1',
  },
  'HMAC-SHA-512': {
    id: 'HMAC-SHA-512',
    displayName: 'HMAC using SHA-512',
    family: 'HMAC',
    category: 'MAC',
    primitiveType: 'symmetric',
    supportedOperations: ['hmac', 'hmac_verify'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-198-1',
    keyRequirements: { minBits: 256, maxBits: 4096 },
    digestSizeBits: 512,
    provider: 'node-crypto',
    description: 'Keyed-hash message authentication code using SHA-512 with 512-bit security.',
    standardReference: 'NIST FIPS 198-1',
  },

  // --- AEAD SYMMETRIC ENCRYPTION ---
  'AES-256-GCM': {
    id: 'AES-256-GCM',
    displayName: 'AES-256 in Galois/Counter Mode',
    family: 'AES',
    category: 'AEAD',
    primitiveType: 'symmetric',
    supportedOperations: ['encrypt', 'decrypt'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-197',
    keyRequirements: { minBits: 256, maxBits: 256, fixedBytes: 32 },
    nonceRequirements: { sizeBytes: 12, isUniqueRequired: true },
    tagSizeBits: 128,
    provider: 'node-crypto',
    description: 'NIST SP 800-38D authenticated encryption with associated data (AEAD) using 256-bit keys and 96-bit random IVs.',
    standardReference: 'NIST FIPS 197 / SP 800-38D',
  },

  // --- ASYMMETRIC SIGNATURES ---
  'ED25519': {
    id: 'ED25519',
    displayName: 'Ed25519 (Edwards-curve Digital Signature Algorithm)',
    family: 'EdDSA',
    category: 'SIGNATURE',
    primitiveType: 'asymmetric',
    supportedOperations: ['sign', 'verify'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: false,
    fipsStatus: 'RFC-8032',
    keyRequirements: { fixedBytes: 32, format: ['raw', 'pkcs8', 'spki'] },
    publicKeySizeBytes: 32,
    privateKeySizeBytes: 32,
    signatureSizeBytes: 64,
    provider: 'node-crypto',
    description: 'High-speed, collision-resistant Edwards-curve signature algorithm over Curve25519. Immune to side-channel cache attacks.',
    standardReference: 'RFC 8032 / FIPS 186-5',
  },

  // --- KEY AGREEMENT ---
  'X25519': {
    id: 'X25519',
    displayName: 'X25519 Diffie-Hellman Key Agreement',
    family: 'ECDH',
    category: 'KEY_AGREEMENT',
    primitiveType: 'asymmetric',
    supportedOperations: ['key_agreement'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: false,
    fipsStatus: 'RFC-7748',
    keyRequirements: { fixedBytes: 32, format: ['raw', 'pkcs8', 'spki'] },
    publicKeySizeBytes: 32,
    privateKeySizeBytes: 32,
    sharedSecretSizeBytes: 32,
    provider: 'node-crypto',
    description: 'Elliptic-curve Diffie-Hellman protocol using Montgomery curve Curve25519 for secure two-party shared secret derivation.',
    standardReference: 'RFC 7748',
  },

  // =========================================================================
  // PHASE 6: STANDARDIZED POST-QUANTUM CRYPTOGRAPHY (PQC)
  // =========================================================================

  // --- NIST FIPS 203: ML-KEM (Module-Lattice Key Encapsulation Mechanism) ---
  'ML-KEM-512': {
    id: 'ML-KEM-512',
    displayName: 'ML-KEM-512 Post-Quantum Key Encapsulation (Kyber-512)',
    family: 'ML-KEM',
    category: 'PQC_KEM',
    primitiveType: 'asymmetric',
    supportedOperations: ['kem_keygen', 'kem_encapsulate', 'kem_decapsulate', 'key_agreement'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-203',
    securityLevel: 1,
    publicKeySizeBytes: 800,
    privateKeySizeBytes: 1632,
    ciphertextSizeBytes: 768,
    sharedSecretSizeBytes: 32,
    provider: 'noble-pqc',
    description: 'NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism at Security Category 1 (~AES-128 equivalent).',
    standardReference: 'NIST FIPS 203 (August 2024)',
  },
  'ML-KEM-768': {
    id: 'ML-KEM-768',
    displayName: 'ML-KEM-768 Post-Quantum Key Encapsulation (Kyber-768)',
    family: 'ML-KEM',
    category: 'PQC_KEM',
    primitiveType: 'asymmetric',
    supportedOperations: ['kem_keygen', 'kem_encapsulate', 'kem_decapsulate', 'key_agreement'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-203',
    securityLevel: 3,
    publicKeySizeBytes: 1184,
    privateKeySizeBytes: 2400,
    ciphertextSizeBytes: 1088,
    sharedSecretSizeBytes: 32,
    provider: 'noble-pqc',
    description: 'NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism at Security Category 3 (~AES-192 equivalent). Primary recommended general-purpose PQC KEM.',
    standardReference: 'NIST FIPS 203 (August 2024)',
  },
  'ML-KEM-1024': {
    id: 'ML-KEM-1024',
    displayName: 'ML-KEM-1024 Post-Quantum Key Encapsulation (Kyber-1024)',
    family: 'ML-KEM',
    category: 'PQC_KEM',
    primitiveType: 'asymmetric',
    supportedOperations: ['kem_keygen', 'kem_encapsulate', 'kem_decapsulate', 'key_agreement'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-203',
    securityLevel: 5,
    publicKeySizeBytes: 1568,
    privateKeySizeBytes: 3168,
    ciphertextSizeBytes: 1568,
    sharedSecretSizeBytes: 32,
    provider: 'noble-pqc',
    description: 'NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism at Security Category 5 (~AES-256 equivalent). Maximum classical and post-quantum security margin.',
    standardReference: 'NIST FIPS 203 (August 2024)',
  },

  // --- NIST FIPS 204: ML-DSA (Module-Lattice Digital Signature Algorithm) ---
  'ML-DSA-44': {
    id: 'ML-DSA-44',
    displayName: 'ML-DSA-44 Post-Quantum Signatures (Dilithium2)',
    family: 'ML-DSA',
    category: 'PQC_SIG',
    primitiveType: 'asymmetric',
    supportedOperations: ['pqc_sign', 'pqc_verify', 'sign', 'verify'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-204',
    securityLevel: 2,
    publicKeySizeBytes: 1312,
    privateKeySizeBytes: 2560,
    signatureSizeBytes: 2420,
    provider: 'noble-pqc',
    description: 'NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm at Security Category 2 (~SHA-256 / AES-128 equivalent). Compact signatures.',
    standardReference: 'NIST FIPS 204 (August 2024)',
  },
  'ML-DSA-65': {
    id: 'ML-DSA-65',
    displayName: 'ML-DSA-65 Post-Quantum Signatures (Dilithium3)',
    family: 'ML-DSA',
    category: 'PQC_SIG',
    primitiveType: 'asymmetric',
    supportedOperations: ['pqc_sign', 'pqc_verify', 'sign', 'verify'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-204',
    securityLevel: 3,
    publicKeySizeBytes: 1952,
    privateKeySizeBytes: 4032,
    signatureSizeBytes: 3309,
    provider: 'noble-pqc',
    description: 'NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm at Security Category 3 (~AES-192 equivalent). Primary recommended general-purpose PQC signature.',
    standardReference: 'NIST FIPS 204 (August 2024)',
  },
  'ML-DSA-87': {
    id: 'ML-DSA-87',
    displayName: 'ML-DSA-87 Post-Quantum Signatures (Dilithium5)',
    family: 'ML-DSA',
    category: 'PQC_SIG',
    primitiveType: 'asymmetric',
    supportedOperations: ['pqc_sign', 'pqc_verify', 'sign', 'verify'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'FIPS-204',
    securityLevel: 5,
    publicKeySizeBytes: 2592,
    privateKeySizeBytes: 4896,
    signatureSizeBytes: 4627,
    provider: 'noble-pqc',
    description: 'NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm at Security Category 5 (~AES-256 equivalent). Maximum security digital signatures.',
    standardReference: 'NIST FIPS 204 (August 2024)',
  },

  // --- HYBRID POST-QUANTUM KEY EXCHANGE (Dual Combiner) ---
  'X25519+ML-KEM-768': {
    id: 'X25519+ML-KEM-768',
    displayName: 'Hybrid X25519 + ML-KEM-768 Dual Combiner',
    family: 'HYBRID',
    category: 'HYBRID_KEM',
    primitiveType: 'hybrid',
    supportedOperations: ['hybrid_keygen', 'hybrid_encapsulate', 'hybrid_decapsulate', 'key_agreement'],
    securityStatus: 'recommended',
    status: 'SUPPORTED',
    quantumResistant: true,
    fipsStatus: 'HYBRID-NONSTANDARD',
    securityLevel: 3,
    publicKeySizeBytes: 1216, // 32 + 1184
    privateKeySizeBytes: 2432, // 32 + 2400
    ciphertextSizeBytes: 1120, // 32 + 1088
    sharedSecretSizeBytes: 32,
    provider: 'amaracus-hybrid',
    description: 'Hybrid Key Encapsulation combining classical X25519 Diffie-Hellman with ML-KEM-768 via HKDF-SHA256. Fails safe even if either primitive is compromised.',
    // AMARACUS's own combiner, not IETF X-Wing (draft-connolly-cfrg-xwing-kem)
    standardReference: 'FIPS 203 (ML-KEM-768) + RFC 7748 (X25519), combined with HKDF-SHA256 (RFC 5869)',
  },
};

/**
 * Maps common spellings onto the registry's canonical IDs, so that
 * 'hmac-sha256', 'HMAC_SHA256' and 'HMAC-SHA-256' all name the same algorithm.
 */
export function normalizeAlgorithmId(id: string): string {
  const upper = String(id || '').toUpperCase().trim().replace(/_/g, '-');
  let m = upper.match(/^HMAC-?SHA-?(256|384|512)$/);
  if (m) return `HMAC-SHA-${m[1]}`;
  m = upper.match(/^SHA-?(256|384|512)$/);
  if (m) return `SHA-${m[1]}`;
  m = upper.match(/^SHA3-?(256|384|512)$/);
  if (m) return `SHA3-${m[1]}`;
  return upper;
}

export class AlgorithmRegistry {
  private static instance: AlgorithmRegistry;
  private readonly catalog: Map<AlgorithmId, AlgorithmMetadata> = new Map();

  private constructor() {
    for (const [id, meta] of Object.entries(ALGORITHM_CATALOG)) {
      this.catalog.set(id as AlgorithmId, meta);
    }
  }

  public static getInstance(): AlgorithmRegistry {
    if (!AlgorithmRegistry.instance) {
      AlgorithmRegistry.instance = new AlgorithmRegistry();
    }
    return AlgorithmRegistry.instance;
  }

  public get(id: string): AlgorithmMetadata {
    const normalized = normalizeAlgorithmId(id) as AlgorithmId;
    const meta = this.catalog.get(normalized);
    if (!meta) {
      throw new CryptoEngineError(
        'UNSUPPORTED_ALGORITHM',
        `Algorithm '${id}' is not supported by the AMARACUS Algorithm Registry.`,
        400,
        { requested: id, available: Array.from(this.catalog.keys()) }
      );
    }
    return meta;
  }

  public getAll(): AlgorithmMetadata[] {
    return Array.from(this.catalog.values());
  }

  public getByCategory(category: AlgorithmCategory): AlgorithmMetadata[] {
    return this.getAll().filter((a) => a.category === category);
  }

  public getPqcAlgorithms(): AlgorithmMetadata[] {
    return this.getAll().filter((a) => a.category === 'PQC_KEM' || a.category === 'PQC_SIG');
  }

  public getHybridAlgorithms(): AlgorithmMetadata[] {
    return this.getAll().filter((a) => a.category === 'HYBRID_KEM');
  }

  public getClassicalAlgorithms(): AlgorithmMetadata[] {
    return this.getAll().filter(
      (a) => a.category !== 'PQC_KEM' && a.category !== 'PQC_SIG' && a.category !== 'HYBRID_KEM'
    );
  }

  public getBySecurityLevel(level: PqcSecurityLevel): AlgorithmMetadata[] {
    return this.getAll().filter((a) => a.securityLevel === level);
  }

  public getByStatus(status: AlgorithmStatus): AlgorithmMetadata[] {
    return this.getAll().filter((a) => a.status === status);
  }

  public validate(id: string, operation: CryptoOperation): AlgorithmMetadata {
    const meta = this.get(id);
    if (!meta.supportedOperations.includes(operation)) {
      throw new CryptoEngineError(
        'UNSUPPORTED_ALGORITHM',
        `Algorithm '${meta.id}' does not support operation '${operation}'. Supported: ${meta.supportedOperations.join(', ')}`,
        400,
        { algorithm: meta.id, operation, supported: meta.supportedOperations }
      );
    }
    return meta;
  }

  public isAvailable(id: string): boolean {
    const normalized = normalizeAlgorithmId(id) as AlgorithmId;
    return this.catalog.has(normalized);
  }
}

export const registry = AlgorithmRegistry.getInstance();

