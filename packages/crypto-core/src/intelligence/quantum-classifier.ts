import { QuantumStatus } from './types';

export interface QuantumClassificationResult {
  algorithm: string;
  quantumStatus: QuantumStatus;
  rationale: string;
  impactMechanism: string;
  nistStatus?: string;
  recommendedAlternative?: string;
}

export class QuantumClassifier {
  /**
   * Classify the quantum risk of an algorithm with scientific rationale.
   * Grounded in NIST PQC standards (FIPS 203, FIPS 204), Shor's algorithm, and Grover's algorithm bounds.
   */
  static classify(algorithmName: string, keySizeBits?: number): QuantumClassificationResult {
    const norm = (algorithmName || '').toUpperCase().trim();

    // 1. Hybrid Post-Quantum / Classical Combiners
    if (
      norm.includes('+') ||
      norm.includes('HYBRID') ||
      norm.includes('X-WING') ||
      norm.includes('DUAL')
    ) {
      return {
        algorithm: algorithmName,
        quantumStatus: 'HYBRID',
        rationale: 'Hybrid construction combining a classical primitive (e.g. X25519) with a post-quantum primitive (e.g. ML-KEM-768). Provides defense-in-depth: maintains proven classical hardness while safeguarding against Store-Now-Decrypt-Later (SNDL) threats.',
        impactMechanism: 'Dual key combiner ensures security as long as at least one underlying primitive remains unbroken.',
        nistStatus: 'IETF RFC / NIST SP 800-56C Rev 2 recommendation',
        recommendedAlternative: 'Current best practice for TLS / KEM transition',
      };
    }

    // 2. Post-Quantum Cryptography (NIST Standardized FIPS 203 / FIPS 204)
    if (
      norm.includes('ML-KEM') ||
      norm.includes('ML-DSA') ||
      norm.includes('SLH-DSA') ||
      norm.includes('KYBER') ||
      norm.includes('DILITHIUM') ||
      norm.includes('SPHINCS')
    ) {
      return {
        algorithm: algorithmName,
        quantumStatus: 'PQC',
        rationale: 'Standardized post-quantum algorithm designed to resist attacks from both classical and cryptographically relevant quantum computers (CRQC). Based on hard lattice problems (Module Learning With Errors / Ring-LWE).',
        impactMechanism: 'Immune to Shor\'s algorithm; no polynomial-time quantum attack known.',
        nistStatus: norm.includes('ML-KEM') ? 'NIST FIPS 203' : 'NIST FIPS 204',
      };
    }

    // 3. Classical Public-Key Cryptography (Broken by Shor's Algorithm)
    if (
      norm.includes('RSA') ||
      norm.includes('ECDSA') ||
      norm.includes('ECDH') ||
      norm.includes('ED25519') ||
      norm.includes('X25519') ||
      norm.includes('SECP') ||
      norm.includes('PRIME256V1') ||
      norm.includes('DSA') ||
      norm.includes('DIFFIE-HELLMAN')
    ) {
      const isSignature = norm.includes('RSA') || norm.includes('ECDSA') || norm.includes('ED25519') || norm.includes('DSA');
      const recAlt = isSignature ? 'ML-DSA-65 or hybrid dual-signature' : 'ML-KEM-768 or X25519+ML-KEM-768 hybrid';

      return {
        algorithm: algorithmName,
        quantumStatus: 'QUANTUM_VULNERABLE',
        rationale: 'Relies on classical integer factorization or discrete logarithm / elliptic curve discrete logarithm problems. Completely vulnerable to Shor\'s polynomial-time algorithm on a sufficiently large Cryptographically Relevant Quantum Computer (CRQC).',
        impactMechanism: 'Shor\'s quantum algorithm computes discrete logarithms and factors integers in O((log N)^3) time, reducing security to zero once scalable fault-tolerant quantum hardware is realized.',
        nistStatus: 'NIST deprecation timeline CNSA 2.0 (target migration 2030-2035)',
        recommendedAlternative: recAlt,
      };
    }

    // 4. Classical Symmetric Encryption and Cryptographic Hashes
    if (
      norm.includes('AES') ||
      norm.includes('CHACHA') ||
      norm.includes('SHA-256') ||
      norm.includes('SHA-384') ||
      norm.includes('SHA-512') ||
      norm.includes('SHA3') ||
      norm.includes('HMAC')
    ) {
      const isAES128 = norm.includes('128') || (keySizeBits !== undefined && keySizeBits <= 128);
      
      if (isAES128) {
        return {
          algorithm: algorithmName,
          quantumStatus: 'CLASSICAL',
          rationale: 'Symmetric primitive with 128-bit key length. Subject to Grover\'s quadratic speedup, reducing effective quantum security to 64 bits of brute-force resistance.',
          impactMechanism: 'Grover\'s algorithm achieves O(2^(N/2)) search complexity, halving the effective key size in symmetric cryptography.',
          nistStatus: 'NIST acceptable currently; upgrade to 256-bit keys recommended for long-term quantum resistance.',
          recommendedAlternative: 'AES-256-GCM',
        };
      }

      return {
        algorithm: algorithmName,
        quantumStatus: 'CLASSICAL',
        rationale: 'Symmetric primitive or cryptographic hash with >= 256-bit security margin. Grover\'s quantum search yields an effective post-quantum security level of >= 128 bits, which remains computationally infeasible.',
        impactMechanism: 'Grover\'s algorithm provides quadratic speedup (256 bits -> 128 bits post-quantum security margin).',
        nistStatus: 'FIPS 197 / FIPS 180-4 / FIPS 202 (Quantum-resistant under Grover bounds)',
      };
    }

    // 5. Deprecated Legacy Primitives
    if (norm.includes('MD5') || norm.includes('SHA-1') || norm.includes('DES') || norm.includes('RC4')) {
      return {
        algorithm: algorithmName,
        quantumStatus: 'QUANTUM_VULNERABLE',
        rationale: 'Cryptographically broken legacy primitive. Insecure under both classical and quantum computational models.',
        impactMechanism: 'Severe classical collision or key recovery attacks exist independent of quantum capabilities.',
        nistStatus: 'Disallowed by NIST SP 800-131A Rev 2',
        recommendedAlternative: 'SHA-256 / AES-256-GCM',
      };
    }

    return {
      algorithm: algorithmName,
      quantumStatus: 'UNKNOWN',
      rationale: 'Algorithm could not be definitively classified under current standardized cryptographic profiles.',
      impactMechanism: 'Unknown mathematical structure.',
      nistStatus: 'Unclassified',
    };
  }
}
