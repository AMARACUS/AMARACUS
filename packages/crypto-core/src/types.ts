export type AlgorithmId =
  // Hashing
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'
  // Message Authentication Codes
  | 'HMAC-SHA-256'
  | 'HMAC-SHA-384'
  | 'HMAC-SHA-512'
  // Authenticated Symmetric Encryption
  | 'AES-256-GCM'
  // Classical Digital Signatures
  | 'ED25519'
  // Classical Key Agreement
  | 'X25519'
  // NIST FIPS 203 Module-Lattice Key Encapsulation Mechanism (ML-KEM)
  | 'ML-KEM-512'
  | 'ML-KEM-768'
  | 'ML-KEM-1024'
  // NIST FIPS 204 Module-Lattice Digital Signature Algorithm (ML-DSA)
  | 'ML-DSA-44'
  | 'ML-DSA-65'
  | 'ML-DSA-87'
  // Hybrid Post-Quantum Key Exchange (Dual Combiner)
  | 'X25519+ML-KEM-768';

export type AlgorithmCategory =
  | 'HASH'
  | 'MAC'
  | 'AEAD'
  | 'SIGNATURE'
  | 'KEY_AGREEMENT'
  | 'PQC_KEM'
  | 'PQC_SIG'
  | 'HYBRID_KEM';

export type AlgorithmStatus =
  | 'SUPPORTED'
  | 'EXPERIMENTAL'
  | 'DEPRECATED'
  | 'DISABLED'
  | 'UNSUPPORTED';

export type PqcSecurityLevel = 1 | 2 | 3 | 4 | 5;

export type PrimitiveType = 'symmetric' | 'asymmetric' | 'digest' | 'hybrid';

export type CryptoOperation =
  | 'hash'
  | 'hmac'
  | 'hmac_verify'
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'key_agreement'
  | 'random'
  | 'kem_keygen'
  | 'kem_encapsulate'
  | 'kem_decapsulate'
  | 'pqc_sign'
  | 'pqc_verify'
  | 'hybrid_keygen'
  | 'hybrid_encapsulate'
  | 'hybrid_decapsulate';

export type SecurityStatus = 'recommended' | 'acceptable' | 'deprecated' | 'experimental';

export type FipsStatus =
  | 'FIPS-140-3'
  | 'FIPS-180-4'
  | 'FIPS-197'
  | 'FIPS-198-1'
  | 'FIPS-202'
  | 'FIPS-203'
  | 'FIPS-204'
  | 'RFC-8032'
  | 'RFC-7748'
  | 'NIST-PQC'
  | 'HYBRID-NONSTANDARD';

export interface KeyRequirements {
  minBits?: number;
  maxBits?: number;
  fixedBytes?: number;
  format?: ('raw' | 'pkcs8' | 'spki')[];
}

export interface NonceRequirements {
  sizeBytes: number;
  isUniqueRequired: boolean;
}

export interface AlgorithmMetadata {
  id: AlgorithmId;
  displayName: string;
  family: string;
  category: AlgorithmCategory;
  primitiveType: PrimitiveType;
  supportedOperations: CryptoOperation[];
  securityStatus: SecurityStatus;
  status: AlgorithmStatus;
  quantumResistant: boolean;
  fipsStatus: FipsStatus;
  securityLevel?: PqcSecurityLevel;
  keyRequirements?: KeyRequirements;
  nonceRequirements?: NonceRequirements;
  digestSizeBits?: number;
  tagSizeBits?: number;
  publicKeySizeBytes?: number;
  privateKeySizeBytes?: number;
  ciphertextSizeBytes?: number;
  signatureSizeBytes?: number;
  sharedSecretSizeBytes?: number;
  provider: 'node-crypto' | 'noble-pqc' | 'amaracus-hybrid' | 'external' | 'unsupported';
  description: string;
  standardReference?: string;
}

export type EncodingFormat = 'hex' | 'base64' | 'base64url' | 'utf8' | 'raw';

export interface EncryptedEnvelope {
  v: number;
  alg: 'AES-256-GCM';
  iv: string; // Base64URL
  ct: string; // Base64URL
  tag: string; // Base64URL
  aad?: string | null; // Base64URL
  wrappedDek?: string | null;
  wrapAlg?: string | null;
  /** Managed-key version that produced the envelope */
  keyVersion?: number | null;
}

export interface HashRequest {
  algorithm: AlgorithmId;
  data: string | Buffer;
  encoding?: EncodingFormat;
  outputEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface HashResult {
  algorithm: AlgorithmId;
  digest: string;
  encoding: 'hex' | 'base64' | 'base64url';
  byteLength: number;
}

export interface HmacRequest {
  algorithm: AlgorithmId;
  key: string | Buffer;
  data: string | Buffer;
  dataEncoding?: EncodingFormat;
  keyEncoding?: EncodingFormat;
  outputEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface HmacResult {
  algorithm: AlgorithmId;
  mac: string;
  encoding: 'hex' | 'base64' | 'base64url';
}

export interface HmacVerifyRequest {
  algorithm: AlgorithmId;
  key: string | Buffer;
  data: string | Buffer;
  mac: string;
  macEncoding?: 'hex' | 'base64' | 'base64url';
  dataEncoding?: EncodingFormat;
  keyEncoding?: EncodingFormat;
}

export interface EncryptRequest {
  algorithm: AlgorithmId;
  key: string | Buffer; // 32 bytes for AES-256
  plaintext: string | Buffer;
  keyEncoding?: EncodingFormat;
  plaintextEncoding?: EncodingFormat;
  aad?: string | Buffer;
  aadEncoding?: EncodingFormat;
}

export interface DecryptRequest {
  envelope: EncryptedEnvelope | string;
  key: string | Buffer;
  keyEncoding?: EncodingFormat;
  outputEncoding?: 'utf8' | 'hex' | 'base64' | 'base64url';
}

export interface SignRequest {
  algorithm: AlgorithmId;
  privateKey: string | Buffer;
  message: string | Buffer;
  privateKeyEncoding?: 'pkcs8' | 'raw' | 'hex' | 'base64';
  messageEncoding?: EncodingFormat;
  signatureEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface SignResult {
  algorithm: AlgorithmId;
  signature: string;
  encoding: 'hex' | 'base64' | 'base64url';
}

export interface VerifySignatureRequest {
  algorithm: AlgorithmId;
  publicKey: string | Buffer;
  message: string | Buffer;
  signature: string | Buffer;
  publicKeyEncoding?: 'spki' | 'raw' | 'hex' | 'base64';
  messageEncoding?: EncodingFormat;
  signatureEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface KeyAgreementRequest {
  algorithm: AlgorithmId;
  privateKey: string | Buffer;
  publicKey: string | Buffer;
  privateKeyEncoding?: 'pkcs8' | 'raw' | 'hex' | 'base64';
  publicKeyEncoding?: 'spki' | 'raw' | 'hex' | 'base64';
  outputEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface KeyAgreementResult {
  algorithm: AlgorithmId;
  sharedSecret: string;
  encoding: 'hex' | 'base64' | 'base64url';
}

export interface KeyPairResult {
  algorithm: AlgorithmId;
  publicKey: string;
  privateKey: string;
  format: string;
}

// ============================================================================
// PHASE 6: POST-QUANTUM CRYPTOGRAPHY (PQC) & HYBRID INTERFACES
// ============================================================================

// --- ML-KEM (FIPS 203) ---

export interface KemKeygenRequest {
  algorithm: 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
  encoding?: 'hex' | 'base64' | 'base64url';
}

export interface KemKeygenResult {
  algorithm: AlgorithmId;
  publicKey: string;
  privateKey: string;
  encoding: 'hex' | 'base64' | 'base64url';
  securityLevel: PqcSecurityLevel;
  publicKeyBytes: number;
  privateKeyBytes: number;
}

export interface KemEncapsulateRequest {
  algorithm: AlgorithmId;
  publicKey: string | Buffer;
  publicKeyEncoding?: 'hex' | 'base64' | 'base64url' | 'raw';
  outputEncoding?: 'hex' | 'base64' | 'base64url';
  /** Fixed encapsulation randomness m (32 bytes, hex or Buffer); for known-answer tests only */
  randomness?: string | Buffer;
}

export interface KemEncapsulateResult {
  algorithm: AlgorithmId;
  ciphertext: string;
  sharedSecret: string;
  encoding: 'hex' | 'base64' | 'base64url';
  ciphertextBytes: number;
  sharedSecretBytes: number;
}

export interface KemDecapsulateRequest {
  algorithm: AlgorithmId;
  privateKey: string | Buffer;
  ciphertext: string | Buffer;
  privateKeyEncoding?: 'hex' | 'base64' | 'base64url' | 'raw';
  ciphertextEncoding?: 'hex' | 'base64' | 'base64url' | 'raw';
  outputEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface KemDecapsulateResult {
  algorithm: AlgorithmId;
  sharedSecret: string;
  encoding: 'hex' | 'base64' | 'base64url';
  sharedSecretBytes: number;
}

// --- ML-DSA (FIPS 204) ---

export interface PqcSignatureKeygenRequest {
  algorithm: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
  encoding?: 'hex' | 'base64' | 'base64url';
}

export interface PqcKeygenResult {
  algorithm: AlgorithmId;
  publicKey: string;
  privateKey: string;
  encoding: 'hex' | 'base64' | 'base64url';
  securityLevel: PqcSecurityLevel;
  publicKeyBytes: number;
  privateKeyBytes: number;
}

export type PqcSignatureKeygenResult = PqcKeygenResult;

export interface PqcSignRequest {
  algorithm: AlgorithmId;
  privateKey: string | Buffer;
  message: string | Buffer;
  privateKeyEncoding?: 'hex' | 'base64' | 'base64url' | 'raw';
  messageEncoding?: EncodingFormat;
  signatureEncoding?: 'hex' | 'base64' | 'base64url';
  outputEncoding?: 'hex' | 'base64' | 'base64url';
  context?: string | Buffer;
}

export interface PqcSignResult {
  algorithm: AlgorithmId;
  signature: string;
  encoding: 'hex' | 'base64' | 'base64url';
  signatureBytes: number;
}

export interface PqcVerifyRequest {
  algorithm: AlgorithmId;
  publicKey: string | Buffer;
  message: string | Buffer;
  signature: string | Buffer;
  publicKeyEncoding?: 'hex' | 'base64' | 'base64url' | 'raw';
  messageEncoding?: EncodingFormat;
  signatureEncoding?: 'hex' | 'base64' | 'base64url' | 'raw';
  context?: string | Buffer;
}

export interface PqcVerifyResult {
  algorithm: AlgorithmId;
  valid: boolean;
}

// --- HYBRID KEY EXCHANGE (X25519 + ML-KEM-768) ---

export interface HybridPublicKey {
  x25519PublicKey: string; // 32 bytes
  mlkemPublicKey: string;   // 1184 bytes
}

export interface HybridPrivateKey {
  x25519PrivateKey: string; // 32 bytes
  mlkemPrivateKey: string;   // 2400 bytes
}

export interface HybridKeygenRequest {
  algorithm?: 'X25519+ML-KEM-768';
  encoding?: 'hex' | 'base64' | 'base64url';
}

export interface HybridKeygenResult {
  algorithm: 'X25519+ML-KEM-768';
  publicKey: HybridPublicKey;
  privateKey: HybridPrivateKey;
  encoding: 'hex' | 'base64' | 'base64url';
}

export interface HybridCiphertext {
  ephemeralX25519PublicKey: string; // 32 bytes
  mlkemCiphertext: string;          // 1088 bytes
}

export interface HybridEncapsulateRequest {
  algorithm?: 'X25519+ML-KEM-768';
  publicKey: HybridPublicKey;
  encoding?: 'hex' | 'base64' | 'base64url';
  outputEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface HybridEncapsulateResult {
  algorithm: 'X25519+ML-KEM-768';
  ciphertext: HybridCiphertext;
  combinedCiphertext: string; // Canonical concatenated byte string
  sharedSecret: string;       // 32-byte HKDF-SHA256 derived secret
  encoding: 'hex' | 'base64' | 'base64url';
}

export interface HybridDecapsulateRequest {
  algorithm?: 'X25519+ML-KEM-768';
  privateKey: HybridPrivateKey;
  ciphertext: HybridCiphertext | string;
  encoding?: 'hex' | 'base64' | 'base64url';
  outputEncoding?: 'hex' | 'base64' | 'base64url';
}

export interface HybridDecapsulateResult {
  algorithm: 'X25519+ML-KEM-768';
  sharedSecret: string;
  encoding: 'hex' | 'base64' | 'base64url';
}
