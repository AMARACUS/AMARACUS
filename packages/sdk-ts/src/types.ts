/**
 * Binary data types supported by AMARACUS SDK.
 */
export type BinaryLike = string | Buffer | Uint8Array | ArrayBuffer;

/**
 * Client initialization configuration.
 */
export interface AmaracusClientOptions {
  /**
   * AMARACUS API credential (e.g. "am_live_...").
   * Defaults to process.env.AMARACUS_API_KEY.
   */
  apiKey?: string;

  /**
   * Root API URL.
   * Defaults to process.env.AMARACUS_BASE_URL or "https://api.amaracus.tech/v1".
   */
  baseUrl?: string;

  /**
   * Request timeout in milliseconds.
   * Defaults to 30,000ms (30 seconds).
   */
  timeout?: number;

  /**
   * Maximum number of automatic retries on transient errors (429, 503, network drop).
   * Safe retries are only performed on idempotent requests.
   * Defaults to 2.
   */
  maxRetries?: number;

  /**
   * Default HTTP headers merged into every outgoing request.
   */
  defaultHeaders?: Record<string, string>;
}

/**
 * Per-request execution options.
 */
export interface RequestOptions {
  /**
   * Unique client-generated token ensuring safe idempotent replay protection.
   */
  idempotencyKey?: string;

  /**
   * Request-specific timeout override in milliseconds.
   */
  timeout?: number;

  /**
   * Additional HTTP headers for this specific request.
   */
  headers?: Record<string, string>;
}

/**
 * Standard API response envelope.
 */
export interface ApiResponseEnvelope<T> {
  data: T;
  requestId: string;
  operationId?: string;
  status?: string;
  mode?: 'sync' | 'async';
  pollUrl?: string;
  durationMs?: number;
  expiresAt?: string;
  pagination?: {
    hasMore: boolean;
    nextCursor: string | null;
    total?: number;
  };
  meta?: Record<string, any>;
}

// ============================================================================
// UNIVERSAL CRYPTOGRAPHIC TYPES (PHASE 12 API)
// ============================================================================

export interface EncryptRequest {
  /**
   * Logical key identifier (e.g. "key_ab12cd34").
   * Recommended for managed key lifecycle and automated rotation.
   */
  key?: string;

  /**
   * Raw 256-bit symmetric key in 64-character hex or base64 format.
   * Enables direct client-supplied key encryption without pre-registering a logical key.
   */
  rawKey?: string;

  /**
   * Plaintext data to encrypt. Supports strings, Node.js Buffers, Uint8Arrays, and ArrayBuffers.
   */
  data: BinaryLike;

  /**
   * Cryptographic algorithm. Defaults to "AES-256-GCM".
   */
  algorithm?: 'AES-256-GCM' | string;

  /**
   * Additional Authenticated Data (AAD) cryptographically bound to ciphertext.
   */
  aad?: BinaryLike;

  /**
   * Input string encoding if data is passed as a string. Defaults to "utf8".
   */
  encoding?: 'utf8' | 'base64' | 'hex';

  /**
   * Compliance and security policy profile. Defaults to "DEFAULT_SECURE".
   */
  policy?: 'DEFAULT_SECURE' | 'FIPS_COMPLIANT' | 'PQC_PREFERRED' | string;

  /**
   * Specific key version number to use. Defaults to the key's current active version.
   */
  version?: number;
}

export interface EncryptResponse {
  /**
   * Base64-encoded authenticated ciphertext.
   */
  ciphertext: string;

  /**
   * Base64-encoded 96-bit Initialization Vector (IV).
   */
  iv: string;

  /**
   * Base64-encoded 128-bit authentication tag.
   */
  tag: string;

  /**
   * Algorithm used for encryption (e.g. "AES-256-GCM").
   */
  algorithm: string;

  /**
   * Logical key identifier if encrypted with a managed key.
   */
  keyId?: string;

  /**
   * Version of the key used for this operation.
   */
  /**
   * Everything needed to decrypt (ciphertext, IV, tag, AAD, key version, wrapped data key)
   * as one opaque base64url string. Pass it back as `envelope` to decrypt().
   */
  envelope?: string;

  /**
   * Provider-wrapped data key (Azure Key Vault / Managed HSM keys only).
   */
  wrappedDek?: string;
  wrapAlg?: string;

  keyVersion?: number;

  /**
   * Envelope format version ("v1").
   */
  format: 'v1' | string;

  /**
   * Unique operation identifier for audit tracing and billing.
   */
  operationId: string;

  /**
   * Final operation state ("COMPLETED").
   */
  status: 'COMPLETED' | string;

  /**
   * Correlation request identifier.
   */
  requestId: string;
}

export interface DecryptRequest {
  /**
   * Logical key identifier (e.g. "key_ab12cd34").
   */
  key?: string;

  /**
   * Raw 256-bit symmetric key in hex or base64 format.
   */
  rawKey?: string;

  /**
   * Base64-encoded ciphertext.
   */
  ciphertext?: string;

  /**
   * Base64-encoded initialization vector.
   */
  iv?: string;

  /**
   * Base64-encoded authentication tag.
   */
  tag?: string;

  /**
   * Optional additional authenticated data.
   */
  aad?: string;

  /**
   * The opaque envelope string returned by encrypt() (preferred: it carries the key
   * version and any wrapped data key), or an envelope object.
   */
  envelope?:
    | string
    | {
        ciphertext?: string;
        ct?: string;
        iv?: string;
        tag?: string;
        aad?: string;
        algorithm?: string;
        wrappedDek?: string;
        wrapAlg?: string;
        keyVersion?: number;
      };

  /**
   * Output plaintext format. Defaults to "utf8".
   */
  outputEncoding?: 'utf8' | 'hex' | 'base64' | 'buffer';

  /**
   * Algorithm override if not specified in envelope.
   */
  algorithm?: string;

  /**
   * Compliance policy profile. Defaults to "DEFAULT_SECURE".
   */
  policy?: 'DEFAULT_SECURE' | 'FIPS_COMPLIANT' | 'PQC_PREFERRED' | string;

  /**
   * Key version to decrypt with.
   */
  version?: number;
}

export interface DecryptResponse {
  /**
   * Recovered plaintext string (or buffer representation).
   */
  plaintext: string;

  /**
   * Alias for plaintext to support ergonomic property access.
   */
  data?: string;

  /**
   * Encoding of `plaintext`: "utf8" for text, otherwise "base64"/"base64url"/"hex"
   * (binary plaintext that is not valid UTF-8 comes back as base64).
   */
  encoding?: 'utf8' | 'base64' | 'base64url' | 'hex';

  /**
   * Cryptographic algorithm used for decryption.
   */
  algorithm: string;

  /**
   * Logical key identifier.
   */
  keyId?: string;

  /**
   * Version of the key used.
   */
  keyVersion?: number;

  /**
   * Operation correlation identifier.
   */
  operationId: string;

  /**
   * Final operation state ("COMPLETED").
   */
  status: 'COMPLETED' | string;

  /**
   * Correlation request identifier.
   */
  requestId: string;
}

export interface HashRequest {
  /**
   * Data payload to hash. Supports strings, Buffers, Uint8Arrays, and ArrayBuffers.
   */
  data: BinaryLike;

  /**
   * Cryptographic hash algorithm.
   * Supported: "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512".
   */
  algorithm?: 'SHA-256' | 'SHA-384' | 'SHA-512' | 'SHA3-256' | 'SHA3-384' | 'SHA3-512' | string;

  /**
   * Input string encoding if data is a string. Defaults to "utf8".
   */
  encoding?: 'utf8' | 'base64' | 'hex';

  /**
   * Output digest format. Defaults to "hex".
   */
  outputEncoding?: 'hex' | 'base64';

  /**
   * Policy profile.
   */
  policy?: string;
}

export interface HashResponse {
  /**
   * Hex or Base64-encoded cryptographic digest.
   */
  digest: string;

  /**
   * Algorithm used.
   */
  algorithm: string;

  /**
   * Digest byte length (e.g. 32 for SHA-256, 64 for SHA-512).
   */
  byteLength: number;

  /**
   * Output encoding ("hex" or "base64").
   */
  encoding: 'hex' | 'base64';

  /**
   * Operation correlation identifier.
   */
  operationId: string;

  /**
   * Final operation state ("COMPLETED").
   */
  status: 'COMPLETED' | string;

  /**
   * Correlation request identifier.
   */
  requestId: string;
}

export interface SignRequest {
  /**
   * Logical signing key identifier (e.g. ED25519 or PQC key).
   */
  key?: string;

  /**
   * Raw private key in hex, base64, or PEM format.
   */
  privateKey?: string;

  /**
   * Data payload to sign.
   */
  data: BinaryLike;

  /**
   * Algorithm identifier (e.g. "ED25519", "ML-DSA-65").
   */
  algorithm?: string;

  /**
   * Input data encoding. Defaults to "utf8".
   */
  encoding?: 'utf8' | 'base64' | 'hex';

  /**
   * Output signature encoding. Defaults to "hex".
   */
  outputEncoding?: 'hex' | 'base64';

  /**
   * Key version to sign with.
   */
  version?: number;

  /**
   * Policy profile.
   */
  policy?: string;
}

export interface SignResponse {
  /**
   * Generated digital signature string.
   */
  signature: string;

  /**
   * Signing algorithm used.
   */
  algorithm: string;

  /**
   * Logical key identifier if signed with managed key.
   */
  keyId?: string;

  /**
   * Version of the key used.
   */
  keyVersion?: number;

  /**
   * Signature encoding ("hex" or "base64").
   */
  encoding: string;

  /**
   * Operation correlation identifier.
   */
  operationId: string;

  /**
   * Final operation state ("COMPLETED").
   */
  status: 'COMPLETED' | string;

  /**
   * Correlation request identifier.
   */
  requestId: string;
}

export interface VerifyRequest {
  /**
   * Logical verification key identifier.
   */
  key?: string;

  /**
   * Raw public key in hex, base64, or PEM format.
   */
  publicKey?: string;

  /**
   * Original data payload that was signed.
   */
  data: BinaryLike;

  /**
   * Digital signature string or buffer to verify.
   */
  signature: BinaryLike;

  /**
   * Algorithm identifier (e.g. "ED25519").
   */
  algorithm?: string;

  /**
   * Data encoding. Defaults to "utf8".
   */
  encoding?: 'utf8' | 'base64' | 'hex';

  /**
   * Signature encoding if signature is a string. Defaults to "hex".
   */
  signatureEncoding?: 'hex' | 'base64';

  /**
   * Key version to verify against.
   */
  version?: number;

  /**
   * Policy profile.
   */
  policy?: string;
}

export interface VerifyResponse {
  /**
   * True if signature is authentic and verified against data; false otherwise.
   */
  valid: boolean;

  /**
   * Algorithm used for verification.
   */
  algorithm: string;

  /**
   * Logical key identifier.
   */
  keyId?: string;

  /**
   * Operation correlation identifier.
   */
  operationId: string;

  /**
   * Final operation state ("COMPLETED").
   */
  status: 'COMPLETED' | string;

  /**
   * Correlation request identifier.
   */
  requestId: string;
}

// ============================================================================
// LOGICAL KEY MANAGEMENT TYPES (PHASE 12 API)
// ============================================================================

export interface LogicalKeyVersion {
  id: string;
  version: number;
  status: string;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  createdAt: string;
}

export interface LogicalKey {
  id: string;
  name: string;
  description?: string | null;
  algorithm: string;
  purpose: 'ENCRYPT_DECRYPT' | 'SIGN_VERIFY' | 'WRAP_UNWRAP' | string;
  status: 'ACTIVE' | 'DISABLED' | 'REVOKED' | 'DESTROYED' | string;
  currentVersion: number;
  createdAt: string;
  updatedAt: string;
  projectId?: string | null;
  environmentId?: string | null;
  versions?: LogicalKeyVersion[];
}

export interface CreateKeyRequest {
  name: string;
  algorithm: 'AES-256-GCM' | 'ED25519' | 'ML-KEM-768' | 'ML-DSA-65' | string;
  purpose: 'ENCRYPT_DECRYPT' | 'SIGN_VERIFY' | 'WRAP_UNWRAP' | string;
  description?: string;
  provider?: 'LOCAL_DEV' | 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM' | string;
  projectId?: string;
  environmentId?: string;
}

export interface UpdateKeyRequest {
  name?: string;
  description?: string;
  status?: 'ACTIVE' | 'DISABLED' | 'REVOKED';
  metadata?: Record<string, any>;
}

export interface ListKeysOptions extends RequestOptions {
  limit?: number;
  offset?: number;
  purpose?: string;
  status?: string;
  algorithm?: string;
}

export interface LogicalKeyListResponse {
  items: LogicalKey[];
  meta: {
    count: number;
    total: number;
    limit: number;
    offset: number;
  };
  requestId: string;
}

export interface KmsProviderHealth {
  providerId: string;
  name: string;
  type: string;
  status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE' | string;
  latencyMs?: number;
  lastChecked?: string;
  details?: Record<string, any>;
}

// ============================================================================
// DISCOVERY & OBSERVABILITY TYPES
// ============================================================================

export interface PlatformCapabilities {
  version: string;
  supportedOperations: string[];
  supportedAlgorithms: Array<{
    id: string;
    category: string;
    fipsApproved: boolean;
    keySizeBits?: number;
    digestBits?: number;
    standard?: string;
  }>;
  defaultAlgorithms: {
    encryption: string;
    hashing: string;
    signing: string;
  };
  securityProfiles: string[];
  features: {
    envelopeEncryption: boolean;
    logicalKeyManagement: boolean;
    keyRotation: boolean;
    postQuantumCryptography: boolean;
    hardwareBackedHSM: boolean;
    fipsCompliant: boolean;
    zeroSecretLeakage: boolean;
    billingUsageProtection: boolean;
  };
}

export interface AlgorithmMetadata {
  id: string;
  displayName?: string;
  category: string;
  family?: string;
  primitiveType?: string;
  supportedOperations?: string[];
  securityStatus?: string;
  status?: string;
  quantumResistant?: boolean;
  fipsStatus?: string;
  securityLevel?: number;
  provider?: string;
  description?: string;
  standardReference?: string;
}

export interface OperationRecord {
  id: string;
  operationType: string;
  algorithm?: string | null;
  keyId?: string | null;
  providerId?: string | null;
  status: string;
  durationMs?: number | null;
  retryCount?: number;
  expiresAt?: string | null;
  createdAt: string;
  updatedAt: string;
  error?: any;
}

export interface CreateOperationRequest {
  type: string;
  keyId?: string;
  algorithm?: string;
  mode?: 'sync' | 'async';
  priority?: 'HIGH' | 'NORMAL' | 'LOW';
  timeoutMs?: number;
  maxRetries?: number;
  ttlSeconds?: number;
  data?: any;
  plaintext?: any;
  ciphertext?: any;
  signature?: any;
  witness?: any;
  params?: Record<string, any>;
  metadata?: Record<string, any>;
  [key: string]: any;
}

export interface CreateOperationResponse {
  operationId: string;
  requestId: string;
  status: string;
  mode: 'sync' | 'async';
  pollUrl?: string;
  data?: any;
  durationMs?: number;
  expiresAt?: string | null;
}

export interface ListOperationsOptions extends RequestOptions {
  limit?: number;
  offset?: number;
  status?: string;
  type?: string;
}

export interface OperationResultResponse {
  operationId: string;
  status: string;
  data?: any;
  error?: any;
  durationMs?: number;
  retryAfterMs?: number;
}

export interface CancelOperationResponse {
  operationId: string;
  status: string;
  canceled: boolean;
}

export interface PollOperationOptions {
  intervalMs?: number;
  timeoutMs?: number;
  onProgress?: (status: string) => void;
}

// ============================================================================
// LEGACY DEVELOPER PLATFORM COMPATIBILITY TYPES
// ============================================================================

export interface ApiCredential {
  id: string;
  name: string;
  prefix: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  scopes: string[];
  status: 'ACTIVE' | 'DISABLED' | 'REVOKED' | 'EXPIRED';
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  createdAt: string;
}

export interface CreateCredentialParams {
  name: string;
  environment?: 'live' | 'test';
  scopes: string[];
  projectId?: string;
  environmentId?: string;
  expiresInDays?: number;
}

export interface CreateCredentialResult {
  credential: ApiCredential;
  rawApiKey: string;
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  description?: string | null;
  organizationId: string;
  events: string[];
  status: 'ACTIVE' | 'DISABLED';
  createdAt: string;
  updatedAt: string;
}

export interface CreateWebhookParams {
  url: string;
  description?: string;
  events: string[];
}

export interface CreateWebhookResult {
  webhook: WebhookEndpoint;
  signingSecret: string;
}

export interface WebhookDelivery {
  id: string;
  webhookEndpointId: string;
  event: string;
  payload: any;
  status: 'SUCCESS' | 'FAILED' | 'PENDING';
  statusCode?: number | null;
  error?: string | null;
  durationMs: number;
  attempt: number;
  createdAt: string;
}

export interface AsyncJob<T = any> {
  id: string;
  type: 'ZK_PROVE' | 'FHE_EVALUATE' | 'MPC_COMPUTE' | 'DISCOVERY_SCAN';
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  organizationId: string;
  progress: number;
  result?: T | null;
  error?: string | null;
  createdAt: string;
  completedAt?: string | null;
}

export interface SubmitJobParams {
  type: 'ZK_PROVE' | 'FHE_EVALUATE' | 'MPC_COMPUTE' | 'DISCOVERY_SCAN';
  payload: Record<string, any>;
}

export interface UsageMetrics {
  totalRequests: number;
  successRequests: number;
  errorRequests: number;
  avgLatencyMs: number;
  timeline?: Array<{ timestamp: string; count: number }>;
}

export type CryptographicKey = LogicalKey;
export type CreateKeyParams = CreateKeyRequest;
export type EncryptParams = EncryptRequest;
export type EncryptResult = EncryptResponse;
export type DecryptParams = DecryptRequest;
export type DecryptResult = DecryptResponse;
export type SignParams = SignRequest;
export type SignResult = SignResponse;
export type VerifyParams = VerifyRequest;
export type VerifyResult = VerifyResponse;

export interface CertificateRecord {
  id: string;
  name?: string;
  authorityId?: string | null;
  serialNumber: string;
  subject: string;
  issuer: string;
  certificateType?: string;
  keyAlgorithm?: string;
  status: string;
  daysRemaining?: number;
  notBefore: string;
  notAfter: string;
  fingerprint?: string;
  certificatePem: string;
  chainPem?: string | null;
  san?: { dns?: string[]; ips?: string[]; emails?: string[]; uris?: string[] } | null;
  revocation?: any;
}

export interface IssueCertificateParams {
  /** Issuing certificate authority ID (see certificates.getCas()). */
  authorityId: string;
  projectId: string;
  environmentId: string;
  /** Distinguished name, e.g. 'CN=api.example.com, O=Example, C=US'. */
  subject: string;
  name?: string;
  type?: 'SERVER' | 'CLIENT' | 'CODE_SIGNING' | 'EMAIL' | string;
  keyAlgorithm?: string;
  /** Existing managed key to certify instead of generating a new key pair. */
  keyReference?: string;
  validityDays?: number;
  san?: { dns?: string[]; ips?: string[]; emails?: string[]; uris?: string[] };
  keyUsage?: string[];
  extendedKeyUsage?: string[];
}

export interface CertificateValidationResult {
  certificateId: string;
  serialNumber: string;
  /** Signature, validity period and revocation check of the certificate itself. */
  isValid: boolean;
  /** Chain check up to the issuing CA (true when there is no chain to check). */
  chainValid: boolean;
  status: string;
  revocationStatus: 'GOOD' | 'REVOKED' | string;
  validation: any;
  chain: any | null;
}

// Post-Quantum
export interface PqcKeyPairParams {
  algorithm: 'ML_KEM_768' | 'ML_DSA_65' | string;
}

export interface PqcKeyPairResult {
  algorithm: string;
  publicKey: string;
  privateKey: string;
}

export interface PqcEncapsulateParams {
  algorithm: 'ML_KEM_768' | string;
  publicKey: string;
}

export interface PqcEncapsulateResult {
  cipherText: string;
  sharedSecret: string;
}

export interface PqcDecapsulateParams {
  algorithm: 'ML_KEM_768' | string;
  cipherText: string;
  privateKey: string;
}

export interface PqcDecapsulateResult {
  sharedSecret: string;
}

export interface PqcSignParams {
  algorithm: 'ML_DSA_65' | string;
  message: string;
  privateKey: string;
}

export interface PqcSignResult {
  signature: string;
  algorithm: string;
}

export interface PqcVerifyParams {
  algorithm: 'ML_DSA_65' | string;
  message: string;
  signature: string;
  publicKey: string;
}

export interface PqcVerifyResult {
  valid: boolean;
}

// ============================================================================
// PHASE 15 — CRYPTOGRAPHIC POLICY & INTELLIGENCE TYPES
// ============================================================================

export type PolicyScope = 'GLOBAL' | 'ORGANIZATION' | 'PROJECT' | 'ENVIRONMENT' | 'OPERATION';

export type PolicyRuleCategory =
  | 'ALGORITHM_RESTRICTION'
  | 'KEY_HYGIENE'
  | 'PQC_REQUIREMENT'
  | 'COMPLIANCE_MANDATE'
  | 'PROVIDER_RESTRICTION'
  | 'KEY_ACCESS_CONTROL'
  | 'PURPOSE_LIMITATION';

export type PolicyDecisionType =
  | 'ALLOW'
  | 'DENY'
  | 'REQUIRE_CONFIGURATION'
  | 'REQUIRE_STRONGER_ALGORITHM'
  | 'REQUIRE_KEY_ROTATION'
  | 'REQUIRE_APPROVED_PROVIDER';

export interface PolicyRule {
  id: string;
  category: PolicyRuleCategory;
  name: string;
  description?: string;
  effect: 'ALLOW' | 'DENY' | 'REQUIRE' | 'WARN';
  prohibitedAlgorithms?: string[];
  allowedAlgorithms?: string[];
  minRsaKeyBits?: number;
  minEccKeyBits?: number;
  maxKeyAgeDays?: number;
  maxRotationAgeDays?: number;
  requirePqc?: boolean;
  prohibitExportable?: boolean;
  requiredProviders?: string[];
  allowedProviders?: string[];
  exemptions?: string[];
  enabled: boolean;
}

export interface PolicyDocument {
  id: string;
  name: string;
  scope: PolicyScope;
  organizationId?: string;
  projectId?: string;
  environmentId?: string;
  version: number;
  description?: string;
  status: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
  rules: PolicyRule[];
  createdAt: string;
  updatedAt: string;
}

export interface PolicyDecisionTrace {
  level: PolicyScope;
  policyId: string;
  policyName: string;
  ruleId?: string;
  ruleCategory?: string;
  decision: PolicyDecisionType;
  reason?: string;
  timestamp: string;
}

export interface PolicyDecision {
  decision: PolicyDecisionType;
  allowed: boolean;
  policyVersion: string;
  reasons: string[];
  requirements: string[];
  warnings: string[];
  recommendations: string[];
  evaluatedPolicies: string[];
  trace: PolicyDecisionTrace[];
  timestamp: string;
}

export interface PolicyDryRunRequest {
  operationType: string;
  algorithm?: string;
  keyId?: string;
  providerId?: string;
  complianceProfile?: string;
  purpose?: string;
}

export interface PolicyDryRunResponse {
  allowed: boolean;
  decision: PolicyDecisionType;
  reasons: string[];
  requirements: string[];
  warnings: string[];
  recommendations: string[];
  trace: PolicyDecisionTrace[];
  explanation?: string;
  evaluatedPolicies: string[];
  timestamp: string;
}

export interface PolicySimulationRequest {
  candidatePolicy?: Partial<PolicyDocument>;
  rules?: PolicyRule[];
}

export interface PolicySimulationImpact {
  assetId: string;
  assetType: 'KEY' | 'OPERATION' | 'FINDING';
  algorithm?: string;
  compliant: boolean;
  previousDecision: PolicyDecisionType;
  simulatedDecision: PolicyDecisionType;
  violations: string[];
  recommendations: string[];
}

export interface PolicySimulationResponse {
  summary: {
    totalEvaluated: number;
    compliantCount: number;
    nonCompliantCount: number;
    breakageCount: number;
  };
  impacts: PolicySimulationImpact[];
  conflicts: string[];
  timestamp: string;
}

export interface CreatePolicyRequest {
  name: string;
  scope?: PolicyScope;
  projectId?: string;
  environmentId?: string;
  description?: string;
  rules?: PolicyRule[];
  status?: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
}

export interface UpdatePolicyRequest {
  name?: string;
  description?: string;
  rules?: PolicyRule[];
  status?: 'DRAFT' | 'ACTIVE' | 'ARCHIVED';
}

export interface PolicyMetricsResponse {
  evaluationCount: number;
  decisionDistribution: Record<string, number>;
  avgLatencyMs: number;
  p95LatencyMs: number;
  cacheHitRatio: number;
  anomalyAlerts: any[];
}

// ============================================================================
// PHASE 16: CONTROL PLANE TYPES
// ============================================================================

export interface ControlProject {
  id: string;
  name: string;
  slug: string;
  description?: string | null;
  organizationId: string;
  environments?: ControlEnvironment[];
  createdAt: string;
  updatedAt: string;
}

export interface ControlEnvironment {
  id: string;
  name: string;
  slug: string;
  type: 'development' | 'staging' | 'production' | string;
  projectId: string;
  createdAt: string;
  updatedAt: string;
}

export interface ControlTeam {
  id: string;
  organizationId: string;
  name: string;
  description?: string | null;
  members?: ControlTeamMember[];
  createdAt: string;
  updatedAt: string;
}

export interface ControlTeamMember {
  id: string;
  teamId: string;
  userId: string;
  role: string;
  user?: { id: string; name?: string | null; email: string };
  createdAt: string;
}

export interface ControlServiceIdentity {
  id: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  name: string;
  description?: string | null;
  status: string;
  scopes: string[];
  prefix: string;
  createdAt: string;
}

export interface ControlServiceIdentityCreated {
  serviceIdentity: ControlServiceIdentity;
  secretKey: string;
}

export interface CryptographicPosture {
  organizationId: string;
  timestamp: string;
  overallPostureScore: number;
  pqcReadinessScore: number;
  keys: {
    total: number;
    active: number;
    disabled: number;
    destroyed: number;
    rotationRequired: number;
    pqcCount: number;
    algorithmDistribution: Record<string, number>;
  };
  certificates: {
    total: number;
    expiringSoon: number;
  };
  policies: {
    total: number;
    active: number;
  };
  drifts: {
    unresolvedCount: number;
    items: any[];
  };
  findings: Array<{
    category: string;
    severity: string;
    title: string;
    detail: string;
  }>;
}

export interface ConfigurationDrift {
  id: string;
  organizationId: string;
  resourceType: string;
  resourceId: string;
  expectedState: any;
  actualState: any;
  driftSummary: string;
  status: 'DETECTED' | 'RESOLVED' | 'IGNORED' | string;
  detectedAt: string;
  resolvedAt?: string | null;
}

export interface ControlAuditEvent {
  id: string;
  organizationId?: string | null;
  userId?: string | null;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  metadata?: any;
  createdAt: string;
}

// ============================================================================
// PHASE 21 — INTELLIGENCE & AUTONOMOUS OPTIMIZATION TYPES
// ============================================================================

export type RecommendationStatus =
  | 'DETECTED'
  | 'UNDER_REVIEW'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'SCHEDULED'
  | 'EXECUTING'
  | 'COMPLETED'
  | 'FAILED'
  | 'DISMISSED';

export type RecommendationCategory =
  | 'SECURITY_RISK'
  | 'KEY_LIFECYCLE'
  | 'PQC_READINESS'
  | 'PROVIDER_OPTIMIZATION'
  | 'POLICY_OPTIMIZATION'
  | 'COST_EFFICIENCY'
  | 'RELIABILITY'
  | 'MIGRATION_RECOMMENDATION';

export type SeverityLevel =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export type EvidenceConfidenceLevel =
  | 'VERIFIED_FACT'
  | 'HIGH_CONFIDENCE'
  | 'MEDIUM_CONFIDENCE'
  | 'ESTIMATE'
  | 'INFERRED';

export interface EvidenceReference {
  source: string;
  resourceId: string;
  metricOrFact: string;
  observedValue: any;
  thresholdOrStandard?: any;
  timestamp: string;
  isEstimate?: boolean;
  confidence: EvidenceConfidenceLevel;
}

export interface RecommendationExplanation {
  summary: string;
  observedFacts: string[];
  technicalRisk: string;
  businessImpact: string;
  remediationSteps: string[];
  isAiGeneratedSummary?: boolean;
}

export interface ProposedAction {
  type: string;
  targetResourceId: string;
  targetResourceType: string;
  parameters?: Record<string, any>;
  isAutomated: boolean;
  requiresApproval: boolean;
  requiresFourEyes: boolean;
}

export interface AffectedResourceRef {
  id: string;
  type: string;
  name: string;
  provider?: string;
  algorithm?: string;
}

export interface UserFeedback {
  decision: 'ACCEPT' | 'REJECT' | 'DISMISS';
  reason?: string;
  decidedBy: string;
  decidedAt: string;
}

export interface ImpactAnalysisResult {
  recommendationId: string;
  affectedResourcesCount: number;
  affectedResources: AffectedResourceRef[];
  policyConsequences: {
    compliant: boolean;
    evaluatedPolicies: number;
    violationsFound: string[];
  };
  compatibilityRisks: string[];
  potentialDowntime: 'NONE' | 'MINIMAL_SUBSECOND' | 'SCHEDULED_MAINTENANCE';
  requiredApprovals: string[];
  estimatedResourceConsumption: {
    operationsCount: number;
    estimatedCostUsd: number;
    isEstimated: boolean;
  };
  knownRecoveryLimitations: string[];
  reversibility: 'FULLY_REVERSIBLE' | 'PARTIALLY_REVERSIBLE' | 'IRREVERSIBLE';
  simulatedAt: string;
}

export interface OptimizationRecommendation {
  id: string;
  orgId: string;
  category: RecommendationCategory;
  severity: SeverityLevel;
  priorityScore: number;
  title: string;
  explanation: RecommendationExplanation;
  evidence: EvidenceReference[];
  affectedResources: AffectedResourceRef[];
  expectedBenefit: string;
  risks: string[];
  preconditions: string[];
  proposedAction: ProposedAction;
  requiredPermissions: string[];
  verificationProcedure: string;
  status: RecommendationStatus;
  userFeedback?: UserFeedback;
  dryRunResult?: ImpactAnalysisResult;
  deduplicationKey: string;
  createdAt: string;
  updatedAt: string;
}

export interface RecommendationListOptions extends RequestOptions {
  category?: RecommendationCategory;
  status?: RecommendationStatus;
  severity?: SeverityLevel;
  limit?: number;
  offset?: number;
}

// ============================================================================
// PHASE 22: CRYPTOGRAPHIC TRUST, COMPLIANCE & ASSURANCE
// ============================================================================

export type ComplianceFrameworkId =
  | 'SOC_2_TYPE_II'
  | 'ISO_27001_2022'
  | 'NIST_SP_800_53_R5'
  | 'NIST_SP_800_57'
  | 'FIPS_140_3'
  | 'NIST_PQC';

export type ControlCategory =
  | 'DATA_AT_REST'
  | 'DATA_IN_TRANSIT'
  | 'KEY_LIFECYCLE'
  | 'CRYPTO_AGILITY'
  | 'QUANTUM_READINESS'
  | 'ACCESS_CONTROL'
  | 'AUDIT_INTEGRITY';

export type SharedResponsibilityParty =
  | 'AMARACUS_MANAGED'
  | 'CUSTOMER_CONFIGURED'
  | 'SHARED_RESPONSIBILITY'
  | 'CLOUD_PROVIDER_HSM';

export type ControlStatus =
  | 'SATISFIED'
  | 'PARTIALLY_SATISFIED'
  | 'UNSATISFIED'
  | 'NOT_APPLICABLE'
  | 'EXCEPTION_GRANTED';

export type EvidenceType =
  | 'KEY_METADATA'
  | 'POLICY_DEFINITION'
  | 'AUDIT_LOG_ENTRY'
  | 'PKI_CERTIFICATE'
  | 'CBOM_INVENTORY'
  | 'CIRCUIT_BREAKER_STATE'
  | 'CONFIGURATION_SETTING';

export type EvidenceFreshness = 'VALID' | 'STALE' | 'EXPIRED';

export type ExceptionStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface EvidenceArtifact {
  id: string;
  orgId: string;
  type: EvidenceType;
  source: string;
  title: string;
  collectedAt: string;
  expiresAt: string;
  digest: string;
  freshness: EvidenceFreshness;
  properties: Record<string, any>;
  chainOfCustody: {
    collector: string;
    sourceHost?: string;
    timestamp: string;
    digestAlgorithm: 'SHA-256';
  };
}

export interface ControlGap {
  id: string;
  controlId: string;
  frameworkId: ComplianceFrameworkId;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  rootCause: string;
  remediationGuidance: string;
  recommendationId?: string;
}

export interface ComplianceException {
  id: string;
  orgId: string;
  controlId: string;
  frameworkId: ComplianceFrameworkId;
  justification: string;
  compensatingControls: string;
  requestedBy: string;
  approvedBy?: string;
  status: ExceptionStatus;
  createdAt: string;
  expiresAt: string;
}

export interface ControlAssessment {
  controlId: string;
  frameworkId: ComplianceFrameworkId;
  code: string;
  title: string;
  category: ControlCategory;
  responsibility: SharedResponsibilityParty;
  status: ControlStatus;
  score: number;
  details: string;
  evidenceIds: string[];
  gaps: ControlGap[];
  exceptionId?: string;
  lastAssessedAt: string;
}

export interface ComplianceFrameworkDefinition {
  id: ComplianceFrameworkId;
  name: string;
  version: string;
  authority: string;
  description: string;
  controlCount: number;
  categories: ControlCategory[];
}

export interface FrameworkAssessmentReport {
  id: string;
  orgId: string;
  frameworkId: ComplianceFrameworkId;
  frameworkName: string;
  overallScore: number;
  totalControls: number;
  satisfiedControls: number;
  partiallySatisfiedControls: number;
  unsatisfiedControls: number;
  exceptionsCount: number;
  gapsCount: number;
  controls: ControlAssessment[];
  evidenceCount: number;
  reportDigest: string;
  generatedAt: string;
  disclaimer: string;
}

export interface EvaluateAssessmentsParams {
  frameworkId?: ComplianceFrameworkId;
  forceRefresh?: boolean;
}

export interface RequestExceptionParams {
  controlId: string;
  justification: string;
  compensatingControls: string;
  expiresAt: string;
}

export interface EvidenceListFilter {
  type?: EvidenceType;
  freshness?: EvidenceFreshness;
  source?: string;
}

export interface GapListFilter {
  frameworkId?: ComplianceFrameworkId;
  controlId?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}


