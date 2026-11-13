/**
 * AMARACUS — Phase 9: Advanced Cryptography Types
 * Zero-Knowledge Proofs (ZK) + Fully Homomorphic Encryption (FHE) +
 * Multi-Party Computation (MPC) + Threshold Cryptography
 */

// ==========================================
// 1. Zero-Knowledge Proof Types
// ==========================================

export type ZkProvingSystem = 'NIZK_SCHNORR_PEDERSEN' | 'GROTH16_R1CS';

export type ZkCircuitStatus = 'ACTIVE' | 'DRAFT' | 'DEPRECATED';

export interface ZkCircuitDefinition {
  id: string;
  name: string;
  version: string;
  description?: string;
  provingSystem: ZkProvingSystem;
  publicInputsSchema: string[]; // names of public parameters, e.g. ['commitment', 'epoch']
  privateInputsSchema: string[]; // names of witness fields, e.g. ['secretValue', 'blindingFactor']
  constraintsDescription: string;
  verificationKey: ZkVerificationKey;
  provingKeyMetadata?: {
    keyFingerprint: string;
    curve: string;
    generatorG: string;
    generatorH?: string;
  };
  status: ZkCircuitStatus;
  organizationId: string;
  projectId?: string;
  environmentId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ZkVerificationKey {
  circuitId: string;
  version: string;
  curve: 'bn254' | 'ed25519';
  generatorG: string;
  generatorH?: string;
  publicParameterPoints?: string[];
  metadata?: Record<string, any>;
}

export interface ZkProof {
  circuitId: string;
  version: string;
  provingSystem: ZkProvingSystem;
  publicInputs: Record<string, string>; // e.g. { commitment: "0x..." }
  proofData: {
    commitmentPointA: string;
    responseScalarS: string;
    auxiliaryData?: string;
  };
  timestamp: string;
}

export interface ZkStatement {
  circuitId: string;
  version: string;
  publicInputs: Record<string, string>;
}

export interface ZkWitness {
  privateInputs: Record<string, string>; // e.g. { secretValue: "42", blindingFactor: "0x..." }
}

export interface ZkVerifyResult {
  valid: boolean;
  circuitId: string;
  version: string;
  error?: string;
  verifiedAt: string;
  durationMs: number;
}

// ==========================================
// 2. Fully Homomorphic Encryption (FHE) Types
// ==========================================

export type FheScheme = 'BFV' | 'BGV' | 'CKKS';

export type FheOperationType = 'ADD' | 'SUBTRACT' | 'MULTIPLY' | 'NEGATE';

export interface FheSchemeParameters {
  scheme: FheScheme;
  polyModulusDegree: 4096 | 8192;
  plainModulusBitLength?: number;
  securityLevel: 'tc128' | 'tc192' | 'tc256';
}

export interface FheKeyMetadata {
  id: string;
  organizationId: string;
  projectId?: string;
  environmentId?: string;
  scheme: FheScheme;
  polyModulusDegree: number;
  publicKeyBase64: string;
  relinKeysBase64?: string;
  galoisKeysBase64?: string;
  hasSecretKey: boolean;
  createdAt: string;
}

export interface FheCiphertext {
  keyId: string;
  scheme: FheScheme;
  polyModulusDegree: number;
  ciphertextBase64: string;
  scale?: number;
  noiseBudgetEstimate?: number;
  operationDepth: number;
}

export interface FheEvaluationRequest {
  keyId: string;
  operation: FheOperationType;
  ciphertexts: string[]; // Base64 encoded ciphertexts
}

export interface FheEvaluationResult {
  keyId: string;
  scheme: FheScheme;
  operation: FheOperationType;
  resultCiphertextBase64: string;
  operationDepth: number;
  durationMs: number;
}

export interface FheLimits {
  maxPolyModulusDegree: number;
  maxMultiplicationDepth: number;
  maxCiphertextSizeBytes: number;
  supportedSchemes: FheScheme[];
  supportedOperations: FheOperationType[];
}

// ==========================================
// 3. Multi-Party Computation (MPC) Types
// ==========================================

export type MpcProtocol = 'ADDITIVE_SECRET_SHARING' | 'SHAMIR_SECRET_SHARING';

export type MpcSessionStatus =
  | 'INITIALIZING'
  | 'WAITING_FOR_PARTIES'
  | 'WAITING_FOR_INPUTS'
  | 'COMPUTING_ROUND'
  | 'COMPLETED'
  | 'FAILED'
  | 'TIMED_OUT';

export type MpcPartyRole = 'COORDINATOR' | 'COMPUTE_PARTY' | 'INPUT_PARTY';

export interface MpcParty {
  partyId: string;
  name: string;
  role: MpcPartyRole;
  joinedAt: string;
  hasSubmittedInput: boolean;
  blindedShareHash?: string; // SHA-256 of blinded share (no raw data)
}

export interface MpcSession {
  id: string;
  organizationId: string;
  projectId?: string;
  environmentId?: string;
  title: string;
  protocol: MpcProtocol;
  operation: 'SECURE_SUM' | 'SECURE_AVERAGE' | 'SECURE_COUNT';
  requiredParties: number;
  threshold: number;
  status: MpcSessionStatus;
  currentRound: number;
  totalRounds: number;
  parties: MpcParty[];
  result?: {
    computedValue: number;
    completedAt: string;
    participatingParties: string[];
  };
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface MpcInputSubmission {
  partyId: string;
  blindedShares: Array<{
    targetPartyId: string;
    shareData: string; // Base64 encoded share
  }>;
}

// ==========================================
// 4. Threshold Cryptography Types
// ==========================================

export type ThresholdOperation = 'THRESHOLD_SIGN' | 'THRESHOLD_DECRYPT' | 'THRESHOLD_AUTHORIZATION';

export type ThresholdStatus = 'PENDING_APPROVALS' | 'READY' | 'EXECUTED' | 'REJECTED' | 'EXPIRED';

export interface ThresholdParticipant {
  participantId: string;
  name: string;
  publicKeyShare: string;
  index: number;
}

export interface ThresholdKey {
  id: string;
  organizationId: string;
  projectId?: string;
  environmentId?: string;
  name: string;
  algorithm: 'ED25519_FROST' | 'SHAMIR_M_OF_N';
  threshold: number; // M
  totalParticipants: number; // N
  groupPublicKey: string;
  participants: ThresholdParticipant[];
  createdAt: string;
}

export interface ThresholdSession {
  id: string;
  organizationId: string;
  keyId: string;
  operation: ThresholdOperation;
  messageToSign?: string;
  payloadToAuthorize?: string;
  threshold: number;
  totalParticipants: number;
  approvals: Array<{
    participantId: string;
    approvedAt: string;
    signatureShare?: string;
  }>;
  status: ThresholdStatus;
  combinedResult?: {
    signature?: string;
    authorized: boolean;
    executedAt: string;
  };
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

// ==========================================
// 5. Provider & Policy Registry Types
// ==========================================

export type AdvancedCryptoFamily = 'ZK' | 'FHE' | 'MPC' | 'THRESHOLD';

export type AdvancedProviderStatus = 'SUPPORTED' | 'EXPERIMENTAL' | 'DEPRECATED' | 'DISABLED';

export interface AdvancedProviderCapability {
  family: AdvancedCryptoFamily;
  providerId: string;
  name: string;
  implementation: string;
  supportedSchemes: string[];
  supportedOperations: string[];
  status: AdvancedProviderStatus;
  version: string;
  description: string;
  limitations: Record<string, any>;
}

export interface AdvancedCryptoPolicyConfig {
  allowedZkSystems: ZkProvingSystem[];
  allowedFheSchemes: FheScheme[];
  allowedMpcProtocols: MpcProtocol[];
  minThresholdParticipants: number;
  maxThresholdParticipants: number;
  allowExperimental: boolean;
  maxFhePolyModulusDegree: number;
}
