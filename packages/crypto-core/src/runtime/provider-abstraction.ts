/**
 * AMARACUS Cryptographic Infrastructure — Provider Abstraction
 *
 * Defines the standardized interface that all internal cryptographic providers
 * must implement (Local Dev, Azure Key Vault, Azure Managed HSM, BYOK, PQC, Advanced).
 *
 * Principles:
 * - Application developers never interact directly with providers.
 * - Providers explicitly report capabilities (3-state: true, false, 'UNKNOWN').
 * - No fake implementations for unsupported functionality.
 */

import { EncryptedEnvelope, AlgorithmId } from '../types';
import { CapabilityValue } from '../keys/types';
import { KeyReference } from './key-reference';
import { OperationType } from './operation-model';

export interface ProviderCapabilityMap {
  encryption: CapabilityValue;
  decryption: CapabilityValue;
  signing: CapabilityValue;
  verification: CapabilityValue;
  hashing: CapabilityValue;
  hmac: CapabilityValue;
  keyGeneration: CapabilityValue;
  keyRotation: CapabilityValue;
  keyWrapping: CapabilityValue;
  keyUnwrapping: CapabilityValue;
  pqc: CapabilityValue;
  hardwareBacked: boolean;
  fipsValidated: boolean;
  supportedAlgorithms: string[];
  supportedPurposes: string[];
}

export interface ProviderHealthReport {
  providerId: string;
  name: string;
  status: 'AVAILABLE' | 'UNAVAILABLE' | 'DEGRADED' | 'DEVELOPMENT_ONLY' | 'NOT_CONFIGURED';
  message: string;
  latencyMs?: number;
  capabilities: ProviderCapabilityMap;
  timestamp: string;
}

export interface ProviderEncryptParams {
  keyReference?: KeyReference | null;
  key?: Buffer | string;
  keyEncoding?: 'hex' | 'base64' | 'raw';
  plaintext: Buffer;
  algorithm: string;
  aad?: Buffer;
  version?: number | string;
}

export interface ProviderDecryptParams {
  keyReference?: KeyReference | null;
  key?: Buffer | string;
  keyEncoding?: 'hex' | 'base64' | 'raw';
  envelope: EncryptedEnvelope;
  algorithm?: string;
  version?: number | string;
}

export interface ProviderSignParams {
  keyReference?: KeyReference | null;
  privateKey?: Buffer | string;
  data: Buffer;
  algorithm: string;
  version?: number | string;
}

export interface ProviderVerifyParams {
  keyReference?: KeyReference | null;
  publicKey?: Buffer | string;
  data: Buffer;
  signature: Buffer;
  algorithm: string;
  version?: number | string;
}

export interface ProviderKeyGenParams {
  name: string;
  algorithm: string;
  purpose: string;
  isHsm?: boolean;
  metadata?: Record<string, any>;
}

export interface ProviderKeyGenResult {
  providerKeyId: string;
  publicKey?: string | null;
  encryptedKeyMaterial?: string | null;
  keyFingerprint?: string | null;
  metadata?: Record<string, any>;
}

export interface CryptographicProvider {
  /** Unique provider identifier (e.g. 'LOCAL_DEV', 'AZURE_KEY_VAULT', 'AZURE_MANAGED_HSM', 'PQC_ENGINE') */
  readonly id: string;
  readonly name: string;
  readonly capabilities: ProviderCapabilityMap;

  /** Health & readiness check */
  isAvailable(): Promise<boolean>;
  healthCheck(): Promise<ProviderHealthReport>;

  /** Capability query before execution */
  supportsOperation(operation: OperationType, algorithm?: string): boolean;

  /** Standard Cryptographic Primitives */
  encrypt(params: ProviderEncryptParams): Promise<EncryptedEnvelope>;
  decrypt(params: ProviderDecryptParams): Promise<Buffer>;
  sign(params: ProviderSignParams): Promise<Buffer>;
  verify(params: ProviderVerifyParams): Promise<boolean>;

  /** Optional extended primitives */
  hash?(data: Buffer, algorithm: string): Promise<Buffer>;
  hmac?(key: Buffer, data: Buffer, algorithm: string): Promise<Buffer>;
  generateKey?(params: ProviderKeyGenParams): Promise<ProviderKeyGenResult>;
  rotateKey?(keyReference: KeyReference): Promise<ProviderKeyGenResult>;
}
