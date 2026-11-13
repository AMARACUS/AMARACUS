import { AlgorithmId, EncryptedEnvelope } from '../types';

export type KeyProviderType = 'LOCAL_DEV' | 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM';

export type KeyPurpose = 'ENCRYPTION' | 'SIGNING' | 'KEY_AGREEMENT' | 'KEY_WRAPPING';

export type KeyLifecycleStatus =
  | 'PENDING'
  | 'ACTIVE'
  | 'DISABLED'
  | 'ROTATING'
  | 'REVOKED'
  | 'SCHEDULED_FOR_DELETION'
  | 'DESTROYED';

export type KeyVersionStatus = 'ACTIVE' | 'DEPRECATED' | 'DISABLED' | 'REVOKED' | 'DESTROYED';

export interface KeyProviderCapabilities {
  supportedPurposes: KeyPurpose[];
  supportedAlgorithms: AlgorithmId[];
  supportsKeyGeneration: boolean;
  supportsRotation: boolean;
  supportsScheduledDeletion: boolean;
  supportsEnvelopeEncryption: boolean;
  supportsAsymmetricSign: boolean;
  supportsPurge: boolean;
  supportsRecovery: boolean;
  supportsOctHsm: boolean;
  isHardwareBacked: boolean;
  isFips140Validated: boolean;
  supportsPqc: boolean;
}

export type ProviderHealthStatus =
  | 'CONFIGURED'
  | 'NOT_CONFIGURED'
  | 'AVAILABLE'
  | 'UNAVAILABLE'
  | 'DEGRADED'
  | 'DEVELOPMENT_ONLY';

export interface ProviderHealth {
  provider: KeyProviderType;
  label: string;
  status: ProviderHealthStatus;
  message: string;
  isConfigured: boolean;
  latencyMs?: number;
  details?: Record<string, any>;
}

export interface ManagedKeyMetadata {
  id: string;
  name: string;
  description?: string | null;
  organizationId: string;
  projectId: string;
  environmentId: string;
  algorithm: AlgorithmId;
  purpose: KeyPurpose;
  provider: KeyProviderType;
  status: KeyLifecycleStatus;
  currentVersion: number;
  createdAt: Date;
  updatedAt: Date;
  activatedAt?: Date | null;
  rotatedAt?: Date | null;
  disabledAt?: Date | null;
  revokedAt?: Date | null;
  scheduledDeletionAt?: Date | null;
  destroyedAt?: Date | null;
  expiresAt?: Date | null;
  metadata?: Record<string, any> | null;
}

export interface ManagedKeyVersion {
  id: string;
  keyId: string;
  version: number;
  providerKeyId: string;
  status: KeyVersionStatus;
  publicKey?: string | null;
  encryptedKeyMaterial?: string | null;
  keyFingerprint?: string | null;
  createdAt: Date;
  activatedAt?: Date | null;
  revokedAt?: Date | null;
  destroyedAt?: Date | null;
  metadata?: Record<string, any> | null;
}

export interface CreateKeyParams {
  name: string;
  algorithm: AlgorithmId;
  purpose: KeyPurpose;
  organizationId: string;
  projectId: string;
  environmentId: string;
  metadata?: Record<string, any>;
}

export interface ProviderKeyResult {
  providerKeyId: string;
  publicKey?: string | null;
  encryptedKeyMaterial?: string | null;
  keyFingerprint?: string | null;
  metadata?: Record<string, any>;
}

export interface RotateKeyParams {
  key: ManagedKeyMetadata;
  currentActiveVersion: ManagedKeyVersion;
}

export interface KeyProvider {
  readonly providerId: KeyProviderType;
  readonly label: string;
  readonly capabilities: KeyProviderCapabilities;

  isConfigured(): boolean;
  healthCheck(): Promise<ProviderHealth>;

  createKey(params: CreateKeyParams): Promise<ProviderKeyResult>;
  getPublicKey(providerKeyId: string, version?: ManagedKeyVersion): Promise<string | null>;

  encrypt(
    providerKeyId: string,
    plaintext: Buffer,
    aad?: Buffer,
    version?: ManagedKeyVersion
  ): Promise<EncryptedEnvelope>;

  decrypt(
    providerKeyId: string,
    envelope: EncryptedEnvelope,
    version?: ManagedKeyVersion
  ): Promise<Buffer>;

  sign(
    providerKeyId: string,
    data: Buffer,
    version?: ManagedKeyVersion
  ): Promise<Buffer>;

  verify(
    providerKeyId: string,
    data: Buffer,
    signature: Buffer,
    version?: ManagedKeyVersion
  ): Promise<boolean>;

  rotateKey(params: RotateKeyParams): Promise<ProviderKeyResult>;
  disableKey(providerKeyId: string): Promise<void>;
  enableKey(providerKeyId: string): Promise<void>;
  scheduleDeletion(providerKeyId: string, pendingWindowDays?: number): Promise<Date>;
  cancelDeletion(providerKeyId: string): Promise<void>;
  recoverKey(providerKeyId: string): Promise<void>;
  purgeKey(providerKeyId: string): Promise<void>;
  destroyKey(providerKeyId: string): Promise<void>;
}

export type OwnershipType = 'CUSTOMER_MANAGED' | 'AMARACUS_MANAGED' | 'CUSTOMER_OWNED';

export type CustomerProviderAuthType = 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY' | 'WORKLOAD_IDENTITY';

export type ConnectionStatus =
  | 'PENDING'
  | 'CONNECTING'
  | 'CONNECTED'
  | 'DEGRADED'
  | 'DISCONNECTED'
  | 'AUTHORIZATION_FAILED'
  | 'RESOURCE_NOT_FOUND'
  | 'KEY_NOT_FOUND'
  | 'CAPABILITY_ERROR'
  | 'ERROR';

export type HsmBackedStatus = 'VERIFIED_HSM' | 'STANDARD_VAULT' | 'UNKNOWN' | 'UNVERIFIED';

export interface KeyCapabilities {
  encrypt: boolean | 'unknown';
  decrypt: boolean | 'unknown';
  sign: boolean | 'unknown';
  verify: boolean | 'unknown';
  wrap: boolean | 'unknown';
  unwrap: boolean | 'unknown';
  derive: boolean | 'unknown';
  rotate: boolean | 'unknown';
  pqc?: boolean | 'unknown';
  unavailableReasons?: Record<string, string>;
}

export type CapabilityValue = true | false | 'UNKNOWN';

export interface ProviderCapabilitiesMap {
  ENCRYPT: CapabilityValue;
  DECRYPT: CapabilityValue;
  SIGN: CapabilityValue;
  VERIFY: CapabilityValue;
  WRAP: CapabilityValue;
  UNWRAP: CapabilityValue;
  DERIVE: CapabilityValue;
  KEY_VERSIONING?: CapabilityValue;
  ROTATION?: CapabilityValue;
  DISABLE?: CapabilityValue;
  ENABLE?: CapabilityValue;
  DELETE?: CapabilityValue;
  RECOVER?: CapabilityValue;
  PURGE?: CapabilityValue;
}

export type ResourceType = 'KEY_VAULT' | 'MANAGED_HSM';

export type KeyState =
  | 'DISCOVERED'
  | 'REGISTERED'
  | 'ACTIVE'
  | 'DISABLED'
  | 'REVOKED'
  | 'EXPIRED'
  | 'DELETED'
  | 'UNKNOWN';

export * from './onboarding-state-machine';

export type CustomerKeyOperation = 'ENCRYPT' | 'DECRYPT' | 'SIGN' | 'VERIFY' | 'WRAP' | 'UNWRAP' | 'DERIVE';

export interface CustomerKeyProviderConfig {
  name: string;
  providerType: 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM';
  ownershipType: OwnershipType;
  vaultUrl: string;
  hsmUrl?: string;
  resourceId?: string;
  authType: CustomerProviderAuthType;
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  managedIdentityId?: string;
}

export interface CustomerConnectionTestResult {
  success: boolean;
  providerType: 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM';
  connectionStatus: ConnectionStatus;
  isHsmBacked: boolean;
  hsmBackedStatus: HsmBackedStatus;
  vaultUrl: string;
  accessibleKeysCount: number;
  capabilities: KeyCapabilities;
  providerCapabilities: KeyProviderCapabilities;
  pqc?: boolean;
  latencyMs: number;
  message: string;
  error?: string;
}

export interface DiscoveredKeyMetadata {
  keyIdentifier: string;
  keyType: string;
  algorithm: AlgorithmId;
  purpose: KeyPurpose;
  currentVersion: string;
  enabled: boolean;
  isHsmBacked: boolean;
  hsmBackedStatus: HsmBackedStatus;
  operations: string[];
  capabilities: KeyCapabilities;
  publicKey?: string;
  keyFingerprint?: string;
  createdAt?: Date;
  expiresAt?: Date;
}

export interface CustomerRegisteredKeyMetadata {
  id: string;
  providerId: string;
  organizationId: string;
  projectId: string;
  environmentId: string;
  keyIdentifier: string;
  keyVaultUrl: string;
  keyType: string;
  algorithm: AlgorithmId;
  purpose: KeyPurpose;
  ownershipType: OwnershipType;
  isHsmBacked: boolean;
  hsmBackedStatus: HsmBackedStatus;
  status: string;
  currentVersion: string;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  operations: string[];
  capabilities: KeyCapabilities;
  lastSyncedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface CustomerKeyOperationParams {
  keyIdentifier: string;
  version?: string;
}

export interface CustomerKeyProvider {
  readonly config: CustomerKeyProviderConfig;
  readonly capabilities: KeyProviderCapabilities;

  testConnection(): Promise<CustomerConnectionTestResult>;
  discoverKeys(): Promise<DiscoveredKeyMetadata[]>;
  discoverKey(keyIdentifier: string): Promise<DiscoveredKeyMetadata>;
  encrypt(
    keyIdentifier: string,
    plaintext: Buffer,
    aad?: Buffer,
    version?: string
  ): Promise<EncryptedEnvelope>;
  decrypt(
    keyIdentifier: string,
    envelope: EncryptedEnvelope,
    version?: string
  ): Promise<Buffer>;
  sign(
    keyIdentifier: string,
    data: Buffer,
    version?: string
  ): Promise<Buffer>;
  verify(
    keyIdentifier: string,
    data: Buffer,
    signature: Buffer,
    version?: string
  ): Promise<boolean>;
  syncKeyVersions(keyIdentifier: string): Promise<{ versions: string[]; currentVersion: string }>;
}


