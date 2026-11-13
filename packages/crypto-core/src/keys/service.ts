import {
  KeyProvider,
  KeyProviderType,
  ProviderHealth,
  ManagedKeyMetadata,
  ManagedKeyVersion,
  CreateKeyParams,
  ProviderKeyResult,
  RotateKeyParams,
} from './types';
import { LocalDevKeyProvider } from './providers/local-dev-provider';
import { AzureKeyVaultKeyProvider } from './providers/azure-kv-provider';
import { AzureManagedHsmProvider } from './providers/azure-managed-hsm-provider';
import { KeyLifecycleValidator } from './state-machine';
import { CryptoEngineError } from '../errors';
import { EncryptedEnvelope } from '../types';

/**
 * Only the current ACTIVE version may encrypt or sign; decrypt and verify also
 * accept DEPRECATED (rotated-out) versions. Disabled, revoked and destroyed
 * versions fail closed.
 */
function assertVersionUsable(
  key: ManagedKeyMetadata,
  version: ManagedKeyVersion,
  use: 'encrypt' | 'decrypt' | 'sign' | 'verify'
): void {
  const status = String(version.status || '').toUpperCase();
  const producesOutput = use === 'encrypt' || use === 'sign';
  if (producesOutput && Number(version.version) !== Number(key.currentVersion)) {
    throw new CryptoEngineError(
      'KEY_DISABLED',
      `Only the current version (${key.currentVersion}) can ${use}; version ${version.version} is not active.`,
      400
    );
  }
  const allowed = producesOutput ? status === 'ACTIVE' : status === 'ACTIVE' || status === 'DEPRECATED';
  if (!allowed) {
    throw new CryptoEngineError('KEY_DISABLED', `Key version ${version.version} is ${status} and cannot be used to ${use}.`, 400);
  }
}

export class KeyManagementService {
  private providers: Map<KeyProviderType, KeyProvider> = new Map();

  constructor() {
    this.registerProvider(new LocalDevKeyProvider());
    this.registerProvider(new AzureKeyVaultKeyProvider());
    this.registerProvider(new AzureManagedHsmProvider());
  }

  registerProvider(provider: KeyProvider): void {
    this.providers.set(provider.providerId, provider);
  }

  getProvider(type: KeyProviderType): KeyProvider {
    const provider = this.providers.get(type);
    if (!provider) {
      throw new CryptoEngineError('UNSUPPORTED_PROVIDER', `Key provider '${type}' is not recognized.`);
    }
    return provider;
  }

  async getAllProviderHealth(): Promise<ProviderHealth[]> {
    const results: ProviderHealth[] = [];
    for (const provider of Array.from(this.providers.values())) {
      results.push(await provider.healthCheck());
    }
    return results;
  }

  async createKey(params: CreateKeyParams & { provider: KeyProviderType }): Promise<ProviderKeyResult> {
    const provider = this.getProvider(params.provider);
    return provider.createKey(params);
  }

  async encryptWithKey(
    key: ManagedKeyMetadata,
    version: ManagedKeyVersion,
    plaintext: Buffer,
    aad?: Buffer
  ): Promise<EncryptedEnvelope> {
    KeyLifecycleValidator.validateOperationAllowed(key.status, 'encrypt');
    assertVersionUsable(key, version, 'encrypt');
    KeyLifecycleValidator.validatePurpose(key.purpose, 'encrypt');
    const provider = this.getProvider(key.provider);
    return provider.encrypt(version.providerKeyId, plaintext, aad, version);
  }

  async decryptWithKey(
    key: ManagedKeyMetadata,
    version: ManagedKeyVersion,
    envelope: EncryptedEnvelope
  ): Promise<Buffer> {
    KeyLifecycleValidator.validateOperationAllowed(key.status, 'decrypt');
    assertVersionUsable(key, version, 'decrypt');
    KeyLifecycleValidator.validatePurpose(key.purpose, 'decrypt');
    const provider = this.getProvider(key.provider);
    return provider.decrypt(version.providerKeyId, envelope, version);
  }

  async signWithKey(
    key: ManagedKeyMetadata,
    version: ManagedKeyVersion,
    data: Buffer
  ): Promise<Buffer> {
    KeyLifecycleValidator.validateOperationAllowed(key.status, 'sign');
    assertVersionUsable(key, version, 'sign');
    KeyLifecycleValidator.validatePurpose(key.purpose, 'sign');
    const provider = this.getProvider(key.provider);
    return provider.sign(version.providerKeyId, data, version);
  }

  async verifyWithKey(
    key: ManagedKeyMetadata,
    version: ManagedKeyVersion,
    data: Buffer,
    signature: Buffer
  ): Promise<boolean> {
    KeyLifecycleValidator.validateOperationAllowed(key.status, 'verify');
    assertVersionUsable(key, version, 'verify');
    KeyLifecycleValidator.validatePurpose(key.purpose, 'verify');
    const provider = this.getProvider(key.provider);
    return provider.verify(version.providerKeyId, data, signature, version);
  }

  async rotateKey(params: RotateKeyParams): Promise<ProviderKeyResult> {
    KeyLifecycleValidator.validateOperationAllowed(params.key.status, 'rotate');
    const provider = this.getProvider(params.key.provider);
    return provider.rotateKey(params);
  }

  async disableKey(key: ManagedKeyMetadata, version: ManagedKeyVersion): Promise<void> {
    KeyLifecycleValidator.validateTransition(key.status, 'DISABLED');
    const provider = this.getProvider(key.provider);
    await provider.disableKey(version.providerKeyId);
  }

  async enableKey(key: ManagedKeyMetadata, version: ManagedKeyVersion): Promise<void> {
    KeyLifecycleValidator.validateTransition(key.status, 'ACTIVE');
    const provider = this.getProvider(key.provider);
    await provider.enableKey(version.providerKeyId);
  }

  async scheduleDeletion(key: ManagedKeyMetadata, version: ManagedKeyVersion, days: number = 7): Promise<Date> {
    KeyLifecycleValidator.validateTransition(key.status, 'SCHEDULED_FOR_DELETION');
    const provider = this.getProvider(key.provider);
    return provider.scheduleDeletion(version.providerKeyId, days);
  }

  async cancelDeletion(key: ManagedKeyMetadata, version: ManagedKeyVersion): Promise<void> {
    KeyLifecycleValidator.validateTransition(key.status, 'ACTIVE');
    const provider = this.getProvider(key.provider);
    await provider.cancelDeletion(version.providerKeyId);
  }

  async recoverKey(key: ManagedKeyMetadata, version: ManagedKeyVersion): Promise<void> {
    KeyLifecycleValidator.validateTransition(key.status, 'ACTIVE');
    const provider = this.getProvider(key.provider);
    await provider.recoverKey(version.providerKeyId);
  }

  async purgeKey(key: ManagedKeyMetadata, version: ManagedKeyVersion): Promise<void> {
    KeyLifecycleValidator.validateTransition(key.status, 'DESTROYED');
    const provider = this.getProvider(key.provider);
    await provider.purgeKey(version.providerKeyId);
  }

  async destroyKey(key: ManagedKeyMetadata, version: ManagedKeyVersion): Promise<void> {
    KeyLifecycleValidator.validateTransition(key.status, 'DESTROYED');
    const provider = this.getProvider(key.provider);
    await provider.destroyKey(version.providerKeyId);
  }
}
