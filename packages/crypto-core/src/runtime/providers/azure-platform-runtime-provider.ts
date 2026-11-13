/**
 * AMARACUS Cryptographic Infrastructure — runtime adapter for platform Azure keys
 *
 * Runs envelope encrypt/decrypt with managed keys held in AMARACUS's Azure Key Vault or
 * Managed HSM. Key creation, rotation and lifecycle go through the key routes and the
 * KMS service, which record each key against its tenant; the runtime does not create
 * vault keys, so none exist without a database record.
 */

import {
  CryptographicProvider,
  ProviderCapabilityMap,
  ProviderHealthReport,
  ProviderEncryptParams,
  ProviderDecryptParams,
} from '../provider-abstraction';
import { OperationType } from '../operation-model';
import { EncryptedEnvelope } from '../../types';
import { AzurePlatformKeyProvider } from '../../keys/providers/azure-platform-provider';
import { CryptoEngineError } from '../../errors';

export abstract class AzurePlatformRuntimeProvider implements CryptographicProvider {
  public abstract readonly id: string;
  public abstract readonly name: string;
  protected abstract readonly innerProvider: AzurePlatformKeyProvider;

  public get capabilities(): ProviderCapabilityMap {
    return {
      encryption: true,
      decryption: true,
      signing: false,
      verification: false,
      hashing: false,
      hmac: false,
      keyGeneration: false,
      keyRotation: false,
      keyWrapping: true,
      keyUnwrapping: true,
      pqc: false,
      hardwareBacked: this.innerProvider.capabilities.isHardwareBacked,
      fipsValidated: this.innerProvider.capabilities.isFips140Validated,
      supportedAlgorithms: ['AES-256-GCM'],
      supportedPurposes: ['ENCRYPTION', 'KEY_WRAPPING'],
    };
  }

  public async isAvailable(): Promise<boolean> {
    return this.innerProvider.isConfigured();
  }

  public async healthCheck(): Promise<ProviderHealthReport> {
    const health = await this.innerProvider.healthCheck();
    return {
      providerId: this.id,
      name: this.name,
      status: health.status === 'AVAILABLE' ? 'AVAILABLE' : health.isConfigured ? 'DEGRADED' : 'NOT_CONFIGURED',
      message: health.message,
      latencyMs: health.latencyMs,
      capabilities: this.capabilities,
      timestamp: new Date().toISOString(),
    };
  }

  public supportsOperation(operation: OperationType, algorithm?: string): boolean {
    const alg = (algorithm || '').toUpperCase().replace(/_/g, '-');
    if (alg && !this.capabilities.supportedAlgorithms.includes(alg)) return false;
    return operation === 'ENCRYPT' || operation === 'DECRYPT';
  }

  public async encrypt(params: ProviderEncryptParams): Promise<EncryptedEnvelope> {
    if (!params.keyReference) {
      throw new CryptoEngineError('INVALID_KEY', `${this.name} operations require a managed key reference.`);
    }
    return this.innerProvider.encrypt(params.keyReference.providerKeyId, params.plaintext, params.aad);
  }

  public async decrypt(params: ProviderDecryptParams): Promise<Buffer> {
    if (!params.keyReference) {
      throw new CryptoEngineError('INVALID_KEY', `${this.name} operations require a managed key reference.`);
    }
    return this.innerProvider.decrypt(params.keyReference.providerKeyId, params.envelope);
  }

  public async sign(): Promise<Buffer> {
    throw new CryptoEngineError('OPERATION_NOT_SUPPORTED', `${this.name} keys are envelope-encryption keys and cannot sign.`);
  }

  public async verify(): Promise<boolean> {
    throw new CryptoEngineError('OPERATION_NOT_SUPPORTED', `${this.name} keys are envelope-encryption keys and cannot verify.`);
  }
}
