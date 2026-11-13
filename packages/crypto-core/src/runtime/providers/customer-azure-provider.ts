/**
 * AMARACUS Cryptographic Infrastructure — Customer Azure (BYOK) Provider
 *
 * Implements CryptographicProvider wrapping customer-managed Azure Key Vault
 * and Azure Managed HSM instances. Supports multi-tenant BYOK credentials,
 * capability discovery, and truthful routing.
 */

import {
  CryptographicProvider,
  ProviderCapabilityMap,
  ProviderHealthReport,
  ProviderEncryptParams,
  ProviderDecryptParams,
  ProviderSignParams,
  ProviderVerifyParams,
} from '../provider-abstraction';
import { OperationType } from '../operation-model';
import { KeyReference } from '../key-reference';
import { EncryptedEnvelope } from '../../types';
import { CustomerAzureKeyVaultProvider } from '../../keys/providers/customer-azure-provider';
import { CryptoEngineError } from '../../errors';

export class CustomerAzureCryptographicProvider implements CryptographicProvider {
  public readonly id = 'CUSTOMER_AZURE_BYOK';
  public readonly name = 'Customer Azure BYOK / Managed HSM Provider';

  public readonly capabilities: ProviderCapabilityMap = {
    encryption: true,
    decryption: true,
    signing: true,
    verification: true,
    hashing: false,
    hmac: false,
    keyGeneration: false, // BYOK keys are provisioned in customer's Azure tenant
    keyRotation: false,
    keyWrapping: true,
    keyUnwrapping: true,
    pqc: false,
    hardwareBacked: true, // Configurable per vault (Managed HSM vs Standard Vault)
    fipsValidated: true,
    // Envelope encryption (AES-256-GCM under an RSA-OAEP-256 or A256KW-wrapped data key) and
    // signing with RS256 / ES256 / ES384 / ES512, chosen by the customer key's type.
    supportedAlgorithms: ['AES-256-GCM', 'RS256', 'ES256', 'ES384', 'ES512'],
    supportedPurposes: ['ENCRYPTION', 'SIGNING', 'KEY_WRAPPING'],
  };

  private providerInstances: Map<string, CustomerAzureKeyVaultProvider> = new Map();

  /**
   * Registers a customer-specific Azure Key Vault / Managed HSM connection.
   */
  public registerCustomerInstance(providerId: string, instance: CustomerAzureKeyVaultProvider): void {
    this.providerInstances.set(providerId, instance);
  }

  public getCustomerInstance(providerId: string): CustomerAzureKeyVaultProvider | undefined {
    return this.providerInstances.get(providerId);
  }

  public async isAvailable(): Promise<boolean> {
    return this.providerInstances.size > 0;
  }

  public async healthCheck(): Promise<ProviderHealthReport> {
    return {
      providerId: this.id,
      name: this.name,
      status: this.providerInstances.size > 0 ? 'AVAILABLE' : 'NOT_CONFIGURED',
      message: `Customer Azure BYOK router managing ${this.providerInstances.size} active provider connection(s).`,
      capabilities: this.capabilities,
      timestamp: new Date().toISOString(),
    };
  }

  public supportsOperation(operation: OperationType, algorithm?: string): boolean {
    const alg = (algorithm || '').toUpperCase().replace(/_/g, '-');
    if (alg && !this.capabilities.supportedAlgorithms.includes(alg)) {
      return false;
    }
    switch (operation) {
      case 'ENCRYPT':
      case 'DECRYPT':
      case 'SIGN':
      case 'VERIFY':
      case 'WRAP_KEY':
      case 'UNWRAP_KEY':
        return true;
      default:
        return false;
    }
  }

  public async encrypt(params: ProviderEncryptParams): Promise<EncryptedEnvelope> {
    if (!params.keyReference) {
      throw new CryptoEngineError('INVALID_KEY', 'BYOK operations require an authoritative KeyReference.');
    }
    const instance = this.resolveInstance(params.keyReference);
    return instance.encrypt(
      params.keyReference.providerKeyId,
      params.plaintext,
      params.aad,
      String(params.version || params.keyReference.currentVersion)
    );
  }

  public async decrypt(params: ProviderDecryptParams): Promise<Buffer> {
    if (!params.keyReference) {
      throw new CryptoEngineError('INVALID_KEY', 'BYOK operations require an authoritative KeyReference.');
    }
    const instance = this.resolveInstance(params.keyReference);
    return instance.decrypt(
      params.keyReference.providerKeyId,
      params.envelope,
      String(params.version || params.keyReference.currentVersion)
    );
  }

  public async sign(params: ProviderSignParams): Promise<Buffer> {
    if (!params.keyReference) {
      throw new CryptoEngineError('INVALID_KEY', 'BYOK operations require an authoritative KeyReference.');
    }
    const instance = this.resolveInstance(params.keyReference);
    return instance.sign(
      params.keyReference.providerKeyId,
      params.data,
      String(params.version || params.keyReference.currentVersion)
    );
  }

  public async verify(params: ProviderVerifyParams): Promise<boolean> {
    if (!params.keyReference) {
      throw new CryptoEngineError('INVALID_KEY', 'BYOK operations require an authoritative KeyReference.');
    }
    const instance = this.resolveInstance(params.keyReference);
    return instance.verify(
      params.keyReference.providerKeyId,
      params.data,
      params.signature,
      String(params.version || params.keyReference.currentVersion)
    );
  }

  private resolveInstance(keyRef: KeyReference): CustomerAzureKeyVaultProvider {
    const providerInstanceId = (keyRef.metadata?.providerId as string) || keyRef.provider;
    // Only connections registered with the customer's own credentials are used. Building one
    // from key metadata alone would fall back to the platform's Azure identity.
    const instance = this.providerInstances.get(providerInstanceId);
    if (!instance) {
      throw new CryptoEngineError('PROVIDER_UNAVAILABLE', `Customer BYOK provider instance '${providerInstanceId}' not connected or unavailable.`);
    }
    return instance;
  }
}
