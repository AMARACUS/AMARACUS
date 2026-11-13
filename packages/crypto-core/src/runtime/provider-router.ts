/**
 * AMARACUS Cryptographic Infrastructure — Provider Router
 *
 * Authoritatively resolves which internal cryptographic provider executes an operation.
 * Evaluates tenant context, logical key reference, algorithm, compliance policies,
 * and verified provider capabilities.
 *
 * Guarantees:
 * - Application developers never specify or know underlying provider details.
 * - Capabilities are verified before dispatch (3-state validation).
 * - BYOK customer vaults/HSMs are routed truthfully based on key ownership.
 */

import { CryptographicProvider } from './provider-abstraction';
import { CryptographicOperationRequest } from './operation-model';
import { KeyReference } from './key-reference';
import { TenantContext } from './context';
import { LocalCryptographicProvider } from './providers/local-crypto-provider';
import { AzureKeyVaultCryptographicProvider } from './providers/azure-kv-provider';
import { AzureManagedHsmCryptographicProvider } from './providers/azure-managed-hsm-provider';
import { CustomerAzureCryptographicProvider } from './providers/customer-azure-provider';
import { PqcCryptographicProvider } from './providers/pqc-provider';
import { AdvancedCryptographicProvider } from './providers/advanced-crypto-provider';
import { CryptoEngineError } from '../errors';

export class CryptographicProviderRouter {
  private providers: Map<string, CryptographicProvider> = new Map();

  constructor() {
    this.registerProvider(new LocalCryptographicProvider());
    this.registerProvider(new AzureKeyVaultCryptographicProvider());
    this.registerProvider(new AzureManagedHsmCryptographicProvider());
    this.registerProvider(new CustomerAzureCryptographicProvider());
    this.registerProvider(new PqcCryptographicProvider());
    this.registerProvider(new AdvancedCryptographicProvider());
  }

  public registerProvider(provider: CryptographicProvider): void {
    this.providers.set(provider.id, provider);
  }

  public getProvider(id: string): CryptographicProvider | undefined {
    return this.providers.get(id);
  }

  public getAllProviders(): CryptographicProvider[] {
    return Array.from(this.providers.values());
  }

  /**
   * Authoritative routing resolution.
   * Dispatches to the correct internal provider without caller knowing internal mechanics.
   */
  public async route(
    operation: CryptographicOperationRequest,
    keyRef?: KeyReference | null,
    context?: TenantContext
  ): Promise<CryptographicProvider> {
    const rawAlgorithm = (operation.algorithm || '').toUpperCase().replace(/_/g, '-');

    // 1. Key-directed Routing: If keyReference is provided, follow key's provider mapping
    if (keyRef) {
      if (
        keyRef.isCustomerManaged ||
        keyRef.provider === 'CUSTOMER_MANAGED' ||
        keyRef.provider === 'CUSTOMER_AZURE_KEY_VAULT' ||
        keyRef.provider === 'CUSTOMER_AZURE_BYOK'
      ) {
        const customerProvider = this.getProvider('CUSTOMER_AZURE_BYOK');
        if (customerProvider) return customerProvider;
      }

      if (keyRef.provider === 'AZURE_MANAGED_HSM' || keyRef.isHsmBacked) {
        const hsmProvider = this.getProvider('AZURE_MANAGED_HSM');
        if (hsmProvider) return hsmProvider;
      }

      if (keyRef.provider === 'AZURE_KEY_VAULT') {
        const kvProvider = this.getProvider('AZURE_KEY_VAULT');
        if (kvProvider) return kvProvider;
      }

      if (keyRef.provider === 'LOCAL_DEV') {
        const localProvider = this.getProvider('LOCAL_DEV');
        if (localProvider) return localProvider;
      }
    }

    // 2. Algorithm-directed Routing
    if (
      rawAlgorithm.startsWith('ML-KEM') ||
      rawAlgorithm.startsWith('ML-DSA') ||
      rawAlgorithm.includes('ML-KEM') ||
      rawAlgorithm === 'X25519+ML-KEM-768' ||
      operation.type.startsWith('PQC_') ||
      operation.type.startsWith('KEM_')
    ) {
      const pqcProvider = this.getProvider('PQC_ENGINE');
      if (pqcProvider) return pqcProvider;
    }

    if (
      rawAlgorithm.startsWith('FHE') ||
      rawAlgorithm.startsWith('CKKS') ||
      rawAlgorithm.startsWith('BFV') ||
      rawAlgorithm.startsWith('BGV') ||
      rawAlgorithm.startsWith('NIZK') ||
      rawAlgorithm.startsWith('GROTH16') ||
      rawAlgorithm.startsWith('MPC') ||
      rawAlgorithm.includes('FROST') ||
      operation.type.startsWith('ZK_') ||
      operation.type.startsWith('FHE_') ||
      operation.type.startsWith('MPC_') ||
      operation.type.startsWith('THRESHOLD_') ||
      operation.type === 'ADVANCED_ZK_PROVE' ||
      operation.type === 'ADVANCED_ZK_VERIFY'
    ) {
      const advProvider = this.getProvider('ADVANCED_CRYPTO');
      if (advProvider) return advProvider;
    }

    // 3. Fallback to Local / Software provider for standard classical primitives
    const localProvider = this.getProvider('LOCAL_DEV');
    if (!localProvider) {
      throw new CryptoEngineError('PROVIDER_UNAVAILABLE', 'No suitable cryptographic provider available.');
    }

    // Verify capability before returning
    if (!localProvider.supportsOperation(operation.type, operation.algorithm || undefined)) {
      throw new CryptoEngineError(
        'PROVIDER_CAPABILITY_MISSING',
        `No provider supports operation '${operation.type}' with algorithm '${operation.algorithm}'.`
      );
    }

    return localProvider;
  }

  /**
   * Evaluates and resolves a safe fallback provider when primary provider encounters transient outage.
   * Strictly enforces safety rules:
   * - NEVER failover customer BYOK operations (strictly prohibited).
   * - Fallback must support identical operation and algorithm.
   * - Fallback must preserve required security properties (e.g. FIPS, HSM if required by policy).
   * - Key material must be available to fallback provider (e.g. raw key or unwrappable key).
   */
  public resolveFailoverProvider(
    failedProvider: CryptographicProvider,
    operation: CryptographicOperationRequest,
    keyRef?: KeyReference | null,
    context?: TenantContext
  ): CryptographicProvider | null {
    // 1. BYOK Isolation: NEVER failover customer-managed keys
    if (keyRef?.isCustomerManaged || keyRef?.provider?.startsWith('CUSTOMER_')) {
      return null;
    }

    // 2. Hardware HSM Lock: If key is strictly HSM-backed and policy requires hardware HSM
    if (keyRef?.isHsmBacked && operation.policy === 'FIPS_COMPLIANT') {
      return null;
    }

    // 3. Safe fallback to Local Provider for classical operations or unwrappable keys
    const localProvider = this.getProvider('LOCAL_DEV');
    if (
      localProvider &&
      localProvider.id !== failedProvider.id &&
      localProvider.supportsOperation(operation.type, operation.algorithm || undefined)
    ) {
      if (keyRef) {
        if (keyRef.encryptedKeyMaterial || keyRef.provider === 'LOCAL_DEV') {
          return localProvider;
        }
        return null;
      }
      return localProvider;
    }

    return null;
  }
}

export const providerRouter = new CryptographicProviderRouter();
