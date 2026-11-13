/**
 * AMARACUS Cryptographic Infrastructure — Capability Discovery
 *
 * Allows callers and the runtime to authoritatively discover supported capabilities,
 * algorithm coverage, hardware backing, and compliance postures across providers.
 */

import { CryptographicProviderRouter, providerRouter } from './provider-router';
import { registry } from '../registry';
import { OperationType } from './operation-model';
import { ProviderCapabilityMap } from './provider-abstraction';

export interface PlatformCapabilitySummary {
  providers: {
    id: string;
    name: string;
    isAvailable: boolean;
    capabilities: ProviderCapabilityMap;
  }[];
  supportedAlgorithmsCount: number;
  pqcSupported: boolean;
  hsmSupported: boolean;
  hardwareBackedCount: number;
  fipsValidatedCount: number;
}

export class CapabilityDiscoveryService {
  constructor(private readonly router: CryptographicProviderRouter = providerRouter) {}

  public async discoverAll(): Promise<PlatformCapabilitySummary> {
    return this.getPlatformCapabilities();
  }

  public getProvider(providerId: string) {
    return this.router.getProvider(providerId);
  }

  /**
   * Checks if an operation and algorithm can be executed by any registered provider.
   */
  public async canExecute(operation: OperationType, algorithm?: string): Promise<boolean> {
    const providers = this.router.getAllProviders();
    for (const provider of providers) {
      if (provider.supportsOperation(operation, algorithm)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if a specific provider supports a target algorithm.
   */
  public isAlgorithmSupportedByProvider(providerId: string, algorithm: string): boolean {
    const provider = this.router.getProvider(providerId);
    if (!provider) return false;
    const normalizedAlg = algorithm.toUpperCase().replace(/_/g, '-');
    return provider.capabilities.supportedAlgorithms.includes(normalizedAlg);
  }

  /**
   * Checks if a key type is supported by a dedicated HSM provider.
   */
  public isHsmSupportedKeyType(keyType: string): boolean {
    const hsmProvider = this.router.getProvider('AZURE_MANAGED_HSM');
    if (!hsmProvider) return false;
    const normalizedType = keyType.toUpperCase();
    return ['RSA-HSM', 'OCT-HSM', 'EC-HSM', 'RSA', 'OCT', 'EC'].includes(normalizedType);
  }

  /**
   * Summarizes all available platform capabilities.
   */
  public async getPlatformCapabilities(): Promise<PlatformCapabilitySummary> {
    const providers = this.router.getAllProviders();
    const providerSummaries = await Promise.all(
      providers.map(async (p) => ({
        id: p.id,
        name: p.name,
        isAvailable: await p.isAvailable(),
        capabilities: p.capabilities,
      }))
    );

    const allAlgs = registry.getAll();
    const pqcSupported = providerSummaries.some((p) => p.capabilities.pqc === true);
    const hsmSupported = providerSummaries.some((p) => p.capabilities.hardwareBacked === true);
    const hardwareBackedCount = providerSummaries.filter((p) => p.capabilities.hardwareBacked === true).length;
    const fipsValidatedCount = providerSummaries.filter((p) => p.capabilities.fipsValidated === true).length;

  return {
      providers: providerSummaries,
      supportedAlgorithmsCount: allAlgs.length,
      pqcSupported,
      hsmSupported,
      hardwareBackedCount,
      fipsValidatedCount,
    };
  }
}

export const capabilityDiscovery = new CapabilityDiscoveryService();
