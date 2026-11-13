import { KeyProviderCapabilities } from '../types';
import { AzurePlatformKeyProvider } from './azure-platform-provider';

/**
 * Platform keys in AMARACUS's Azure Managed HSM (AZURE_MANAGED_HSM_URL), a single-tenant
 * FIPS 140 Level 3 HSM pool. Data keys are wrapped with A256KW under a 256-bit oct-HSM key.
 */
export class AzureManagedHsmProvider extends AzurePlatformKeyProvider {
  readonly providerId = 'AZURE_MANAGED_HSM' as const;
  readonly label = 'Azure Managed HSM';
  readonly capabilities: KeyProviderCapabilities = {
    supportedPurposes: ['ENCRYPTION', 'KEY_WRAPPING'],
    supportedAlgorithms: ['AES-256-GCM'],
    supportsKeyGeneration: true,
    supportsRotation: true,
    supportsScheduledDeletion: true,
    supportsEnvelopeEncryption: true,
    supportsAsymmetricSign: false,
    supportsPurge: true,
    supportsRecovery: true,
    supportsOctHsm: true,
    isHardwareBacked: true,
    isFips140Validated: true,
    supportsPqc: false,
  };
  protected readonly vaultKind = 'MANAGED_HSM' as const;
  protected readonly kek = { keyType: 'oct-HSM' as const, keySize: 256 };
  protected readonly envVarName = 'AZURE_MANAGED_HSM_URL';
  protected readonly classicalKeyTypes = 'classical oct-HSM (AES), RSA-HSM, and EC-HSM keys';

  protected configuredVaultUrl(): string | undefined {
    return process.env.AZURE_MANAGED_HSM_URL || undefined;
  }
}
