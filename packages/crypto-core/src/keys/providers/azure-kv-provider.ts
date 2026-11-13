import { KeyProviderCapabilities } from '../types';
import { AzurePlatformKeyProvider } from './azure-platform-provider';

/**
 * Platform keys in AMARACUS's Azure Key Vault (AZURE_KEY_VAULT_URL). Data keys are wrapped
 * with RSA-OAEP-256 under an RSA-3072 vault key.
 */
export class AzureKeyVaultKeyProvider extends AzurePlatformKeyProvider {
  readonly providerId = 'AZURE_KEY_VAULT' as const;
  readonly label = 'Azure Key Vault';
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
    supportsOctHsm: false,
    isHardwareBacked: false,
    isFips140Validated: true,
    supportsPqc: false,
  };
  protected readonly vaultKind = 'KEY_VAULT' as const;
  protected readonly kek = { keyType: 'RSA' as const, keySize: 3072 };
  protected readonly envVarName = 'AZURE_KEY_VAULT_URL';
  protected readonly classicalKeyTypes = 'classical RSA and EC algorithms';

  protected configuredVaultUrl(): string | undefined {
    return process.env.AZURE_KEY_VAULT_URL || process.env.AZURE_VAULT_URL || undefined;
  }
}
