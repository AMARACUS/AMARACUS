/**
 * AMARACUS Cryptographic Infrastructure — Azure Key Vault runtime provider
 *
 * Envelope encrypt/decrypt with platform keys in AMARACUS's Azure Key Vault.
 */

import { AzureKeyVaultKeyProvider } from '../../keys/providers/azure-kv-provider';
import { AzurePlatformRuntimeProvider } from './azure-platform-runtime-provider';

export class AzureKeyVaultCryptographicProvider extends AzurePlatformRuntimeProvider {
  public readonly id = 'AZURE_KEY_VAULT';
  public readonly name = 'Azure Key Vault Cryptographic Provider';
  protected readonly innerProvider = new AzureKeyVaultKeyProvider();
}
