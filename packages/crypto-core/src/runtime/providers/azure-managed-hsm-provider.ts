/**
 * AMARACUS Cryptographic Infrastructure — Azure Managed HSM runtime provider
 *
 * Envelope encrypt/decrypt with platform keys in AMARACUS's Azure Managed HSM.
 */

import { AzureManagedHsmProvider } from '../../keys/providers/azure-managed-hsm-provider';
import { AzurePlatformRuntimeProvider } from './azure-platform-runtime-provider';

export class AzureManagedHsmCryptographicProvider extends AzurePlatformRuntimeProvider {
  public readonly id = 'AZURE_MANAGED_HSM';
  public readonly name = 'Azure Managed HSM Provider';
  protected readonly innerProvider = new AzureManagedHsmProvider();
}
