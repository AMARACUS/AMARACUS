/**
 * AMARACUS Cryptographic Infrastructure — Unified Key Abstraction
 *
 * Applications reference logical keys rather than manipulating provider-specific
 * identifiers or raw key material. Decouples keys from specific cloud providers.
 */

import { AlgorithmId } from '../types';
import { KeyPurpose, KeyLifecycleStatus, KeyProviderType } from '../keys/types';

export interface KeyVersionReference {
  version: number;
  providerKeyId: string;
  status: string;
  publicKey?: string | null;
  encryptedKeyMaterial?: string | null;
}

export interface KeyReference {
  /** AMARACUS logical key ID (canonical reference) */
  id: string;
  name: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  algorithm: AlgorithmId | string;
  purpose: KeyPurpose | string;
  provider: KeyProviderType | string;
  /** Provider's internal reference (e.g. Azure Key URL, HSM Key Name, or Local KEK ID) */
  providerKeyId: string;
  currentVersion: number | string;
  status: KeyLifecycleStatus | string;
  isHsmBacked: boolean;
  isCustomerManaged: boolean;
  publicKey?: string | null;
  encryptedKeyMaterial?: string | null;
  metadata?: Record<string, any> | null;
  versions?: KeyVersionReference[];
}

export interface KeyResolver {
  /**
   * Resolves a logical key ID or name within a tenant context to an authoritative KeyReference.
   * Fails closed if the key does not exist or does not belong to the tenant.
   */
  resolveKey(keyIdOrName: string, organizationId: string, projectId?: string | null, environmentId?: string | null): Promise<KeyReference | null>;
}
