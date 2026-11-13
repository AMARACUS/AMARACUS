import crypto from 'node:crypto';
import { DefaultAzureCredential, TokenCredential } from '@azure/identity';
import { CryptoEngineError } from '../errors';
import {
  AzureClientFactory,
  sdkAzureClientFactory,
  parseAzureKeyId,
  validateAzureVaultUrl,
  wrapAlgorithmFor,
  mapAzureError,
} from './providers/azure-common';

/**
 * The platform master secret that the LOCAL_DEV provider derives its key-encryption key from.
 *
 * Each slot holds the secret either in plain text or sealed by an Azure Key Vault / Managed
 * HSM key (base64url of the wrapped secret, plus the vault key's versioned id). Sealed, the
 * plain secret exists only in this process's memory after loadPlatformMasterKey() unwraps it.
 * The unwrapped bytes are the same UTF-8 secret string, so sealing keeps existing keys readable.
 *
 * The `previous` slot is set only while rotating: key material wrapped under it can still be
 * unwrapped until the rewrap script has moved everything to the current key.
 */

export type MasterKeySlot = 'current' | 'previous';

const SLOT_ENV: Record<MasterKeySlot, { plain: string; wrapped: string; kekId: string }> = {
  current: {
    plain: 'AMARACUS_LOCAL_MASTER_KEY',
    wrapped: 'AMARACUS_MASTER_KEY_WRAPPED',
    kekId: 'AMARACUS_MASTER_KEY_KEK_ID',
  },
  previous: {
    plain: 'AMARACUS_PREVIOUS_MASTER_KEY',
    wrapped: 'AMARACUS_PREVIOUS_MASTER_KEY_WRAPPED',
    kekId: 'AMARACUS_PREVIOUS_MASTER_KEY_KEK_ID',
  },
};

const unsealed: Record<MasterKeySlot, string | null> = { current: null, previous: null };

export function masterKeyEnvNames(slot: MasterKeySlot) {
  return SLOT_ENV[slot];
}

export function isMasterKeySealed(slot: MasterKeySlot = 'current'): boolean {
  const env = SLOT_ENV[slot];
  return Boolean(process.env[env.wrapped] || process.env[env.kekId]);
}

function slotConfigured(slot: MasterKeySlot): boolean {
  return isMasterKeySealed(slot) || Boolean(process.env[SLOT_ENV[slot].plain]);
}

function slotSecret(slot: MasterKeySlot): string | undefined {
  if (unsealed[slot]) return unsealed[slot]!;
  if (isMasterKeySealed(slot)) return undefined;
  return process.env[SLOT_ENV[slot].plain] || undefined;
}

/** The current master secret; undefined if it is sealed and not yet unsealed, or not set. */
export function getPlatformMasterSecret(): string | undefined {
  return slotSecret('current');
}

/** The previous master secret during a rotation; undefined otherwise. */
export function getPreviousPlatformMasterSecret(): string | undefined {
  return slotSecret('previous');
}

/** Whether a rotation is in progress (a previous master key is configured). */
export function isMasterKeyRotationInProgress(): boolean {
  return slotConfigured('previous');
}

/** The key-encryption key derived from a master secret. */
export function deriveMasterKek(secret: string): Buffer {
  return crypto.createHash('sha256').update(secret).digest();
}

/**
 * A short, non-secret identifier for a KEK, stored next to each wrapped blob so the right
 * master key is chosen on unwrap. An HMAC, so it reveals nothing about the key.
 */
export function masterKekId(kek: Buffer): string {
  return crypto.createHmac('sha256', kek).update('amaracus-master-kek-id').digest('hex').slice(0, 16);
}

async function unsealSlot(
  slot: MasterKeySlot,
  clients: AzureClientFactory,
  credential: () => TokenCredential
): Promise<'plain' | 'sealed' | 'absent'> {
  const env = SLOT_ENV[slot];
  if (!isMasterKeySealed(slot)) return process.env[env.plain] ? 'plain' : 'absent';

  const wrapped = process.env[env.wrapped]?.trim();
  const keyId = process.env[env.kekId]?.trim();
  if (!wrapped || !keyId) {
    throw new CryptoEngineError(
      'PROVIDER_NOT_CONFIGURED',
      `Sealed master key needs both ${env.wrapped} and ${env.kekId}.`,
      503
    );
  }
  if (process.env[env.plain]) {
    throw new CryptoEngineError(
      'PROVIDER_NOT_CONFIGURED',
      `${env.plain} is set alongside the sealed master key. Remove the plain variable.`,
      503
    );
  }

  const { vaultUrl, name, version } = parseAzureKeyId(keyId);
  if (!version) {
    throw new CryptoEngineError('PROVIDER_NOT_CONFIGURED', `${env.kekId} must name a key version.`, 503);
  }
  const origin = validateAzureVaultUrl(vaultUrl).origin;
  const cred = credential();

  try {
    const key = await clients.keyClient(origin, cred).getKey(name, { version });
    const result = await clients
      .cryptoClient(key.id!, cred)
      .unwrapKey(wrapAlgorithmFor(key.keyType), Buffer.from(wrapped, 'base64url'));
    const secret = Buffer.from(result.result).toString('utf8');
    if (secret.length < 32) {
      throw new CryptoEngineError('PROVIDER_NOT_CONFIGURED', 'Unsealed master key is shorter than 32 characters.', 503);
    }
    unsealed[slot] = secret;
    return 'sealed';
  } catch (err) {
    throw mapAzureError(err, `unsealing the ${slot} platform master key`);
  }
}

/**
 * Unwraps whichever master keys are sealed, using the platform's Azure identity. Throws if a
 * sealed pair is incomplete, Azure refuses, or the previous key equals the current one.
 */
export async function loadPlatformMasterKey(
  options: { clients?: AzureClientFactory; credential?: TokenCredential } = {}
): Promise<'plain' | 'sealed'> {
  const clients = options.clients || sdkAzureClientFactory;
  let credential = options.credential || null;
  const getCredential = () => (credential ||= new DefaultAzureCredential());

  const current = await unsealSlot('current', clients, getCredential);
  await unsealSlot('previous', clients, getCredential);

  const currentSecret = getPlatformMasterSecret();
  const previousSecret = getPreviousPlatformMasterSecret();
  if (currentSecret && previousSecret && currentSecret === previousSecret) {
    throw new CryptoEngineError(
      'PROVIDER_NOT_CONFIGURED',
      'The previous master key is the same as the current one; set a new current key to rotate.',
      503
    );
  }
  return current === 'sealed' ? 'sealed' : 'plain';
}

/** Seals a master secret with a vault key; used by the owner's one-off sealing script. */
export async function sealPlatformMasterKey(
  secret: string,
  keyId: string,
  options: { clients?: AzureClientFactory; credential?: TokenCredential } = {}
): Promise<{ wrapped: string; keyId: string }> {
  const { vaultUrl, name, version } = parseAzureKeyId(keyId);
  const clients = options.clients || sdkAzureClientFactory;
  const credential = options.credential || new DefaultAzureCredential();
  try {
    const key = await clients.keyClient(validateAzureVaultUrl(vaultUrl).origin, credential).getKey(name, { version });
    const result = await clients
      .cryptoClient(key.id!, credential)
      .wrapKey(wrapAlgorithmFor(key.keyType), Buffer.from(secret, 'utf8'));
    return { wrapped: Buffer.from(result.result).toString('base64url'), keyId: key.id! };
  } catch (err) {
    throw mapAzureError(err, 'sealing the platform master key');
  }
}

/** Test hook: forget unsealed values. */
export function resetPlatformMasterKeyForTests(): void {
  unsealed.current = null;
  unsealed.previous = null;
}
