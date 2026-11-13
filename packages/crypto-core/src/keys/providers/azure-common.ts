import crypto from 'node:crypto';
import type { TokenCredential } from '@azure/identity';
import { KeyClient, CryptographyClient, KeyVaultKey, parseKeyVaultKeyIdentifier } from '@azure/keyvault-keys';
import { CryptoEngineError } from '../../errors';

/**
 * Shared Azure Key Vault / Managed HSM rules for the platform providers and BYOK:
 * which hosts may be contacted, how keys are named, and which wrap and signature
 * algorithms each key type may use.
 */

export type AzureVaultKind = 'KEY_VAULT' | 'MANAGED_HSM';

// Public, China and US Government clouds. Anything else is refused before any credential is used,
// because the Azure SDK sends a bearer token to whatever host it is given.
const VAULT_HOST_SUFFIXES: Record<AzureVaultKind, string[]> = {
  KEY_VAULT: ['.vault.azure.net', '.vault.azure.cn', '.vault.usgovcloudapi.net'],
  MANAGED_HSM: ['.managedhsm.azure.net', '.managedhsm.azure.cn', '.managedhsm.usgovcloudapi.net'],
};
// Key Vault and Managed HSM names: 3-24 characters, letters, digits and hyphens, starting with a letter.
const VAULT_NAME = /^[a-z][a-z0-9-]{1,22}[a-z0-9]$/;

/**
 * Returns the vault origin ("https://name.vault.azure.net/") or throws INVALID_INPUT.
 * Without `kind`, either kind is accepted and reported.
 */
export function validateAzureVaultUrl(
  url: string,
  kind?: AzureVaultKind
): { origin: string; kind: AzureVaultKind } {
  let parsed: URL;
  try {
    parsed = new URL(String(url).trim());
  } catch {
    throw new CryptoEngineError('INVALID_INPUT', 'Vault URL is not a valid URL.');
  }
  const host = parsed.hostname.toLowerCase();
  const kinds: AzureVaultKind[] = kind ? [kind] : ['KEY_VAULT', 'MANAGED_HSM'];
  const matched = kinds.find((k) => VAULT_HOST_SUFFIXES[k].some((suffix) => host.endsWith(suffix)));
  const vaultName = matched ? host.slice(0, host.indexOf('.')) : '';

  if (
    parsed.protocol !== 'https:' ||
    parsed.port !== '' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    (parsed.pathname !== '/' && parsed.pathname !== '') ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    !matched ||
    host.split('.').length !== VAULT_HOST_SUFFIXES[matched][0].split('.').length ||
    !VAULT_NAME.test(vaultName)
  ) {
    const allowed = kinds.flatMap((k) => VAULT_HOST_SUFFIXES[k].map((s) => `https://<name>${s}/`)).join(', ');
    throw new CryptoEngineError('INVALID_INPUT', `Vault URL must be an Azure vault endpoint: ${allowed}`);
  }
  return { origin: `https://${host}/`, kind: matched };
}

/**
 * Azure key name for a platform-managed key: tenant prefix, readable name, random suffix.
 * The org prefix keeps tenants apart in a shared vault; the suffix avoids colliding with a
 * soft-deleted key of the same name. Azure allows 1-127 characters of [0-9a-zA-Z-].
 */
export function tenantScopedKeyName(organizationId: string, name: string): string {
  const slug = (value: string, max: number) =>
    value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, max) || 'x';
  return `am-${slug(organizationId, 40)}-${slug(name, 60)}-${crypto.randomBytes(4).toString('hex')}`;
}

/** Splits a key id URL into vault, name and version. */
export function parseAzureKeyId(keyId: string): { vaultUrl: string; name: string; version?: string } {
  try {
    const parsed = parseKeyVaultKeyIdentifier(keyId);
    return { vaultUrl: parsed.vaultUrl, name: parsed.name, version: parsed.version };
  } catch {
    throw new CryptoEngineError('INVALID_KEY', 'Stored provider key id is not an Azure key identifier.');
  }
}

export type AzureWrapAlgorithm = 'RSA-OAEP-256' | 'A256KW';

/** The only wrap algorithm used, and accepted on unwrap, for each key type. */
export function wrapAlgorithmFor(keyType: string | undefined): AzureWrapAlgorithm {
  const kty = (keyType || '').toUpperCase();
  if (kty === 'RSA' || kty === 'RSA-HSM') return 'RSA-OAEP-256';
  if (kty === 'OCT' || kty === 'OCT-HSM') return 'A256KW';
  throw new CryptoEngineError(
    'OPERATION_NOT_SUPPORTED',
    `Azure key type '${keyType || 'unknown'}' cannot wrap data keys; use an RSA or oct-HSM key.`
  );
}

/**
 * Checks an envelope's wrap algorithm against the key before unwrapping. Envelopes without
 * one predate the field and were always RSA-OAEP-256.
 */
export function assertUnwrapAlgorithm(envelopeAlg: string | undefined, keyType: string | undefined): AzureWrapAlgorithm {
  const expected = wrapAlgorithmFor(keyType);
  const given = envelopeAlg || 'RSA-OAEP-256';
  if (given !== expected) {
    throw new CryptoEngineError(
      'INVALID_INPUT',
      `Envelope wrap algorithm '${given}' is not allowed for this key; expected '${expected}'.`
    );
  }
  return expected;
}

/** Signature algorithm and digest for a key: RS256 for RSA, ES256/384/512 by EC curve. */
export function signatureAlgorithmFor(key: KeyVaultKey): { algorithm: string; hash: 'sha256' | 'sha384' | 'sha512' } {
  const kty = (key.keyType || '').toUpperCase();
  if (kty === 'RSA' || kty === 'RSA-HSM') return { algorithm: 'RS256', hash: 'sha256' };
  if (kty === 'EC' || kty === 'EC-HSM') {
    switch (key.key?.crv) {
      case 'P-256':
        return { algorithm: 'ES256', hash: 'sha256' };
      case 'P-384':
        return { algorithm: 'ES384', hash: 'sha384' };
      case 'P-521':
        return { algorithm: 'ES512', hash: 'sha512' };
    }
  }
  throw new CryptoEngineError('OPERATION_NOT_SUPPORTED', `Azure key type '${key.keyType || 'unknown'}' cannot sign.`);
}

export type AzureKeyClient = Pick<
  KeyClient,
  | 'createKey'
  | 'getKey'
  | 'rotateKey'
  | 'updateKeyProperties'
  | 'beginDeleteKey'
  | 'beginRecoverDeletedKey'
  | 'purgeDeletedKey'
  | 'listPropertiesOfKeys'
  | 'listPropertiesOfKeyVersions'
>;
export type AzureCryptoClient = Pick<CryptographyClient, 'wrapKey' | 'unwrapKey' | 'sign' | 'verify'>;

/** How providers reach Azure. Tests pass fakes; production uses the SDK. */
export interface AzureClientFactory {
  keyClient(vaultUrl: string, credential: TokenCredential): AzureKeyClient;
  cryptoClient(keyId: string, credential: TokenCredential): AzureCryptoClient;
}

export const sdkAzureClientFactory: AzureClientFactory = {
  keyClient: (vaultUrl, credential) => new KeyClient(vaultUrl, credential),
  cryptoClient: (keyId, credential) => new CryptographyClient(keyId, credential),
};

/**
 * Maps an Azure SDK error from the platform's own vault to a CryptoEngineError. These are
 * server-side failures (the platform identity, vault or network), so they are 5xx, not 400.
 */
export function mapAzureError(err: any, action: string): CryptoEngineError {
  if (err instanceof CryptoEngineError) return err;
  const status = err?.statusCode;
  if (status === 401 || status === 403) {
    return new CryptoEngineError('AUTHORIZATION_FAILED', `Azure denied ${action}: the platform identity lacks the required key permission.`, 502);
  }
  if (status === 404) {
    return new CryptoEngineError('KEY_NOT_FOUND', `Azure could not find the key for ${action}.`, 502);
  }
  return new CryptoEngineError('PROVIDER_UNAVAILABLE', `Azure ${action} failed: ${err?.message || 'unknown error'}`, 503);
}

/** Envelope AES-256-GCM under a fresh DEK; the caller wraps the returned DEK and must wipe it. */
export function sealWithFreshDek(plaintext: Buffer, aad?: Buffer) {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
  if (aad && aad.length > 0) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { dek, iv, ct, tag: cipher.getAuthTag() };
}

/** Opens an AES-256-GCM envelope with an unwrapped DEK, wiping the DEK either way. */
export function openWithDek(dek: Buffer, iv: Buffer, ct: Buffer, tag: Buffer, aad?: Buffer): Buffer {
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
    decipher.setAuthTag(tag);
    if (aad && aad.length > 0) decipher.setAAD(aad);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new CryptoEngineError(
      'AUTHENTICATION_FAILED',
      'Envelope decryption failed: payload tampered or authentication tag mismatch.'
    );
  } finally {
    dek.fill(0);
  }
}
