import crypto from 'node:crypto';
import { DefaultAzureCredential, TokenCredential } from '@azure/identity';
import type { KeyVaultKey } from '@azure/keyvault-keys';
import {
  KeyProvider,
  KeyProviderCapabilities,
  ProviderHealth,
  CreateKeyParams,
  ProviderKeyResult,
  RotateKeyParams,
} from '../types';
import { EncryptedEnvelope } from '../../types';
import { CryptoEngineError } from '../../errors';
import {
  AzureClientFactory,
  AzureVaultKind,
  sdkAzureClientFactory,
  validateAzureVaultUrl,
  tenantScopedKeyName,
  parseAzureKeyId,
  wrapAlgorithmFor,
  assertUnwrapAlgorithm,
  signatureAlgorithmFor,
  mapAzureError,
  sealWithFreshDek,
  openWithDek,
} from './azure-common';

/**
 * Keys AMARACUS holds in its own Azure Key Vault or Managed HSM, reached with the
 * platform's identity (DefaultAzureCredential). Customer vaults go through BYOK
 * (customer-azure-provider) with the customer's credentials instead.
 *
 * Only envelope encryption is offered: data is sealed with AES-256-GCM under a fresh
 * data key, and the vault key wraps that data key. The vault key never leaves Azure.
 */
export abstract class AzurePlatformKeyProvider implements KeyProvider {
  abstract readonly providerId: 'AZURE_KEY_VAULT' | 'AZURE_MANAGED_HSM';
  abstract readonly label: string;
  abstract readonly capabilities: KeyProviderCapabilities;
  protected abstract readonly vaultKind: AzureVaultKind;
  /** Vault key used to wrap data keys. */
  protected abstract readonly kek: { keyType: 'RSA' | 'oct-HSM'; keySize: number };
  protected abstract configuredVaultUrl(): string | undefined;
  protected abstract readonly envVarName: string;
  /** What the service itself offers, for the post-quantum refusal message. */
  protected abstract readonly classicalKeyTypes: string;

  private credential: TokenCredential | null;
  // Key metadata by versioned key id. A version's type and material never change.
  private readonly keyCache = new Map<string, KeyVaultKey>();

  constructor(
    private readonly clients: AzureClientFactory = sdkAzureClientFactory,
    credential?: TokenCredential
  ) {
    this.credential = credential || null;
  }

  isConfigured(): boolean {
    return Boolean(this.configuredVaultUrl());
  }

  private getCredential(): TokenCredential {
    if (!this.credential) this.credential = new DefaultAzureCredential();
    return this.credential;
  }

  private vaultOrigin(): string {
    const url = this.configuredVaultUrl();
    if (!url) {
      throw new CryptoEngineError('PROVIDER_UNCONFIGURED', `${this.label} is not configured: set ${this.envVarName}.`, 503);
    }
    try {
      return validateAzureVaultUrl(url, this.vaultKind).origin;
    } catch (err: any) {
      throw new CryptoEngineError('PROVIDER_UNCONFIGURED', `${this.envVarName} is invalid. ${err.message}`, 503);
    }
  }

  private keyClient() {
    return this.clients.keyClient(this.vaultOrigin(), this.getCredential());
  }

  /** Reads a key version's metadata, refusing ids that point outside the configured vault. */
  private async describeKey(providerKeyId: string): Promise<KeyVaultKey> {
    const cached = this.keyCache.get(providerKeyId);
    if (cached) return cached;
    const { vaultUrl, name, version } = parseAzureKeyId(providerKeyId);
    if (validateAzureVaultUrl(vaultUrl, this.vaultKind).origin !== this.vaultOrigin()) {
      throw new CryptoEngineError('INVALID_KEY', 'Stored key id belongs to a different vault than the one configured.');
    }
    try {
      const key = await this.keyClient().getKey(name, { version });
      this.keyCache.set(providerKeyId, key);
      return key;
    } catch (err) {
      throw mapAzureError(err, 'reading the key');
    }
  }

  async healthCheck(): Promise<ProviderHealth> {
    if (!this.isConfigured()) {
      return {
        provider: this.providerId,
        label: this.label,
        status: 'NOT_CONFIGURED',
        isConfigured: false,
        message: `${this.envVarName} is not set, so ${this.label} is unavailable.`,
      };
    }
    const start = Date.now();
    try {
      await this.keyClient().listPropertiesOfKeys().next();
      return {
        provider: this.providerId,
        label: this.label,
        status: 'AVAILABLE',
        isConfigured: true,
        latencyMs: Date.now() - start,
        message: `Reached ${this.vaultOrigin()} with the platform identity.`,
        details: { vaultUrl: this.vaultOrigin(), hardwareBacked: this.capabilities.isHardwareBacked },
      };
    } catch (err: any) {
      return {
        provider: this.providerId,
        label: this.label,
        status: 'UNAVAILABLE',
        isConfigured: true,
        message: mapAzureError(err, 'the connectivity check').message,
      };
    }
  }

  async createKey(params: CreateKeyParams): Promise<ProviderKeyResult> {
    const alg = String(params.algorithm);
    if (alg.startsWith('ML-KEM-') || alg.startsWith('ML-DSA-') || alg === 'X25519+ML-KEM-768') {
      throw new CryptoEngineError(
        'OPERATION_NOT_SUPPORTED',
        `${this.label} does not support Post-Quantum Cryptography algorithm '${alg}'. ` +
          `${this.label} currently only supports ${this.classicalKeyTypes}.`
      );
    }
    if (
      !(params.purpose === 'ENCRYPTION' || params.purpose === 'KEY_WRAPPING') ||
      params.algorithm !== 'AES-256-GCM'
    ) {
      throw new CryptoEngineError(
        'OPERATION_NOT_SUPPORTED',
        `${this.label} keys support envelope encryption only (purpose ENCRYPTION or KEY_WRAPPING, ` +
          `algorithm AES-256-GCM). '${params.algorithm}' for ${params.purpose} is not offered with Azure-held keys.`
      );
    }

    const azureName = tenantScopedKeyName(params.organizationId, params.name);
    try {
      const created = await this.keyClient().createKey(azureName, this.kek.keyType, {
        keySize: this.kek.keySize,
        keyOps: ['wrapKey', 'unwrapKey'],
        tags: {
          organizationId: params.organizationId,
          projectId: params.projectId,
          environmentId: params.environmentId,
        },
      });
      if (!created.id) throw new Error('Azure returned no key id');
      this.keyCache.set(created.id, created);
      return {
        providerKeyId: created.id,
        keyFingerprint: crypto.createHash('sha256').update(created.id).digest('hex').substring(0, 16),
        metadata: {
          vaultUrl: this.vaultOrigin(),
          azureKeyName: azureName,
          keyType: this.kek.keyType,
          keySize: this.kek.keySize,
          wrapAlg: wrapAlgorithmFor(this.kek.keyType),
        },
      };
    } catch (err) {
      throw mapAzureError(err, 'key creation');
    }
  }

  async getPublicKey(providerKeyId: string): Promise<string | null> {
    if (!this.isConfigured()) return null;
    const key = await this.describeKey(providerKeyId);
    if (!key.key?.n || !key.key?.e) return null;
    return JSON.stringify({
      kty: 'RSA',
      n: Buffer.from(key.key.n).toString('base64url'),
      e: Buffer.from(key.key.e).toString('base64url'),
    });
  }

  async encrypt(providerKeyId: string, plaintext: Buffer, aad?: Buffer): Promise<EncryptedEnvelope> {
    const key = await this.describeKey(providerKeyId);
    const wrapAlg = wrapAlgorithmFor(key.keyType);
    const { dek, iv, ct, tag } = sealWithFreshDek(plaintext, aad);
    let wrappedDek: Buffer;
    try {
      const wrapped = await this.clients.cryptoClient(key.id!, this.getCredential()).wrapKey(wrapAlg, dek);
      wrappedDek = Buffer.from(wrapped.result);
    } catch (err) {
      throw mapAzureError(err, 'wrapping the data key');
    } finally {
      dek.fill(0);
    }
    return {
      v: 1,
      alg: 'AES-256-GCM',
      iv: iv.toString('base64url'),
      tag: tag.toString('base64url'),
      ct: ct.toString('base64url'),
      aad: aad && aad.length > 0 ? aad.toString('base64url') : null,
      wrappedDek: wrappedDek.toString('base64url'),
      wrapAlg,
    };
  }

  async decrypt(providerKeyId: string, envelope: EncryptedEnvelope): Promise<Buffer> {
    if (!envelope.wrappedDek) {
      throw new CryptoEngineError('INVALID_INPUT', 'Envelope is missing its wrapped data key (wrappedDek).');
    }
    const key = await this.describeKey(providerKeyId);
    const wrapAlg = assertUnwrapAlgorithm(envelope.wrapAlg ?? undefined, key.keyType);
    let dek: Buffer;
    try {
      const unwrapped = await this.clients
        .cryptoClient(key.id!, this.getCredential())
        .unwrapKey(wrapAlg, Buffer.from(envelope.wrappedDek, 'base64url'));
      dek = Buffer.from(unwrapped.result);
    } catch (err) {
      throw mapAzureError(err, 'unwrapping the data key');
    }
    return openWithDek(
      dek,
      Buffer.from(envelope.iv, 'base64url'),
      Buffer.from(envelope.ct, 'base64url'),
      Buffer.from(envelope.tag, 'base64url'),
      envelope.aad ? Buffer.from(envelope.aad, 'base64url') : undefined
    );
  }

  async sign(providerKeyId: string, data: Buffer): Promise<Buffer> {
    const key = await this.describeKey(providerKeyId);
    const { algorithm, hash } = signatureAlgorithmFor(key);
    const digest = crypto.createHash(hash).update(data).digest();
    try {
      const signed = await this.clients.cryptoClient(key.id!, this.getCredential()).sign(algorithm, digest);
      return Buffer.from(signed.result);
    } catch (err) {
      throw mapAzureError(err, 'signing');
    }
  }

  async verify(providerKeyId: string, data: Buffer, signature: Buffer): Promise<boolean> {
    const key = await this.describeKey(providerKeyId);
    const { algorithm, hash } = signatureAlgorithmFor(key);
    // `verify` takes the digest; `verifyData` would hash it a second time.
    const digest = crypto.createHash(hash).update(data).digest();
    try {
      const verified = await this.clients.cryptoClient(key.id!, this.getCredential()).verify(algorithm, digest, signature);
      return Boolean(verified.result);
    } catch (err) {
      throw mapAzureError(err, 'verification');
    }
  }

  /** A new version of the same Azure key: creating an existing name adds a version. */
  async rotateKey(params: RotateKeyParams): Promise<ProviderKeyResult> {
    const { name } = parseAzureKeyId(params.currentActiveVersion.providerKeyId);
    try {
      const created = await this.keyClient().createKey(name, this.kek.keyType, {
        keySize: this.kek.keySize,
        keyOps: ['wrapKey', 'unwrapKey'],
      });
      if (!created.id) throw new Error('Azure returned no key id');
      this.keyCache.set(created.id, created);
      return { providerKeyId: created.id, metadata: { rotated: true, azureKeyName: name } };
    } catch (err) {
      throw mapAzureError(err, 'key rotation');
    }
  }

  private async setEnabled(providerKeyId: string, enabled: boolean): Promise<void> {
    const { name, version } = parseAzureKeyId(providerKeyId);
    try {
      if (version) await this.keyClient().updateKeyProperties(name, version, { enabled });
      else await this.keyClient().updateKeyProperties(name, { enabled });
    } catch (err) {
      throw mapAzureError(err, enabled ? 'enabling the key' : 'disabling the key');
    }
  }

  async disableKey(providerKeyId: string): Promise<void> {
    await this.setEnabled(providerKeyId, false);
  }

  async enableKey(providerKeyId: string): Promise<void> {
    await this.setEnabled(providerKeyId, true);
  }

  async scheduleDeletion(providerKeyId: string, pendingWindowDays: number = 7): Promise<Date> {
    const { name } = parseAzureKeyId(providerKeyId);
    try {
      const poller = await this.keyClient().beginDeleteKey(name);
      const deleted = await poller.pollUntilDone();
      return deleted.properties?.scheduledPurgeDate || new Date(Date.now() + pendingWindowDays * 86400000);
    } catch (err) {
      throw mapAzureError(err, 'scheduling deletion');
    }
  }

  async cancelDeletion(providerKeyId: string): Promise<void> {
    await this.recoverKey(providerKeyId);
  }

  async recoverKey(providerKeyId: string): Promise<void> {
    const { name } = parseAzureKeyId(providerKeyId);
    try {
      const poller = await this.keyClient().beginRecoverDeletedKey(name);
      await poller.pollUntilDone();
    } catch (err) {
      throw mapAzureError(err, 'recovering the key');
    }
  }

  async purgeKey(providerKeyId: string): Promise<void> {
    const { name } = parseAzureKeyId(providerKeyId);
    try {
      await this.keyClient().purgeDeletedKey(name);
    } catch (err) {
      throw mapAzureError(err, 'purging the key');
    }
  }

  /** Deletes the key if it is not already deleted, then purges it (fails if the vault has purge protection). */
  async destroyKey(providerKeyId: string): Promise<void> {
    const { name } = parseAzureKeyId(providerKeyId);
    try {
      const poller = await this.keyClient().beginDeleteKey(name);
      await poller.pollUntilDone();
    } catch (err: any) {
      if (err?.statusCode !== 404) throw mapAzureError(err, 'deleting the key');
    }
    await this.purgeKey(providerKeyId);
  }
}
