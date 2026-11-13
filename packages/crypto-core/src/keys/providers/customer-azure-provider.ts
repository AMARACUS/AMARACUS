import crypto from 'crypto';
import { ClientSecretCredential, TokenCredential } from '@azure/identity';
import { KeyVaultKey } from '@azure/keyvault-keys';
import {
  CustomerKeyProvider,
  CustomerKeyProviderConfig,
  CustomerConnectionTestResult,
  DiscoveredKeyMetadata,
  KeyProviderCapabilities,
  KeyCapabilities,
  KeyPurpose,
} from '../types';
import { EncryptedEnvelope } from '../../types';
import { CryptoEngineError } from '../../errors';
import {
  AzureClientFactory,
  AzureCryptoClient,
  AzureKeyClient,
  sdkAzureClientFactory,
  validateAzureVaultUrl,
  wrapAlgorithmFor,
  assertUnwrapAlgorithm,
  signatureAlgorithmFor,
  sealWithFreshDek,
  openWithDek,
} from './azure-common';

/**
 * The customer's service principal for their own vault. Managed identity and workload
 * identity are refused: on AMARACUS's hosts they would resolve to AMARACUS's own Azure
 * identity, letting one tenant act on vaults that trust the platform (a confused deputy).
 */
export function customerCredentialFor(config: CustomerKeyProviderConfig): TokenCredential {
  const authType = config.authType || 'SERVICE_PRINCIPAL';
  if (authType !== 'SERVICE_PRINCIPAL') {
    throw new CryptoEngineError(
      'INVALID_INPUT',
      `BYOK authentication '${authType}' is not supported. Use SERVICE_PRINCIPAL with the customer's own ` +
        'tenantId, clientId and clientSecret; AMARACUS never uses its own Azure identity for customer vaults.'
    );
  }
  const tenantId = config.tenantId?.trim();
  const clientId = config.clientId?.trim();
  const clientSecret = config.clientSecret?.trim();
  if (!tenantId || !clientId || !clientSecret) {
    throw new CryptoEngineError(
      'INVALID_INPUT',
      "BYOK needs the customer's service principal: tenantId, clientId and clientSecret are all required."
    );
  }
  return new ClientSecretCredential(tenantId, clientId, clientSecret);
}

function cryptoFailure(err: any, action: string): CryptoEngineError {
  if (err instanceof CryptoEngineError) return err;
  if (err?.statusCode === 401 || err?.statusCode === 403) {
    return new CryptoEngineError('AUTHORIZATION_FAILED', `Azure Service Principal lacks ${action} permission.`);
  }
  return new CryptoEngineError('CRYPTO_OPERATION_FAILED', `Azure Key Vault ${action} failed: ${err?.message || 'Operation failed'}`);
}

export class CustomerAzureKeyVaultProvider implements CustomerKeyProvider {
  public readonly config: CustomerKeyProviderConfig;
  public readonly capabilities: KeyProviderCapabilities;
  private readonly vaultOrigin: string;
  private readonly isHsm: boolean;
  private readonly credential: TokenCredential;
  private readonly keyClient: AzureKeyClient;

  constructor(config: CustomerKeyProviderConfig, private readonly clients: AzureClientFactory = sdkAzureClientFactory) {
    this.config = config;
    const endpoint = config.vaultUrl || config.hsmUrl;
    if (!endpoint) {
      throw new CryptoEngineError('INVALID_INPUT', 'Customer Azure Key Vault URL or Managed HSM URL is required.');
    }
    // URL first: no credential is built, and no token requested, for a host that is not an Azure vault.
    const { origin, kind } = validateAzureVaultUrl(endpoint);
    this.vaultOrigin = origin;
    this.isHsm = kind === 'MANAGED_HSM';
    this.credential = customerCredentialFor(config);
    this.keyClient = clients.keyClient(origin, this.credential);

    this.capabilities = {
      supportedPurposes: ['ENCRYPTION', 'SIGNING', 'KEY_WRAPPING'],
      supportedAlgorithms: ['AES-256-GCM', 'SHA-256'],
      supportsKeyGeneration: false, // Customer generates in their own vault
      supportsRotation: false, // Customer rotates in their own vault
      supportsScheduledDeletion: false, // Customer owns deletion
      supportsEnvelopeEncryption: true,
      supportsAsymmetricSign: true,
      supportsPurge: false,
      supportsRecovery: false,
      supportsOctHsm: this.isHsm,
      isHardwareBacked: this.isHsm,
      isFips140Validated: true,
      supportsPqc: false,
    };
  }

  public async testConnection(): Promise<CustomerConnectionTestResult> {
    const start = Date.now();
    const isHsm = this.isHsm;
    const defaultCaps: KeyCapabilities = {
      encrypt: true,
      decrypt: true,
      sign: true,
      verify: true,
      wrap: true,
      unwrap: true,
      derive: 'unknown',
      rotate: false,
      pqc: false,
      unavailableReasons: {
        rotate: 'Key lifecycle rotation is controlled directly inside your customer Azure subscription.',
        derive: 'Key derivation is not advertised as supported by default Azure vault policy.',
        pqc: 'Azure Key Vault and Managed HSM do not support Post-Quantum Cryptography algorithms (ML-KEM / ML-DSA).',
      },
    };

    try {
      let accessibleKeysCount = 0;
      const iterator = this.keyClient.listPropertiesOfKeys();
      // Test listing first page of keys
      for await (const _ of iterator) {
        accessibleKeysCount++;
        if (accessibleKeysCount >= 5) break; // Sample first 5
      }

      const latencyMs = Date.now() - start;

      return {
        success: true,
        providerType: this.config.providerType,
        connectionStatus: 'CONNECTED',
        isHsmBacked: isHsm,
        hsmBackedStatus: isHsm ? 'VERIFIED_HSM' : 'STANDARD_VAULT',
        vaultUrl: this.config.vaultUrl,
        accessibleKeysCount,
        capabilities: {
          ...this.capabilities,
          ...defaultCaps,
        },
        providerCapabilities: this.capabilities,
        pqc: false,
        latencyMs,
        message: `Successfully connected to customer-managed Azure ${isHsm ? 'Managed HSM' : 'Key Vault'}. Verified delegated identity and key read permissions.`,
      };
    } catch (err: any) {
      const latencyMs = Date.now() - start;
      let connectionStatus: any = 'ERROR';
      let safeMessage = `Connection failed: ${err.message || 'Unable to reach vault endpoint'}`;

      if (err.statusCode === 401 || err.statusCode === 403) {
        connectionStatus = 'AUTHORIZATION_FAILED';
        safeMessage = 'Authorization failed: Azure Service Principal lacks required Key Vault permissions (e.g. Key Vault Crypto User or Key Vault Reader role).';
      } else if (err.statusCode === 404 || (err.code && err.code.includes('NotFound'))) {
        connectionStatus = 'RESOURCE_NOT_FOUND';
        safeMessage = 'Resource not found: The configured Azure Key Vault or Managed HSM endpoint could not be resolved.';
      } else if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
        connectionStatus = 'RESOURCE_NOT_FOUND';
        safeMessage = 'Endpoint unreachable: Domain name resolution failed for the provided vault URL.';
      }

      return {
        success: false,
        providerType: this.config.providerType,
        connectionStatus,
        isHsmBacked: false,
        hsmBackedStatus: 'UNKNOWN',
        vaultUrl: this.config.vaultUrl,
        accessibleKeysCount: 0,
        capabilities: {
          ...this.capabilities,
          ...defaultCaps,
        },
        providerCapabilities: this.capabilities,
        pqc: false,
        latencyMs,
        message: safeMessage,
        error: connectionStatus,
      };
    }
  }

  public async discoverKeys(): Promise<DiscoveredKeyMetadata[]> {
    const discovered: DiscoveredKeyMetadata[] = [];
    try {
      for await (const prop of this.keyClient.listPropertiesOfKeys()) {
        if (!prop.enabled) continue;
        try {
          const key = await this.keyClient.getKey(prop.name);
          discovered.push(this.mapAzureKeyToMetadata(key));
        } catch {
          // If specific key read is prohibited, skip
        }
      }
      return discovered;
    } catch (err: any) {
      const safeCode = err.statusCode === 401 || err.statusCode === 403 ? 'AUTHORIZATION_FAILED' : 'PROVIDER_UNAVAILABLE';
      throw new CryptoEngineError(
        safeCode as any,
        `Failed to discover keys in customer Azure vault: ${err.message}`
      );
    }
  }

  public async discoverKey(keyIdentifier: string): Promise<DiscoveredKeyMetadata> {
    try {
      const key = await this.keyClient.getKey(keyIdentifier);
      return this.mapAzureKeyToMetadata(key);
    } catch (err: any) {
      if (err.statusCode === 404) {
        throw new CryptoEngineError(
          'KEY_NOT_FOUND',
          `Key '${keyIdentifier}' not found in customer Azure vault.`
        );
      }
      throw new CryptoEngineError(
        'PROVIDER_UNAVAILABLE',
        `Unable to inspect key '${keyIdentifier}': ${err.message}`
      );
    }
  }

  private mapAzureKeyToMetadata(key: KeyVaultKey): DiscoveredKeyMetadata {
    const keyType = key.keyType || 'RSA';
    const isHsm = keyType.endsWith('-HSM') || keyType === 'oct-HSM';
    const ops = (key.keyOperations || []).map((op) => op.toString().toLowerCase());

    const hasEncrypt = ops.includes('encrypt') || ops.includes('wrapkey');
    const hasDecrypt = ops.includes('decrypt') || ops.includes('unwrapkey');
    const hasSign = ops.includes('sign');
    const hasVerify = ops.includes('verify');
    const hasWrap = ops.includes('wrapkey');
    const hasUnwrap = ops.includes('unwrapkey');

    const unavailableReasons: Record<string, string> = {};
    if (!hasEncrypt) unavailableReasons.encrypt = 'Key does not have wrapKey/encrypt operation configured in Azure.';
    if (!hasDecrypt) unavailableReasons.decrypt = 'Key does not have unwrapKey/decrypt operation configured in Azure.';
    if (!hasSign) unavailableReasons.sign = 'Key does not have sign operation configured in Azure.';
    if (!hasVerify) unavailableReasons.verify = 'Key does not have verify operation configured in Azure.';
    if (!hasWrap) unavailableReasons.wrap = 'Key does not permit key wrapping operations.';
    if (!hasUnwrap) unavailableReasons.unwrap = 'Key does not permit key unwrapping operations.';
    unavailableReasons.derive = 'Key agreement / derivation is not supported for this key type.';
    unavailableReasons.rotate = 'Key lifecycle rotation is controlled in your Azure Key Vault.';

    const capabilities: KeyCapabilities = {
      encrypt: hasEncrypt,
      decrypt: hasDecrypt,
      sign: hasSign,
      verify: hasVerify,
      wrap: hasWrap,
      unwrap: hasUnwrap,
      derive: false,
      rotate: false,
      unavailableReasons,
    };

    let purpose: KeyPurpose = 'ENCRYPTION';
    if (hasSign || hasVerify) {
      purpose = hasEncrypt || hasWrap ? 'ENCRYPTION' : 'SIGNING';
    }

    let pubKeyPem: string | undefined;
    let fingerprint: string | undefined;

    if (key.key?.n && key.key?.e) {
      // RSA Key
      pubKeyPem = this.jwkToRsaPublicKey(key.key.n, key.key.e);
      fingerprint = crypto.createHash('sha256').update(pubKeyPem).digest('hex');
    }

    const version = key.properties.version || 'v1';

    return {
      keyIdentifier: key.name,
      keyType,
      algorithm: 'AES-256-GCM',
      purpose,
      currentVersion: version,
      enabled: !!key.properties.enabled,
      isHsmBacked: isHsm,
      hsmBackedStatus: isHsm ? 'VERIFIED_HSM' : 'STANDARD_VAULT',
      operations: ops,
      capabilities,
      publicKey: pubKeyPem,
      keyFingerprint: fingerprint,
      createdAt: key.properties.createdOn,
      expiresAt: key.properties.expiresOn,
    };
  }

  private jwkToRsaPublicKey(n: Uint8Array, e: Uint8Array): string {
    const keyObject = crypto.createPublicKey({
      key: {
        kty: 'RSA',
        n: Buffer.from(n).toString('base64url'),
        e: Buffer.from(e).toString('base64url'),
      },
      format: 'jwk',
    });
    return keyObject.export({ type: 'spki', format: 'pem' }) as string;
  }

  /** The key version and a client for it. The key type decides which algorithms may be used. */
  private async resolveKey(keyIdentifier: string, version?: string): Promise<{ key: KeyVaultKey; client: AzureCryptoClient }> {
    try {
      const key = await this.keyClient.getKey(keyIdentifier, { version });
      if (!key.id || validateAzureVaultUrl(key.id.slice(0, key.id.indexOf('/keys/') + 1)).origin !== this.vaultOrigin) {
        throw new CryptoEngineError('INVALID_KEY', 'Azure returned a key from a different vault.');
      }
      return { key, client: this.clients.cryptoClient(key.id, this.credential) };
    } catch (err: any) {
      if (err instanceof CryptoEngineError) throw err;
      if (err.statusCode === 404) {
        throw new CryptoEngineError('KEY_NOT_FOUND', `Key '${keyIdentifier}' was not found in customer Azure vault.`);
      }
      if (err.statusCode === 401 || err.statusCode === 403) {
        throw new CryptoEngineError('AUTHORIZATION_FAILED', 'Azure Service Principal lacks permissions for key cryptographic operations.');
      }
      throw new CryptoEngineError('PROVIDER_UNAVAILABLE', `Customer key provider is currently unreachable: ${err.message || 'Network error'}`);
    }
  }

  public async encrypt(
    keyIdentifier: string,
    plaintext: Buffer,
    aad?: Buffer,
    version?: string
  ): Promise<EncryptedEnvelope> {
    const { key, client } = await this.resolveKey(keyIdentifier, version);
    const wrapAlg = wrapAlgorithmFor(key.keyType);
    const { dek, iv, ct, tag } = sealWithFreshDek(plaintext, aad);

    // Wrap the DEK inside customer's Azure Key Vault
    let wrappedDek: Buffer;
    try {
      const wrapResult = await client.wrapKey(wrapAlg, dek);
      wrappedDek = Buffer.from(wrapResult.result);
    } catch (err: any) {
      throw cryptoFailure(err, 'wrapKey');
    } finally {
      // Securely wipe plaintext DEK from memory
      dek.fill(0);
    }

    // BYOK envelopes use standard base64 (unlike platform envelopes); stored data depends on it.
    return {
      v: 1,
      alg: 'AES-256-GCM',
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ct: ct.toString('base64'),
      aad: aad ? aad.toString('base64') : undefined,
      wrappedDek: wrappedDek.toString('base64'),
      wrapAlg,
    };
  }

  public async decrypt(
    keyIdentifier: string,
    envelope: EncryptedEnvelope,
    version?: string
  ): Promise<Buffer> {
    if (!envelope.wrappedDek) {
      throw new CryptoEngineError(
        'INVALID_INPUT',
        'Customer BYOK envelope must include a wrapped DEK.'
      );
    }

    const { key, client } = await this.resolveKey(keyIdentifier, version);
    // Never pass the envelope's algorithm through unchecked: a forged envelope could ask
    // for a weak padding mode such as RSA1_5.
    const wrapAlg = assertUnwrapAlgorithm(envelope.wrapAlg ?? undefined, key.keyType);

    let dek: Buffer;
    try {
      const unwrapResult = await client.unwrapKey(wrapAlg, Buffer.from(envelope.wrappedDek, 'base64'));
      dek = Buffer.from(unwrapResult.result);
    } catch (err: any) {
      throw cryptoFailure(err, 'unwrapKey');
    }

    return openWithDek(
      dek,
      Buffer.from(envelope.iv, 'base64'),
      Buffer.from(envelope.ct, 'base64'),
      Buffer.from(envelope.tag, 'base64'),
      envelope.aad ? Buffer.from(envelope.aad, 'base64') : undefined
    );
  }

  public async sign(
    keyIdentifier: string,
    data: Buffer,
    version?: string
  ): Promise<Buffer> {
    const { key, client } = await this.resolveKey(keyIdentifier, version);
    const { algorithm, hash } = signatureAlgorithmFor(key);
    const digest = crypto.createHash(hash).update(data).digest();
    try {
      const signResult = await client.sign(algorithm, digest);
      return Buffer.from(signResult.result);
    } catch (err: any) {
      throw cryptoFailure(err, 'sign');
    }
  }

  public async verify(
    keyIdentifier: string,
    data: Buffer,
    signature: Buffer,
    version?: string
  ): Promise<boolean> {
    const { key, client } = await this.resolveKey(keyIdentifier, version);
    const { algorithm, hash } = signatureAlgorithmFor(key);
    const digest = crypto.createHash(hash).update(data).digest();
    try {
      const verifyResult = await client.verify(algorithm, digest, signature);
      return !!verifyResult.result;
    } catch (err: any) {
      throw cryptoFailure(err, 'verify');
    }
  }

  public async syncKeyVersions(keyIdentifier: string): Promise<{ versions: string[]; currentVersion: string }> {
    const versions: string[] = [];
    let currentVersion = '';
    const iterator = this.keyClient.listPropertiesOfKeyVersions(keyIdentifier);
    for await (const prop of iterator) {
      if (prop.version) {
        versions.push(prop.version);
        if (!currentVersion && prop.enabled) {
          currentVersion = prop.version;
        }
      }
    }
    return {
      versions,
      currentVersion: currentVersion || (versions.length > 0 ? versions[0] : 'v1'),
    };
  }
}
