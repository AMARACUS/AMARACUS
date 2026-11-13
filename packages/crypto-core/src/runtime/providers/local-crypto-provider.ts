/**
 * AMARACUS Cryptographic Infrastructure — Local Provider
 *
 * Backed by OpenSSL / Node.js native crypto and local development KEK.
 * Provides high-speed, software-based cryptographic primitives for development,
 * testing, and standard classical workloads.
 */

import crypto from 'crypto';
import {
  CryptographicProvider,
  ProviderCapabilityMap,
  ProviderHealthReport,
  ProviderEncryptParams,
  ProviderDecryptParams,
  ProviderSignParams,
  ProviderVerifyParams,
  ProviderKeyGenParams,
  ProviderKeyGenResult,
} from '../provider-abstraction';
import { OperationType } from '../operation-model';
import { KeyReference } from '../key-reference';
import { EncryptedEnvelope, AlgorithmId } from '../../types';
import { NodeCryptoProvider } from '../../providers/node-crypto-provider';
import { LocalDevKeyProvider } from '../../keys/providers/local-dev-provider';
import { normalizeAlgorithmId } from '../../registry';
import { CryptoEngineError } from '../../errors';

export class LocalCryptographicProvider implements CryptographicProvider {
  public readonly id = 'LOCAL_DEV';
  public readonly name = 'AMARACUS Local / Software Cryptographic Provider';

  private readonly nodeProvider: NodeCryptoProvider;
  private readonly localDevKeyProvider: LocalDevKeyProvider;

  public readonly capabilities: ProviderCapabilityMap = {
    encryption: true,
    decryption: true,
    signing: true,
    verification: true,
    hashing: true,
    hmac: true,
    keyGeneration: true,
    keyRotation: true,
    keyWrapping: true,
    keyUnwrapping: true,
    pqc: false,
    hardwareBacked: false,
    fipsValidated: false,
    supportedAlgorithms: [
      'AES-256-GCM',
      'AES-128-GCM',
      'CHACHA20-POLY1305',
      'RSA-OAEP-256',
      'RSA-OAEP-384',
      'RSA-OAEP-512',
      'RSA-PSS-256',
      'RSA-PSS-384',
      'RSA-PSS-512',
      'ECDSA-P256',
      'ECDSA-P384',
      'ECDSA-P521',
      'ED25519',
      'X25519',
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'HMAC-SHA-256',
      'HMAC-SHA-384',
      'HMAC-SHA-512',
      // Managed post-quantum signing keys (wrapped by the local key provider)
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
    ],
    supportedPurposes: ['ENCRYPTION', 'SIGNING', 'KEY_AGREEMENT', 'KEY_WRAPPING'],
  };

  constructor() {
    this.nodeProvider = new NodeCryptoProvider();
    this.localDevKeyProvider = new LocalDevKeyProvider();
  }

  public async isAvailable(): Promise<boolean> {
    return true;
  }

  public async healthCheck(): Promise<ProviderHealthReport> {
    return {
      providerId: this.id,
      name: this.name,
      status: 'AVAILABLE',
      message: 'Local software cryptographic provider is ready.',
      latencyMs: 1,
      capabilities: this.capabilities,
      timestamp: new Date().toISOString(),
    };
  }

  public supportsOperation(operation: OperationType, algorithm?: string): boolean {
    const alg = algorithm ? normalizeAlgorithmId(algorithm) : '';
    if (alg && !this.capabilities.supportedAlgorithms.includes(alg)) {
      return false;
    }
    switch (operation) {
      case 'ENCRYPT':
      case 'DECRYPT':
      case 'SIGN':
      case 'VERIFY':
      case 'HASH':
      case 'HMAC':
      case 'HMAC_VERIFY':
      case 'KEY_GEN':
      case 'KEY_ROTATION':
        return true;
      default:
        return false;
    }
  }

  private toManagedKeyVersion(keyRef?: KeyReference | null) {
    if (!keyRef) return undefined;
    return {
      id: keyRef.id,
      keyId: keyRef.id,
      version: Number(keyRef.currentVersion) || 1,
      providerKeyId: keyRef.providerKeyId,
      status: 'ACTIVE',
      publicKey: keyRef.publicKey || null,
      encryptedKeyMaterial: keyRef.encryptedKeyMaterial || null,
      // The local key provider picks ML-DSA vs. classical signing from this
      metadata: { ...(keyRef.metadata || {}), algorithm: keyRef.algorithm },
      createdAt: new Date(),
    } as any;
  }

  public async encrypt(params: ProviderEncryptParams): Promise<EncryptedEnvelope> {
    if (params.keyReference) {
      // Using managed logical key reference
      return this.localDevKeyProvider.encrypt(
        params.keyReference.providerKeyId,
        params.plaintext,
        params.aad,
        this.toManagedKeyVersion(params.keyReference)
      );
    }

    if (params.key) {
      let rawKey: Buffer;
      if (Buffer.isBuffer(params.key)) {
        rawKey = params.key;
      } else if (params.keyEncoding === 'hex' || (/^[0-9a-fA-F]{64}$/.test(params.key) && params.keyEncoding !== 'base64')) {
        rawKey = Buffer.from(params.key, 'hex');
      } else {
        rawKey = Buffer.from(params.key, 'base64');
      }

      return this.nodeProvider.encrypt({
        algorithm: (params.algorithm as AlgorithmId) || 'AES-256-GCM',
        key: rawKey.toString('base64'),
        keyEncoding: 'base64',
        plaintext: params.plaintext,
        aad: params.aad,
      });
    }

    throw new CryptoEngineError('INVALID_KEY', 'Either keyReference or raw key is required for encryption.');
  }

  public async decrypt(params: ProviderDecryptParams): Promise<Buffer> {
    // The runtime has already pinned keyReference to the requested version
    if (params.keyReference) {
      return this.localDevKeyProvider.decrypt(
        params.keyReference.providerKeyId,
        params.envelope,
        this.toManagedKeyVersion(params.keyReference)
      );
    }

    if (params.key) {
      let rawKey: Buffer;
      if (Buffer.isBuffer(params.key)) {
        rawKey = params.key;
      } else if (params.keyEncoding === 'hex' || (/^[0-9a-fA-F]{64}$/.test(params.key) && params.keyEncoding !== 'base64')) {
        rawKey = Buffer.from(params.key, 'hex');
      } else {
        rawKey = Buffer.from(params.key, 'base64');
      }

      const decryptedB64 = await this.nodeProvider.decrypt({
        envelope: params.envelope,
        key: rawKey,
        outputEncoding: 'base64',
      });
      return Buffer.from(decryptedB64, 'base64');
    }

    throw new CryptoEngineError('INVALID_KEY', 'Either keyReference or raw key is required for decryption.');
  }

  public async sign(params: ProviderSignParams): Promise<Buffer> {
    if (params.keyReference) {
      return this.localDevKeyProvider.sign(
        params.keyReference.providerKeyId,
        params.data,
        this.toManagedKeyVersion(params.keyReference)
      );
    }

    if (params.privateKey) {
      const keyStr = typeof params.privateKey === 'string' ? params.privateKey : params.privateKey.toString('utf8');
      const res = await this.nodeProvider.sign({
        algorithm: (params.algorithm as AlgorithmId) || 'ED25519',
        privateKey: keyStr,
        message: params.data,
      });
      return Buffer.from(res.signature, res.encoding === 'base64' ? 'base64' : 'hex');
    }

    throw new CryptoEngineError('INVALID_KEY', 'Either keyReference or privateKey is required for signing.');
  }

  public async verify(params: ProviderVerifyParams): Promise<boolean> {
    if (params.keyReference) {
      return this.localDevKeyProvider.verify(
        params.keyReference.providerKeyId,
        params.data,
        params.signature,
        this.toManagedKeyVersion(params.keyReference)
      );
    }

    if (params.publicKey) {
      const keyStr = typeof params.publicKey === 'string' ? params.publicKey : params.publicKey.toString('utf8');
      return this.nodeProvider.verify({
        algorithm: (params.algorithm as AlgorithmId) || 'ED25519',
        publicKey: keyStr,
        message: params.data,
        signature: params.signature.toString('hex'),
      });
    }

    throw new CryptoEngineError('INVALID_KEY', 'Either keyReference or publicKey is required for signature verification.');
  }

  public async hash(data: Buffer, algorithm: string): Promise<Buffer> {
    const res = await this.nodeProvider.hash({
      algorithm: (algorithm as AlgorithmId) || 'SHA-256',
      data,
    });
    return Buffer.from(res.digest, 'hex');
  }

  public async hmac(key: Buffer, data: Buffer, algorithm: string): Promise<Buffer> {
    const res = await this.nodeProvider.hmac({
      algorithm: (normalizeAlgorithmId(algorithm || 'HMAC-SHA-256') as AlgorithmId),
      key,
      data,
    });
    return Buffer.from(res.mac, 'hex');
  }

  public async generateKey(params: ProviderKeyGenParams): Promise<ProviderKeyGenResult> {
    return this.localDevKeyProvider.createKey({
      name: params.name,
      algorithm: params.algorithm as any,
      purpose: params.purpose as any,
      organizationId: 'internal',
      projectId: 'internal',
      environmentId: 'internal',
      metadata: params.metadata,
    });
  }

  public async rotateKey(keyReference: KeyReference): Promise<ProviderKeyGenResult> {
    return this.localDevKeyProvider.rotateKey({
      key: {
        id: keyReference.id,
        name: keyReference.name,
        organizationId: keyReference.organizationId,
        projectId: keyReference.projectId || '',
        environmentId: keyReference.environmentId || '',
        algorithm: keyReference.algorithm as any,
        purpose: keyReference.purpose as any,
        provider: 'LOCAL_DEV',
        status: keyReference.status as any,
        currentVersion: Number(keyReference.currentVersion),
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      currentActiveVersion: {
        id: `ver_${keyReference.currentVersion}`,
        keyId: keyReference.id,
        version: Number(keyReference.currentVersion),
        providerKeyId: keyReference.providerKeyId,
        status: 'ACTIVE',
        createdAt: new Date(),
      },
    });
  }
}
