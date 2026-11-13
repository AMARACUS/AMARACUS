import crypto from 'node:crypto';
import {
  KeyProvider,
  KeyProviderCapabilities,
  ProviderHealth,
  CreateKeyParams,
  ProviderKeyResult,
  RotateKeyParams,
  ManagedKeyVersion,
} from '../types';
import { EncryptedEnvelope } from '../../types';
import { CryptoEngineError } from '../../errors';
import {
  getPlatformMasterSecret,
  getPreviousPlatformMasterSecret,
  isMasterKeySealed,
  isMasterKeyRotationInProgress,
  deriveMasterKek,
  masterKekId,
} from '../master-key';
import { mlKemEngine, mlDsaEngine, hybridKemEngine } from '../../pqc';

export class LocalDevKeyProvider implements KeyProvider {
  readonly providerId = 'LOCAL_DEV' as const;
  readonly label = 'Local Development Provider (DEVELOPMENT ONLY)';
  readonly capabilities: KeyProviderCapabilities = {
    supportedPurposes: ['ENCRYPTION', 'SIGNING', 'KEY_AGREEMENT', 'KEY_WRAPPING'],
    supportedAlgorithms: [
      'AES-256-GCM',
      'ED25519',
      'X25519',
      'ML-KEM-512',
      'ML-KEM-768',
      'ML-KEM-1024',
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
      'X25519+ML-KEM-768',
    ],
    supportsKeyGeneration: true,
    supportsRotation: true,
    supportsScheduledDeletion: true,
    supportsEnvelopeEncryption: true,
    supportsAsymmetricSign: true,
    supportsPurge: true,
    supportsRecovery: true,
    supportsOctHsm: false,
    isHardwareBacked: false,
    isFips140Validated: false,
    supportsPqc: true,
  };

  private getMasterKek(): Buffer {
    let secret = getPlatformMasterSecret();
    if (!secret) {
      if (process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID !== undefined) {
        secret = 'test-only-master-kek:not-for-production-use';
      } else {
        throw new CryptoEngineError(
          'PROVIDER_NOT_CONFIGURED',
          isMasterKeySealed()
            ? 'The sealed platform master key has not been unsealed; refusing to wrap or unwrap key material.'
            : 'AMARACUS_LOCAL_MASTER_KEY is not configured; refusing to wrap or unwrap key material.'
        );
      }
    }
    return deriveMasterKek(secret);
  }

  /** The KEKs that may unwrap a blob: current first, then the previous one during a rotation. */
  private unwrapCandidates(): Buffer[] {
    const candidates = [this.getMasterKek()];
    const previous = getPreviousPlatformMasterSecret();
    if (previous) candidates.push(deriveMasterKek(previous));
    return candidates;
  }

  isConfigured(): boolean {
    return (
      !!getPlatformMasterSecret() ||
      process.env.NODE_ENV === 'test' ||
      process.env.JEST_WORKER_ID !== undefined
    );
  }

  async healthCheck(): Promise<ProviderHealth> {
    return {
      provider: this.providerId,
      label: this.label,
      status: 'DEVELOPMENT_ONLY',
      isConfigured: true,
      message: 'Local development software provider active. NEVER use in production environments.',
      details: {
        envelopeEncryption: 'AES-256-GCM Master KEK wrapping active',
        masterKekConfigured: !!getPlatformMasterSecret(),
        masterKekSealedByAzure: isMasterKeySealed(),
        masterKekRotationInProgress: isMasterKeyRotationInProgress(),
      },
    };
  }

  /** Wraps key material under the current master KEK, recording which KEK it was (`kid`). */
  private wrapKeyMaterial(rawKey: Buffer): string {
    const kek = this.getMasterKek();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
    const ct = Buffer.concat([cipher.update(rawKey), cipher.final()]);
    const tag = cipher.getAuthTag();
    return JSON.stringify({
      v: 1,
      alg: 'aes-256-gcm',
      kid: masterKekId(kek),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ct: ct.toString('base64'),
    });
  }

  /**
   * Unwraps with the KEK named by the blob's `kid`. Blobs from before `kid` existed are tried
   * against the current KEK and then the previous one.
   */
  private unwrapKeyMaterial(encryptedBlob: string): Buffer {
    let parsed: any;
    try {
      parsed = JSON.parse(encryptedBlob);
    } catch {
      throw new CryptoEngineError('AUTHENTICATION_FAILED', 'Local key material is not a valid wrapped blob.');
    }
    const candidates = this.unwrapCandidates();
    const keks = parsed.kid ? candidates.filter((kek) => masterKekId(kek) === parsed.kid) : candidates;
    if (keks.length === 0) {
      throw new CryptoEngineError(
        'AUTHENTICATION_FAILED',
        'Key material was wrapped under a master key that is not configured (neither the current nor the previous master key).'
      );
    }
    for (const kek of keks) {
      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(parsed.iv, 'base64'));
        decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
        return Buffer.concat([decipher.update(Buffer.from(parsed.ct, 'base64')), decipher.final()]);
      } catch {
        // Try the next candidate; legacy blobs carry no kid.
      }
    }
    throw new CryptoEngineError(
      'AUTHENTICATION_FAILED',
      'Failed to unwrap local key material. Master KEK may have changed or key blob is corrupted.'
    );
  }

  /**
   * For master key rotation: returns the blob re-wrapped under the current master KEK, or the
   * same blob when it already is. Throws if neither configured master key can unwrap it.
   */
  rewrapKeyMaterial(encryptedBlob: string): { blob: string; changed: boolean } {
    const currentKid = masterKekId(this.getMasterKek());
    try {
      if (JSON.parse(encryptedBlob).kid === currentKid) return { blob: encryptedBlob, changed: false };
    } catch {
      // Fall through: unwrapKeyMaterial reports the malformed blob.
    }
    const raw = this.unwrapKeyMaterial(encryptedBlob);
    try {
      return { blob: this.wrapKeyMaterial(raw), changed: true };
    } finally {
      raw.fill(0);
    }
  }

  async createKey(params: CreateKeyParams): Promise<ProviderKeyResult> {
    const providerKeyId = `local-${crypto.randomUUID()}`;
    const rawAlg = params.algorithm;

    if (rawAlg.startsWith('ML-KEM-')) {
      const keypair = await mlKemEngine.generateKeyPair(rawAlg as any);
      const privBuffer = Buffer.from(keypair.privateKey, 'hex');
      const encryptedKeyMaterial = this.wrapKeyMaterial(privBuffer);
      const keyFingerprint = crypto.createHash('sha256').update(Buffer.from(keypair.publicKey, 'hex')).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        publicKey: keypair.publicKey,
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { type: 'PQC_KEM', algorithm: rawAlg, securityLevel: keypair.securityLevel },
      };
    }

    if (rawAlg.startsWith('ML-DSA-')) {
      const keypair = await mlDsaEngine.generateKeyPair(rawAlg as any);
      const privBuffer = Buffer.from(keypair.privateKey, 'hex');
      const encryptedKeyMaterial = this.wrapKeyMaterial(privBuffer);
      const keyFingerprint = crypto.createHash('sha256').update(Buffer.from(keypair.publicKey, 'hex')).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        publicKey: keypair.publicKey,
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { type: 'PQC_SIGNING', algorithm: rawAlg, securityLevel: keypair.securityLevel },
      };
    }

    if (rawAlg === 'X25519+ML-KEM-768') {
      const keypair = await hybridKemEngine.generateKeyPair();
      const privJson = JSON.stringify(keypair.privateKey);
      const pubJson = JSON.stringify(keypair.publicKey);
      const encryptedKeyMaterial = this.wrapKeyMaterial(Buffer.from(privJson, 'utf8'));
      const keyFingerprint = crypto.createHash('sha256').update(pubJson).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        publicKey: pubJson,
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { type: 'HYBRID_KEM', algorithm: rawAlg, securityLevel: 3 },
      };
    }

    const algorithm = rawAlg.toLowerCase();

    if (algorithm.includes('aes') || params.purpose === 'ENCRYPTION' || params.purpose === 'KEY_WRAPPING') {
      const rawKey = crypto.randomBytes(32);
      const encryptedKeyMaterial = this.wrapKeyMaterial(rawKey);
      const keyFingerprint = crypto.createHash('sha256').update(rawKey).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { keyLengthBits: 256, type: 'SYMMETRIC' },
      };
    }

    if (algorithm.startsWith('rsa')) {
      const modulusLength = algorithm.includes('4096') ? 4096 : algorithm.includes('3072') ? 3072 : 2048;
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength,
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });
      const encryptedKeyMaterial = this.wrapKeyMaterial(privateKey);
      const keyFingerprint = crypto.createHash('sha256').update(publicKey).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        publicKey: publicKey.toString('hex'),
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { type: 'ASYMMETRIC_SIGNING', algorithm: `RSA-${modulusLength}`, modulusLength },
      };
    }

    if (algorithm.startsWith('ecdsa') || algorithm.startsWith('ec')) {
      const namedCurve = algorithm.includes('384') ? 'secp384r1' : 'prime256v1';
      const keyName = algorithm.includes('384') ? 'ECDSA-P384' : 'ECDSA-P256';
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve,
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });
      const encryptedKeyMaterial = this.wrapKeyMaterial(privateKey);
      const keyFingerprint = crypto.createHash('sha256').update(publicKey).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        publicKey: publicKey.toString('hex'),
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { type: 'ASYMMETRIC_SIGNING', algorithm: keyName, namedCurve },
      };
    }

    if (algorithm === 'ed25519' || params.purpose === 'SIGNING') {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const pubDer = publicKey.export({ type: 'spki', format: 'der' });
      const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
      const encryptedKeyMaterial = this.wrapKeyMaterial(privDer);
      const keyFingerprint = crypto.createHash('sha256').update(pubDer).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        publicKey: pubDer.toString('hex'),
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { type: 'ASYMMETRIC_SIGNING', curve: 'Ed25519' },
      };
    }

    if (algorithm === 'x25519' || params.purpose === 'KEY_AGREEMENT') {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
      const pubDer = publicKey.export({ type: 'spki', format: 'der' });
      const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
      const encryptedKeyMaterial = this.wrapKeyMaterial(privDer);
      const keyFingerprint = crypto.createHash('sha256').update(pubDer).digest('hex').substring(0, 16);
      return {
        providerKeyId,
        publicKey: pubDer.toString('hex'),
        encryptedKeyMaterial,
        keyFingerprint,
        metadata: { type: 'ASYMMETRIC_KEY_AGREEMENT', curve: 'X25519' },
      };
    }

    throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Unsupported algorithm '${params.algorithm}' for LocalDevKeyProvider.`);
  }

  async getPublicKey(providerKeyId: string, version?: ManagedKeyVersion): Promise<string | null> {
    return version?.publicKey || null;
  }

  async encrypt(
    providerKeyId: string,
    plaintext: Buffer,
    aad?: Buffer,
    version?: ManagedKeyVersion
  ): Promise<EncryptedEnvelope> {
    if (!version?.encryptedKeyMaterial) {
      throw new CryptoEngineError('INVALID_KEY', 'Local key version missing wrapped key material.');
    }
    const rawKey = this.unwrapKeyMaterial(version.encryptedKeyMaterial);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
    if (aad && aad.length > 0) {
      cipher.setAAD(aad);
    }
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      v: 1,
      alg: 'AES-256-GCM',
      iv: iv.toString('base64url'),
      tag: tag.toString('base64url'),
      ct: ct.toString('base64url'),
      aad: aad ? aad.toString('base64url') : undefined,
    };
  }

  async decrypt(
    providerKeyId: string,
    envelope: EncryptedEnvelope,
    version?: ManagedKeyVersion
  ): Promise<Buffer> {
    if (!version?.encryptedKeyMaterial) {
      throw new CryptoEngineError('INVALID_KEY', 'Local key version missing wrapped key material.');
    }
    const rawKey = this.unwrapKeyMaterial(version.encryptedKeyMaterial);
    const iv = Buffer.from(envelope.iv, 'base64url');
    const tag = Buffer.from(envelope.tag, 'base64url');
    const ct = Buffer.from(envelope.ct, 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', rawKey, iv);
    decipher.setAuthTag(tag);
    if (envelope.aad) {
      decipher.setAAD(Buffer.from(envelope.aad, 'base64url'));
    }
    try {
      return Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch {
      throw new CryptoEngineError('AUTHENTICATION_FAILED', 'Envelope decryption authentication failed. Data or tag tampered.');
    }
  }

  async sign(
    providerKeyId: string,
    data: Buffer,
    version?: ManagedKeyVersion
  ): Promise<Buffer> {
    if (!version?.encryptedKeyMaterial) {
      throw new CryptoEngineError('INVALID_KEY', 'Local key version missing wrapped private key material.');
    }
    const privBytes = this.unwrapKeyMaterial(version.encryptedKeyMaterial);
    const alg = version.metadata?.algorithm;
    if (alg && typeof alg === 'string' && alg.startsWith('ML-DSA-')) {
      const sigResult = await mlDsaEngine.sign({
        algorithm: alg as any,
        privateKey: privBytes.toString('hex'),
        message: data,
      });
      return Buffer.from(sigResult.signature, 'hex');
    }
    const privateKey = crypto.createPrivateKey({ key: privBytes, format: 'der', type: 'pkcs8' });
    const keyType = privateKey.asymmetricKeyType;
    const signHash = keyType === 'rsa' || keyType === 'ec' ? 'SHA256' : null;
    return crypto.sign(signHash, data, privateKey);
  }

  async verify(
    providerKeyId: string,
    data: Buffer,
    signature: Buffer,
    version?: ManagedKeyVersion
  ): Promise<boolean> {
    if (!version?.publicKey) {
      throw new CryptoEngineError('INVALID_KEY', 'Local key version missing public key.');
    }
    const alg = version.metadata?.algorithm;
    if (alg && typeof alg === 'string' && alg.startsWith('ML-DSA-')) {
      const verifyResult = await mlDsaEngine.verify({
        algorithm: alg as any,
        publicKey: version.publicKey,
        message: data,
        signature: signature.toString('hex'),
      });
      return verifyResult.valid;
    }
    const pubBytes = Buffer.from(version.publicKey, 'hex');
    const publicKey = crypto.createPublicKey({ key: pubBytes, format: 'der', type: 'spki' });
    const keyType = publicKey.asymmetricKeyType;
    const signHash = keyType === 'rsa' || keyType === 'ec' ? 'SHA256' : null;
    return crypto.verify(signHash, data, publicKey, signature);
  }

  async rotateKey(params: RotateKeyParams): Promise<ProviderKeyResult> {
    return this.createKey({
      name: params.key.name,
      algorithm: params.key.algorithm,
      purpose: params.key.purpose,
      organizationId: params.key.organizationId,
      projectId: params.key.projectId,
      environmentId: params.key.environmentId,
    });
  }

  async disableKey(providerKeyId: string): Promise<void> {}
  async enableKey(providerKeyId: string): Promise<void> {}

  async scheduleDeletion(providerKeyId: string, pendingWindowDays: number = 7): Promise<Date> {
    return new Date(Date.now() + pendingWindowDays * 24 * 60 * 60 * 1000);
  }

  async cancelDeletion(providerKeyId: string): Promise<void> {}
  async recoverKey(providerKeyId: string): Promise<void> {}
  async purgeKey(providerKeyId: string): Promise<void> {}
  async destroyKey(providerKeyId: string): Promise<void> {}
}
