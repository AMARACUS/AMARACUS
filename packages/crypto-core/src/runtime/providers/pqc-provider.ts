/**
 * AMARACUS Cryptographic Infrastructure — Post-Quantum Cryptography (PQC) Provider
 *
 * Implements CryptographicProvider wrapping NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA),
 * and Hybrid X-Wing (X25519 + ML-KEM-768) quantum-safe cryptographic engines.
 */

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
import { EncryptedEnvelope } from '../../types';
import crypto from 'crypto';
import { mlKemEngine, mlDsaEngine, hybridKemEngine } from '../../pqc';
import { CryptoEngineError } from '../../errors';
import { LocalDevKeyProvider } from '../../keys/providers/local-dev-provider';

export class PqcCryptographicProvider implements CryptographicProvider {
  public readonly id = 'PQC_ENGINE';
  public readonly name = 'AMARACUS Post-Quantum Cryptography Provider';

  private readonly localKeys = new LocalDevKeyProvider();

  public readonly capabilities: ProviderCapabilityMap = {
    encryption: false, // PQC uses KEM encapsulation rather than direct symmetric block encryption
    decryption: false,
    signing: true,
    verification: true,
    hashing: false,
    hmac: false,
    keyGeneration: true,
    keyRotation: false,
    keyWrapping: true,
    keyUnwrapping: true,
    pqc: true,
    hardwareBacked: false,
    // Implements FIPS 203 / 204 (via @noble/post-quantum); not a CMVP-validated module
    fipsValidated: false,
    supportedAlgorithms: [
      'ML-KEM-512',
      'ML-KEM-768',
      'ML-KEM-1024',
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
      'X25519+ML-KEM-768',
    ],
    supportedPurposes: ['SIGNING', 'KEY_AGREEMENT', 'KEY_WRAPPING'],
  };

  public async isAvailable(): Promise<boolean> {
    return true;
  }

  public async healthCheck(): Promise<ProviderHealthReport> {
    return {
      providerId: this.id,
      name: this.name,
      status: 'AVAILABLE',
      message: 'Post-Quantum Cryptography engines (ML-KEM, ML-DSA, Hybrid X-Wing) are operational.',
      capabilities: this.capabilities,
      timestamp: new Date().toISOString(),
    };
  }

  public supportsOperation(operation: OperationType, algorithm?: string): boolean {
    const alg = (algorithm || '').toUpperCase().replace(/_/g, '-');
    if (alg && !this.capabilities.supportedAlgorithms.includes(alg)) {
      return false;
    }
    switch (operation) {
      case 'SIGN':
      case 'VERIFY':
      case 'PQC_SIGN':
      case 'PQC_VERIFY':
      case 'KEM_KEYGEN':
      case 'KEM_ENCAPSULATE':
      case 'KEM_DECAPSULATE':
      case 'KEY_GEN':
        return true;
      default:
        return false;
    }
  }

  public async encrypt(params: ProviderEncryptParams): Promise<EncryptedEnvelope> {
    throw new CryptoEngineError(
      'UNSUPPORTED_OPERATION',
      'PQC provider does not support direct block encryption. Use KEM encapsulation to establish a shared secret.'
    );
  }

  public async decrypt(params: ProviderDecryptParams): Promise<Buffer> {
    throw new CryptoEngineError(
      'UNSUPPORTED_OPERATION',
      'PQC provider does not support direct block decryption. Use KEM decapsulation to recover the shared secret.'
    );
  }

  public async sign(params: ProviderSignParams): Promise<Buffer> {
    const alg = params.algorithm.toUpperCase().replace(/_/g, '-');
    if (!alg.startsWith('ML-DSA-')) {
      throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Algorithm '${alg}' is not a supported PQC signature algorithm.`);
    }

    const privateKeyStr = typeof params.privateKey === 'string'
      ? params.privateKey
      : params.privateKey
      ? params.privateKey.toString('hex')
      : '';

    if (!privateKeyStr) {
      throw new CryptoEngineError('INVALID_KEY', 'Private key is required for PQC signing.');
    }

    const res = await mlDsaEngine.sign({
      algorithm: alg as any,
      privateKey: privateKeyStr,
      message: params.data,
    });

    return Buffer.from(res.signature, 'hex');
  }

  public async verify(params: ProviderVerifyParams): Promise<boolean> {
    const alg = params.algorithm.toUpperCase().replace(/_/g, '-');
    if (!alg.startsWith('ML-DSA-')) {
      throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Algorithm '${alg}' is not a supported PQC signature algorithm.`);
    }

    const publicKeyStr = typeof params.publicKey === 'string'
      ? params.publicKey
      : params.publicKey
      ? params.publicKey.toString('hex')
      : '';

    if (!publicKeyStr) {
      throw new CryptoEngineError('INVALID_KEY', 'Public key is required for PQC verification.');
    }

    const res = await mlDsaEngine.verify({
      algorithm: alg as any,
      publicKey: publicKeyStr,
      message: params.data,
      signature: params.signature.toString('hex'),
    });

    return res.valid;
  }

  public async generateKey(params: ProviderKeyGenParams): Promise<ProviderKeyGenResult> {
    const alg = params.algorithm.toUpperCase().replace(/_/g, '-');
    if (!alg.startsWith('ML-KEM-') && !alg.startsWith('ML-DSA-') && alg !== 'X25519+ML-KEM-768') {
      throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `PQC algorithm '${alg}' not supported for key generation.`);
    }
    // The local key provider wraps the private key under the master KEK before it is returned
    return this.localKeys.createKey({
      name: params.name,
      algorithm: alg as any,
      purpose: params.purpose as any,
      organizationId: 'internal',
      projectId: 'internal',
      environmentId: 'internal',
      metadata: params.metadata,
    });
  }

  // --- Extended PQC operations ---
  public async kemEncapsulate(algorithm: string, publicKey: any) {
    const alg = algorithm.toUpperCase().replace(/_/g, '-');
    if (alg.startsWith('ML-KEM-')) {
      return mlKemEngine.encapsulate({ algorithm: alg as any, publicKey });
    }
    if (alg === 'X25519+ML-KEM-768') {
      const pk = typeof publicKey === 'string' && publicKey.startsWith('{') ? JSON.parse(publicKey) : publicKey;
      return hybridKemEngine.encapsulate({ algorithm: 'X25519+ML-KEM-768', publicKey: pk });
    }
    throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `KEM algorithm '${alg}' not supported.`);
  }

  public async kemDecapsulate(algorithm: string, ciphertext: any, privateKey: any) {
    const alg = algorithm.toUpperCase().replace(/_/g, '-');
    if (alg.startsWith('ML-KEM-')) {
      return mlKemEngine.decapsulate({ algorithm: alg as any, ciphertext, privateKey });
    }
    if (alg === 'X25519+ML-KEM-768') {
      const sk = typeof privateKey === 'string' && privateKey.startsWith('{') ? JSON.parse(privateKey) : privateKey;
      return hybridKemEngine.decapsulate({ algorithm: 'X25519+ML-KEM-768', ciphertext, privateKey: sk });
    }
    throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `KEM algorithm '${alg}' not supported.`);
  }
}
