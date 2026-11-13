/**
 * AMARACUS — Phase 9: Fully Homomorphic Encryption (FHE) Engine
 * Powered by Microsoft SEAL. Provides key generation, encryption,
 * decryption, and homomorphic evaluation (ADD, SUBTRACT, MULTIPLY, NEGATE)
 * directly on ciphertexts without server-side decryption.
 */

import { SealBackend } from './seal-backend';
import {
  FheCiphertext,
  FheEvaluationRequest,
  FheEvaluationResult,
  FheKeyMetadata,
  FheLimits,
  FheScheme
} from '../types';
import { CryptoEngineError } from '../../errors';

interface StoredFheKey {
  metadata: FheKeyMetadata;
  secretKeyBase64: string;
  context: any;
  seal: any;
  batchEncoder: any;
  encryptor: any;
  decryptor: any;
  evaluator: any;
}

export class FheEngine {
  private static keyStore = new Map<string, StoredFheKey>();

  /**
   * Generates a new FHE keypair (public key, secret key, relinearization keys)
   * Only BFV exact integer scheme is currently supported in production.
   */
  public static async generateKeypair(
    organizationId: string,
    scheme: FheScheme = 'BFV',
    polyModulusDegree: 4096 | 8192 = 4096,
    projectId?: string,
    environmentId?: string
  ): Promise<FheKeyMetadata> {
    if (scheme !== 'BFV') {
      throw new CryptoEngineError(
        'OPERATION_NOT_SUPPORTED',
        `FHE scheme '${scheme}' is experimental or not supported by this backend. Only 'BFV' (exact integer) is currently supported.`,
        400
      );
    }

    if (polyModulusDegree !== 4096 && polyModulusDegree !== 8192) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `Unsupported polynomial modulus degree ${polyModulusDegree}. Supported degrees are 4096 and 8192.`,
        400
      );
    }

    const { seal, context } = await SealBackend.createBfvContext(polyModulusDegree);
    const keyGen = seal.KeyGenerator(context);
    const secretKey = keyGen.secretKey();
    const publicKey = keyGen.createPublicKey();
    const relinKeys = keyGen.createRelinKeys();

    const encryptor = seal.Encryptor(context, publicKey);
    const decryptor = seal.Decryptor(context, secretKey);
    const evaluator = seal.Evaluator(context);
    const batchEncoder = seal.BatchEncoder(context);

    const keyId = `fhe-key-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const publicKeyBase64 = publicKey.save();
    const relinKeysBase64 = relinKeys.save();
    const secretKeyBase64 = secretKey.save();

    const metadata: FheKeyMetadata = {
      id: keyId,
      organizationId,
      projectId,
      environmentId,
      scheme,
      polyModulusDegree,
      publicKeyBase64,
      relinKeysBase64,
      hasSecretKey: true,
      createdAt: new Date().toISOString()
    };

    this.keyStore.set(keyId, {
      metadata,
      secretKeyBase64,
      context,
      seal,
      batchEncoder,
      encryptor,
      decryptor,
      evaluator
    });

    return metadata;
  }

  /**
   * Retrieves key metadata without exposing the secret key
   */
  public static getKey(keyId: string, organizationId?: string): FheKeyMetadata {
    const stored = this.keyStore.get(keyId);
    if (!stored) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `FHE Key '${keyId}' not found`, 404);
    }
    if (organizationId && stored.metadata.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to FHE Key '${keyId}'`, 403);
    }
    return stored.metadata;
  }

  /**
   * Encrypt an integer value homomorphically using public key
   */
  public static async encrypt(
    keyId: string,
    value: number,
    organizationId?: string
  ): Promise<FheCiphertext> {
    const stored = this.keyStore.get(keyId);
    if (!stored) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `FHE Key '${keyId}' not found`, 404);
    }
    if (organizationId && stored.metadata.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to FHE Key '${keyId}'`, 403);
    }

    if (!Number.isInteger(value)) {
      throw new CryptoEngineError(
        'INVALID_REQUEST',
        `BFV scheme operates strictly on exact integers. Received non-integer: ${value}`,
        400
      );
    }

    const { batchEncoder, encryptor, metadata } = stored;
    const plain = batchEncoder.encode(Int32Array.from([value]));
    const cipher = encryptor.encrypt(plain);
    const ciphertextBase64 = cipher.save();

    return {
      keyId,
      scheme: metadata.scheme,
      polyModulusDegree: metadata.polyModulusDegree,
      ciphertextBase64,
      operationDepth: 0
    };
  }

  /**
   * Decrypt a ciphertext using the private key
   */
  public static async decrypt(
    keyId: string,
    ciphertextBase64: string,
    organizationId?: string
  ): Promise<number> {
    const stored = this.keyStore.get(keyId);
    if (!stored) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `FHE Key '${keyId}' not found`, 404);
    }
    if (organizationId && stored.metadata.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to FHE Key '${keyId}'`, 403);
    }

    const { seal, context, decryptor, batchEncoder } = stored;
    let cipher: any;
    try {
      cipher = seal.CipherText();
      cipher.load(context, ciphertextBase64);
    } catch {
      throw new CryptoEngineError('INVALID_REQUEST', 'Failed to load ciphertext: malformed or incompatible format', 400);
    }

    const plain = decryptor.decrypt(cipher);
    const decoded = batchEncoder.decode(plain);
    return decoded[0];
  }

  /**
   * Execute homomorphic computation directly on ciphertexts WITHOUT decryption
   */
  public static async evaluate(
    request: FheEvaluationRequest,
    organizationId?: string
  ): Promise<FheEvaluationResult> {
    const startTime = Date.now();
    const stored = this.keyStore.get(request.keyId);
    if (!stored) {
      throw new CryptoEngineError('RESOURCE_NOT_FOUND', `FHE Key '${request.keyId}' not found`, 404);
    }
    if (organizationId && stored.metadata.organizationId !== organizationId) {
      throw new CryptoEngineError('TENANT_ACCESS_DENIED', `Access denied to FHE Key '${request.keyId}'`, 403);
    }

    const { seal, context, evaluator, metadata } = stored;

    if (!['ADD', 'SUBTRACT', 'MULTIPLY', 'NEGATE'].includes(request.operation)) {
      throw new CryptoEngineError(
        'OPERATION_NOT_SUPPORTED',
        `Unsupported FHE operation '${request.operation}'. Supported operations: ADD, SUBTRACT, MULTIPLY, NEGATE.`,
        400
      );
    }

    if (request.operation === 'NEGATE') {
      if (!request.ciphertexts || request.ciphertexts.length < 1) {
        throw new CryptoEngineError('INVALID_REQUEST', 'NEGATE requires 1 input ciphertext', 400);
      }
    } else if (!request.ciphertexts || request.ciphertexts.length < 2) {
      throw new CryptoEngineError('INVALID_REQUEST', `${request.operation} requires at least 2 input ciphertexts`, 400);
    }

    // Load ciphertexts
    const loadedCiphers: any[] = [];
    for (let i = 0; i < request.ciphertexts.length; i++) {
      try {
        const c = seal.CipherText();
        c.load(context, request.ciphertexts[i]);
        loadedCiphers.push(c);
      } catch {
        throw new CryptoEngineError(
          'INVALID_REQUEST',
          `Failed to deserialize input ciphertext at index ${i}`,
          400
        );
      }
    }

    let resultCipher: any;
    let operationDepth = 1;

    try {
      if (request.operation === 'ADD') {
        resultCipher = evaluator.add(loadedCiphers[0], loadedCiphers[1]);
        for (let i = 2; i < loadedCiphers.length; i++) {
          resultCipher = evaluator.add(resultCipher, loadedCiphers[i]);
        }
      } else if (request.operation === 'SUBTRACT') {
        resultCipher = evaluator.sub(loadedCiphers[0], loadedCiphers[1]);
      } else if (request.operation === 'MULTIPLY') {
        // Multiplicative depth increases noise budget consumption
        operationDepth = 2;
        resultCipher = evaluator.multiply(loadedCiphers[0], loadedCiphers[1]);
      } else if (request.operation === 'NEGATE') {
        resultCipher = evaluator.negate(loadedCiphers[0]);
      }
    } catch (err: any) {
      throw new CryptoEngineError(
        'CRYPTO_OPERATION_FAILED',
        `Homomorphic ${request.operation} computation failed: ${err.message}`,
        500
      );
    }

    const resultCiphertextBase64 = resultCipher.save();

    return {
      keyId: request.keyId,
      scheme: metadata.scheme,
      operation: request.operation,
      resultCiphertextBase64,
      operationDepth,
      durationMs: Date.now() - startTime
    };
  }

  /**
   * System limits and capability transparency
   */
  public static getLimits(): FheLimits {
    return {
      maxPolyModulusDegree: 8192,
      maxMultiplicationDepth: 4,
      maxCiphertextSizeBytes: 10 * 1024 * 1024, // 10MB limit
      supportedSchemes: ['BFV'],
      supportedOperations: ['ADD', 'SUBTRACT', 'MULTIPLY', 'NEGATE']
    };
  }
}
