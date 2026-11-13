import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import {
  AlgorithmId,
  KemKeygenResult,
  KemEncapsulateRequest,
  KemEncapsulateResult,
  KemDecapsulateRequest,
  KemDecapsulateResult,
  PqcSecurityLevel,
} from '../types';
import { CryptoEngineError } from '../errors';
import { toBuffer, encodeBuffer } from '../encoding';

interface MlKemSpec {
  instance: typeof ml_kem768;
  securityLevel: PqcSecurityLevel;
  publicKeyBytes: number;
  privateKeyBytes: number;
  ciphertoBytes: number;
  sharedSecretBytes: number;
}

const ML_KEM_SPECS: Record<string, MlKemSpec> = {
  'ML-KEM-512': {
    instance: ml_kem512,
    securityLevel: 1,
    publicKeyBytes: 800,
    privateKeyBytes: 1632,
    ciphertoBytes: 768,
    sharedSecretBytes: 32,
  },
  'ML-KEM-768': {
    instance: ml_kem768,
    securityLevel: 3,
    publicKeyBytes: 1184,
    privateKeyBytes: 2400,
    ciphertoBytes: 1088,
    sharedSecretBytes: 32,
  },
  'ML-KEM-1024': {
    instance: ml_kem1024,
    securityLevel: 5,
    publicKeyBytes: 1568,
    privateKeyBytes: 3168,
    ciphertoBytes: 1568,
    sharedSecretBytes: 32,
  },
};

function getSpec(algorithm: AlgorithmId): MlKemSpec {
  const spec = ML_KEM_SPECS[algorithm];
  if (!spec) {
    throw new CryptoEngineError(
      'UNSUPPORTED_ALGORITHM',
      `Algorithm '${algorithm}' is not a supported ML-KEM parameter set. Supported: ML-KEM-512, ML-KEM-768, ML-KEM-1024.`,
      400
    );
  }
  return spec;
}

export class MlKemEngine {
  /**
   * Generates a standardized ML-KEM keypair conforming to NIST FIPS 203.
   */
  public static keygen(
    algorithm: AlgorithmId = 'ML-KEM-768',
    encoding: 'hex' | 'base64' | 'base64url' = 'hex',
    seed?: Buffer
  ): KemKeygenResult {
    const spec = getSpec(algorithm);
    // Optional seed = d || z (64 bytes, FIPS 203 ML-KEM.KeyGen_internal); used for known-answer tests and deterministic derivation
    if (seed && seed.length !== 64) {
      throw new CryptoEngineError('INVALID_INPUT', `Key generation seed must be 64 bytes, received ${seed.length}.`, 400);
    }
    const keypair = seed ? spec.instance.keygen(new Uint8Array(seed)) : spec.instance.keygen();

    const pubBuf = Buffer.from(keypair.publicKey);
    const privBuf = Buffer.from(keypair.secretKey);

    return {
      algorithm,
      publicKey: encodeBuffer(pubBuf, encoding),
      privateKey: encodeBuffer(privBuf, encoding),
      encoding,
      securityLevel: spec.securityLevel,
      publicKeyBytes: pubBuf.length,
      privateKeyBytes: privBuf.length,
    };
  }

  /**
   * Encapsulates a shared secret under the recipient's ML-KEM public key.
   * Conforms strictly to NIST FIPS 203 Section 6.2 (ML-KEM.Encaps).
   */
  public static encapsulate(req: KemEncapsulateRequest): KemEncapsulateResult {
    const spec = getSpec(req.algorithm);
    const enc = req.outputEncoding || 'hex';

    const pubBuf = toBuffer(req.publicKey, (req.publicKeyEncoding as any) || 'hex');
    if (pubBuf.length !== spec.publicKeyBytes) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `ML-KEM public key for '${req.algorithm}' must be exactly ${spec.publicKeyBytes} bytes, received ${pubBuf.length} bytes.`,
        400
      );
    }

    try {
      // Fixed 32-byte randomness m is only for known-answer tests; omit it in normal use
      const m = req.randomness ? toBuffer(req.randomness, 'hex') : undefined;
      const { cipherText, sharedSecret } = m
        ? spec.instance.encapsulate(new Uint8Array(pubBuf), new Uint8Array(m))
        : spec.instance.encapsulate(new Uint8Array(pubBuf));
      const ctBuf = Buffer.from(cipherText);
      const ssBuf = Buffer.from(sharedSecret);

      return {
        algorithm: req.algorithm,
        ciphertext: encodeBuffer(ctBuf, enc),
        sharedSecret: encodeBuffer(ssBuf, enc),
        encoding: enc,
        ciphertextBytes: ctBuf.length,
        sharedSecretBytes: ssBuf.length,
      };
    } catch (err: any) {
      throw new CryptoEngineError(
        'CRYPTO_OPERATION_FAILED',
        `ML-KEM encapsulation failed: ${err.message}`,
        500
      );
    }
  }

  /**
   * Decapsulates the shared secret from a ciphertext using the recipient's ML-KEM secret key.
   * Conforms strictly to NIST FIPS 203 Section 6.3 (ML-KEM.Decaps).
   */
  public static decapsulate(req: KemDecapsulateRequest): KemDecapsulateResult {
    const spec = getSpec(req.algorithm);
    const enc = req.outputEncoding || 'hex';

    const privBuf = toBuffer(req.privateKey, (req.privateKeyEncoding as any) || 'hex');
    if (privBuf.length !== spec.privateKeyBytes) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `ML-KEM secret key for '${req.algorithm}' must be exactly ${spec.privateKeyBytes} bytes, received ${privBuf.length} bytes.`,
        400
      );
    }

    const ctBuf = toBuffer(req.ciphertext, (req.ciphertextEncoding as any) || 'hex');
    if (ctBuf.length !== spec.ciphertoBytes) {
      throw new CryptoEngineError(
        'INVALID_INPUT',
        `ML-KEM ciphertext for '${req.algorithm}' must be exactly ${spec.ciphertoBytes} bytes, received ${ctBuf.length} bytes.`,
        400
      );
    }

    try {
      const sharedSecret = spec.instance.decapsulate(
        new Uint8Array(ctBuf),
        new Uint8Array(privBuf)
      );
      const ssBuf = Buffer.from(sharedSecret);

      return {
        algorithm: req.algorithm,
        sharedSecret: encodeBuffer(ssBuf, enc),
        encoding: enc,
        sharedSecretBytes: ssBuf.length,
      };
    } catch (err: any) {
      throw new CryptoEngineError(
        'CRYPTO_OPERATION_FAILED',
        `ML-KEM decapsulation failed: ${err.message}`,
        500
      );
    } finally {
      // Memory hygiene: clear private key buffer
      privBuf.fill(0);
    }
  }

  public generateKeyPair(
    algorithm: AlgorithmId = 'ML-KEM-768',
    encoding: 'hex' | 'base64' | 'base64url' = 'hex'
  ): KemKeygenResult {
    return MlKemEngine.keygen(algorithm, encoding);
  }

  public keygen(
    algorithm: AlgorithmId = 'ML-KEM-768',
    encoding: 'hex' | 'base64' | 'base64url' = 'hex'
  ): KemKeygenResult {
    return MlKemEngine.keygen(algorithm, encoding);
  }

  public encapsulate(req: KemEncapsulateRequest): KemEncapsulateResult {
    return MlKemEngine.encapsulate(req);
  }

  public decapsulate(req: KemDecapsulateRequest): KemDecapsulateResult {
    return MlKemEngine.decapsulate(req);
  }
}

export const mlKemEngine = new MlKemEngine();
