import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  AlgorithmId,
  PqcKeygenResult,
  PqcSignRequest,
  PqcSignResult,
  PqcVerifyRequest,
  PqcVerifyResult,
  PqcSecurityLevel,
} from '../types';
import { CryptoEngineError } from '../errors';
import { toBuffer, encodeBuffer } from '../encoding';

interface MlDsaSpec {
  instance: typeof ml_dsa65;
  securityLevel: PqcSecurityLevel;
  publicKeyBytes: number;
  privateKeyBytes: number;
  signatureBytes: number;
}

const ML_DSA_SPECS: Record<string, MlDsaSpec> = {
  'ML-DSA-44': {
    instance: ml_dsa44,
    securityLevel: 2,
    publicKeyBytes: 1312,
    privateKeyBytes: 2560,
    signatureBytes: 2420,
  },
  'ML-DSA-65': {
    instance: ml_dsa65,
    securityLevel: 3,
    publicKeyBytes: 1952,
    privateKeyBytes: 4032,
    signatureBytes: 3309,
  },
  'ML-DSA-87': {
    instance: ml_dsa87,
    securityLevel: 5,
    publicKeyBytes: 2592,
    privateKeyBytes: 4896,
    signatureBytes: 4627,
  },
};

function getSpec(algorithm: AlgorithmId): MlDsaSpec {
  const spec = ML_DSA_SPECS[algorithm];
  if (!spec) {
    throw new CryptoEngineError(
      'UNSUPPORTED_ALGORITHM',
      `Algorithm '${algorithm}' is not a supported ML-DSA parameter set. Supported: ML-DSA-44, ML-DSA-65, ML-DSA-87.`,
      400
    );
  }
  return spec;
}

export class MlDsaEngine {
  /**
   * Generates a standardized ML-DSA keypair conforming to NIST FIPS 204.
   */
  public static keygen(
    algorithm: AlgorithmId = 'ML-DSA-65',
    encoding: 'hex' | 'base64' | 'base64url' = 'hex',
    seed?: Buffer
  ): PqcKeygenResult {
    const spec = getSpec(algorithm);
    // Optional seed = xi (32 bytes, FIPS 204 ML-DSA.KeyGen_internal); used for known-answer tests and deterministic derivation
    if (seed && seed.length !== 32) {
      throw new CryptoEngineError('INVALID_INPUT', `Key generation seed must be 32 bytes, received ${seed.length}.`, 400);
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
   * Signs a message using an ML-DSA private key conforming to NIST FIPS 204.
   */
  public static sign(req: PqcSignRequest): PqcSignResult {
    const spec = getSpec(req.algorithm);
    const enc = req.outputEncoding || 'hex';

    const privBuf = toBuffer(req.privateKey, (req.privateKeyEncoding as any) || 'hex');
    if (privBuf.length !== spec.privateKeyBytes) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `ML-DSA secret key for '${req.algorithm}' must be exactly ${spec.privateKeyBytes} bytes, received ${privBuf.length} bytes.`,
        400
      );
    }

    const msgBuf = toBuffer(req.message, req.messageEncoding || 'utf8');

    let contextBytes: Uint8Array | undefined = undefined;
    if (req.context) {
      const ctxBuf = toBuffer(req.context, 'utf8');
      if (ctxBuf.length > 255) {
        throw new CryptoEngineError(
          'INVALID_INPUT',
          'ML-DSA context string must not exceed 255 bytes per FIPS 204.',
          400
        );
      }
      contextBytes = new Uint8Array(ctxBuf);
    }

    try {
      const sig = spec.instance.sign(
        new Uint8Array(msgBuf),
        new Uint8Array(privBuf),
        contextBytes ? { context: contextBytes } : undefined
      );
      const sigBuf = Buffer.from(sig);

      return {
        algorithm: req.algorithm,
        signature: encodeBuffer(sigBuf, enc),
        encoding: enc,
        signatureBytes: sigBuf.length,
      };
    } catch (err: any) {
      throw new CryptoEngineError(
        'CRYPTO_OPERATION_FAILED',
        `ML-DSA signing failed: ${err.message}`,
        500
      );
    } finally {
      // Memory hygiene: clear private key buffer
      privBuf.fill(0);
    }
  }

  /**
   * Verifies an ML-DSA digital signature conforming to NIST FIPS 204.
   */
  public static verify(req: PqcVerifyRequest): PqcVerifyResult {
    const spec = getSpec(req.algorithm);

    const pubBuf = toBuffer(req.publicKey, (req.publicKeyEncoding as any) || 'hex');
    if (pubBuf.length !== spec.publicKeyBytes) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `ML-DSA public key for '${req.algorithm}' must be exactly ${spec.publicKeyBytes} bytes, received ${pubBuf.length} bytes.`,
        400
      );
    }

    const sigBuf = toBuffer(req.signature, (req.signatureEncoding as any) || 'hex');
    if (sigBuf.length !== spec.signatureBytes) {
      // Per FIPS 204, malformed signature sizes fail verification safely
      return { algorithm: req.algorithm, valid: false };
    }

    const msgBuf = toBuffer(req.message, req.messageEncoding || 'utf8');

    let contextBytes: Uint8Array | undefined = undefined;
    if (req.context) {
      const ctxBuf = toBuffer(req.context, 'utf8');
      if (ctxBuf.length > 255) {
        return { algorithm: req.algorithm, valid: false };
      }
      contextBytes = new Uint8Array(ctxBuf);
    }

    try {
      const valid = spec.instance.verify(
        new Uint8Array(sigBuf),
        new Uint8Array(msgBuf),
        new Uint8Array(pubBuf),
        contextBytes ? { context: contextBytes } : undefined
      );

      return {
        algorithm: req.algorithm,
        valid: Boolean(valid),
      };
    } catch {
      return { algorithm: req.algorithm, valid: false };
    }
  }

  public generateKeyPair(
    algorithm: AlgorithmId = 'ML-DSA-65',
    encoding: 'hex' | 'base64' | 'base64url' = 'hex'
  ): PqcKeygenResult {
    return MlDsaEngine.keygen(algorithm, encoding);
  }

  public keygen(
    algorithm: AlgorithmId = 'ML-DSA-65',
    encoding: 'hex' | 'base64' | 'base64url' = 'hex'
  ): PqcKeygenResult {
    return MlDsaEngine.keygen(algorithm, encoding);
  }

  public sign(req: PqcSignRequest): PqcSignResult {
    return MlDsaEngine.sign(req);
  }

  public verify(req: PqcVerifyRequest): PqcVerifyResult {
    return MlDsaEngine.verify(req);
  }
}

export const mlDsaEngine = new MlDsaEngine();
