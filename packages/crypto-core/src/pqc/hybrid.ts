import crypto from 'crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  HybridKeygenResult,
  HybridEncapsulateRequest,
  HybridEncapsulateResult,
  HybridDecapsulateRequest,
  HybridDecapsulateResult,
  HybridPublicKey,
  HybridPrivateKey,
  HybridCiphertext,
} from '../types';
import { CryptoEngineError } from '../errors';
import { toBuffer, encodeBuffer } from '../encoding';

/**
 * Domain separation string for AMARACUS Hybrid Key Encapsulation (X25519 + ML-KEM-768).
 * Ensures cryptographic domain isolation per NIST SP 800-56C / RFC 5869.
 */
export const HYBRID_DOMAIN_SEPARATOR = 'AMARACUS-HYBRID-KEM-X25519-ML-KEM-768-v1';

export class HybridKemEngine {
  /**
   * Generates a composite hybrid keypair consisting of:
   * 1. Classical X25519 keypair (32 bytes raw public key, 32 bytes raw private key)
   * 2. Post-quantum ML-KEM-768 keypair (1184 bytes public key, 2400 bytes secret key)
   */
  public static keygen(
    encoding: 'hex' | 'base64' | 'base64url' = 'hex'
  ): HybridKeygenResult {
    // 1. Classical X25519 Keypair
    const x25519Pair = crypto.generateKeyPairSync('x25519');
    const x25519PubDer = x25519Pair.publicKey.export({ type: 'spki', format: 'der' });
    const x25519PrivDer = x25519Pair.privateKey.export({ type: 'pkcs8', format: 'der' });

    // Raw 32-byte representation (last 32 bytes of standard SPKI/PKCS8 for X25519)
    const x25519PubRaw = x25519PubDer.subarray(x25519PubDer.length - 32);
    const x25519PrivRaw = x25519PrivDer.subarray(x25519PrivDer.length - 32);

    // 2. Post-Quantum ML-KEM-768 Keypair
    const mlkemPair = ml_kem768.keygen();
    const mlkemPubBuf = Buffer.from(mlkemPair.publicKey);
    const mlkemPrivBuf = Buffer.from(mlkemPair.secretKey);

    const publicKey: HybridPublicKey = {
      x25519PublicKey: encodeBuffer(x25519PubRaw, encoding),
      mlkemPublicKey: encodeBuffer(mlkemPubBuf, encoding),
    };

    const privateKey: HybridPrivateKey = {
      x25519PrivateKey: encodeBuffer(x25519PrivRaw, encoding),
      mlkemPrivateKey: encodeBuffer(mlkemPrivBuf, encoding),
    };

    return {
      algorithm: 'X25519+ML-KEM-768',
      publicKey,
      privateKey,
      encoding,
    };
  }

  /**
   * Encapsulates a composite shared secret using both X25519 and ML-KEM-768.
   *
   * Construction:
   * 1. Sender generates ephemeral X25519 keypair (ek_x25519, epk_x25519).
   * 2. Sender computes ECDH: ss_classical = X25519(ek_x25519, recipient.pk_x25519) [32 bytes].
   * 3. Sender encapsulates ML-KEM: (ct_mlkem, ss_pqc) = ml_kem768.encapsulate(recipient.pk_mlkem) [1088 bytes, 32 bytes].
   * 4. Combined Ciphertext: epk_x25519 (32 bytes) || ct_mlkem (1088 bytes) = 1120 bytes.
   * 5. Combined Shared Secret: HKDF-SHA256(ikm = ss_classical || ss_pqc, salt = ct_mlkem, info = HYBRID_DOMAIN_SEPARATOR) [32 bytes].
   */
  public static encapsulate(req: HybridEncapsulateRequest): HybridEncapsulateResult {
    const enc = req.encoding || 'hex';
    const outEnc = req.outputEncoding || enc;

    if (!req.publicKey || !req.publicKey.x25519PublicKey || !req.publicKey.mlkemPublicKey) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        'Hybrid encapsulation requires both x25519PublicKey and mlkemPublicKey.',
        400
      );
    }

    const x25519PubBuf = toBuffer(req.publicKey.x25519PublicKey, enc as any);
    if (x25519PubBuf.length !== 32) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `X25519 public key must be exactly 32 bytes, received ${x25519PubBuf.length}.`,
        400
      );
    }

    const mlkemPubBuf = toBuffer(req.publicKey.mlkemPublicKey, enc as any);
    if (mlkemPubBuf.length !== 1184) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `ML-KEM-768 public key must be exactly 1184 bytes, received ${mlkemPubBuf.length}.`,
        400
      );
    }

    try {
      // 1. Ephemeral X25519 keypair
      const ephemeralX25519 = crypto.generateKeyPairSync('x25519');
      const ephPubDer = ephemeralX25519.publicKey.export({ type: 'spki', format: 'der' });
      const ephPubRaw = ephPubDer.subarray(ephPubDer.length - 32);

      // Re-construct recipient SPKI key object
      const recipientSpkiHeader = Buffer.from('302a300506032b656e032100', 'hex');
      const recipientKeyObject = crypto.createPublicKey({
        key: Buffer.concat([recipientSpkiHeader, x25519PubBuf]),
        format: 'der',
        type: 'spki',
      });

      // Classical shared secret
      const ssClassical = crypto.diffieHellman({
        privateKey: ephemeralX25519.privateKey,
        publicKey: recipientKeyObject,
      });

      // 2. ML-KEM-768 encapsulation
      const { cipherText: mlkemCt, sharedSecret: ssPqc } = ml_kem768.encapsulate(
        new Uint8Array(mlkemPubBuf)
      );
      const mlkemCtBuf = Buffer.from(mlkemCt);
      const ssPqcBuf = Buffer.from(ssPqc);

      // 3. Combined Ciphertext
      const combinedCtBuf = Buffer.concat([ephPubRaw, mlkemCtBuf]);

      // 4. Combined KDF: HKDF-SHA256
      const ikm = Buffer.concat([ssClassical, ssPqcBuf]);
      const derivedSharedSecret = crypto.hkdfSync(
        'sha256',
        ikm,
        mlkemCtBuf, // Salt binds KDF to the specific encapsulation
        Buffer.from(HYBRID_DOMAIN_SEPARATOR, 'utf8'),
        32
      );

      // Clean up sensitive memory buffers
      ssClassical.fill(0);
      ssPqcBuf.fill(0);
      ikm.fill(0);

      const ciphertext: HybridCiphertext = {
        ephemeralX25519PublicKey: encodeBuffer(ephPubRaw, outEnc),
        mlkemCiphertext: encodeBuffer(mlkemCtBuf, outEnc),
      };

      return {
        algorithm: 'X25519+ML-KEM-768',
        ciphertext,
        combinedCiphertext: encodeBuffer(combinedCtBuf, outEnc),
        sharedSecret: encodeBuffer(Buffer.from(derivedSharedSecret), outEnc),
        encoding: outEnc,
      };
    } catch (err: any) {
      throw new CryptoEngineError(
        'CRYPTO_OPERATION_FAILED',
        `Hybrid encapsulation failed: ${err.message}`,
        500
      );
    }
  }

  /**
   * Decapsulates a composite shared secret using the recipient's hybrid private key.
   */
  public static decapsulate(req: HybridDecapsulateRequest): HybridDecapsulateResult {
    const enc = req.encoding || 'hex';
    const outEnc = req.outputEncoding || enc;

    if (!req.privateKey || !req.privateKey.x25519PrivateKey || !req.privateKey.mlkemPrivateKey) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        'Hybrid decapsulation requires both x25519PrivateKey and mlkemPrivateKey.',
        400
      );
    }

    const x25519PrivBuf = toBuffer(req.privateKey.x25519PrivateKey, enc as any);
    if (x25519PrivBuf.length !== 32) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `X25519 private key must be exactly 32 bytes, received ${x25519PrivBuf.length}.`,
        400
      );
    }

    const mlkemPrivBuf = toBuffer(req.privateKey.mlkemPrivateKey, enc as any);
    if (mlkemPrivBuf.length !== 2400) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `ML-KEM-768 private key must be exactly 2400 bytes, received ${mlkemPrivBuf.length}.`,
        400
      );
    }

    // Resolve ciphertext parts
    let ephPubBuf: Buffer;
    let mlkemCtBuf: Buffer;

    if (typeof req.ciphertext === 'string') {
      const fullCtBuf = toBuffer(req.ciphertext, enc as any);
      if (fullCtBuf.length !== 1120) {
        throw new CryptoEngineError(
          'INVALID_INPUT',
          `Combined hybrid ciphertext must be exactly 1120 bytes (32 ephemeral + 1088 ML-KEM), received ${fullCtBuf.length}.`,
          400
        );
      }
      ephPubBuf = fullCtBuf.subarray(0, 32);
      mlkemCtBuf = fullCtBuf.subarray(32);
    } else {
      ephPubBuf = toBuffer(req.ciphertext.ephemeralX25519PublicKey, enc as any);
      mlkemCtBuf = toBuffer(req.ciphertext.mlkemCiphertext, enc as any);

      if (ephPubBuf.length !== 32) {
        throw new CryptoEngineError(
          'INVALID_INPUT',
          `Ephemeral X25519 public key must be 32 bytes, received ${ephPubBuf.length}.`,
          400
        );
      }
      if (mlkemCtBuf.length !== 1088) {
        throw new CryptoEngineError(
          'INVALID_INPUT',
          `ML-KEM-768 ciphertext must be 1088 bytes, received ${mlkemCtBuf.length}.`,
          400
        );
      }
    }

    try {
      // 1. Classical ECDH
      const privPkcs8Header = Buffer.from('302e020100300506032b656e04220420', 'hex');
      const privKeyObject = crypto.createPrivateKey({
        key: Buffer.concat([privPkcs8Header, x25519PrivBuf]),
        format: 'der',
        type: 'pkcs8',
      });

      const ephSpkiHeader = Buffer.from('302a300506032b656e032100', 'hex');
      const ephKeyObject = crypto.createPublicKey({
        key: Buffer.concat([ephSpkiHeader, ephPubBuf]),
        format: 'der',
        type: 'spki',
      });

      const ssClassical = crypto.diffieHellman({
        privateKey: privKeyObject,
        publicKey: ephKeyObject,
      });

      // 2. ML-KEM-768 decapsulation
      const ssPqc = ml_kem768.decapsulate(
        new Uint8Array(mlkemCtBuf),
        new Uint8Array(mlkemPrivBuf)
      );
      const ssPqcBuf = Buffer.from(ssPqc);

      // 3. Combined KDF: HKDF-SHA256
      const ikm = Buffer.concat([ssClassical, ssPqcBuf]);
      const derivedSharedSecret = crypto.hkdfSync(
        'sha256',
        ikm,
        mlkemCtBuf,
        Buffer.from(HYBRID_DOMAIN_SEPARATOR, 'utf8'),
        32
      );

      // Zeroize intermediate secrets
      ssClassical.fill(0);
      ssPqcBuf.fill(0);
      ikm.fill(0);

      return {
        algorithm: 'X25519+ML-KEM-768',
        sharedSecret: encodeBuffer(Buffer.from(derivedSharedSecret), outEnc),
        encoding: outEnc,
      };
    } catch (err: any) {
      throw new CryptoEngineError(
        'CRYPTO_OPERATION_FAILED',
        `Hybrid decapsulation failed: ${err.message}`,
        500
      );
    } finally {
      // Zeroize private key buffers
      x25519PrivBuf.fill(0);
      mlkemPrivBuf.fill(0);
    }
  }

  public generateKeyPair(encoding: 'hex' | 'base64' | 'base64url' = 'hex'): HybridKeygenResult {
    return HybridKemEngine.keygen(encoding);
  }

  public keygen(encoding: 'hex' | 'base64' | 'base64url' = 'hex'): HybridKeygenResult {
    return HybridKemEngine.keygen(encoding);
  }

  public encapsulate(req: HybridEncapsulateRequest): HybridEncapsulateResult {
    return HybridKemEngine.encapsulate(req);
  }

  public decapsulate(req: HybridDecapsulateRequest): HybridDecapsulateResult {
    return HybridKemEngine.decapsulate(req);
  }
}

export const hybridKemEngine = new HybridKemEngine();
