import crypto from 'crypto';
import {
  AlgorithmId,
  EncryptedEnvelope,
  HashRequest,
  HashResult,
  HmacRequest,
  HmacResult,
  HmacVerifyRequest,
  EncryptRequest,
  DecryptRequest,
  SignRequest,
  SignResult,
  VerifySignatureRequest,
  KeyAgreementRequest,
  KeyAgreementResult,
  KeyPairResult,
} from '../types';
import { CryptoEngineError } from '../errors';
import { toBuffer, encodeBuffer, constantTimeEqual, generateSecureRandom } from '../encoding';
import { normalizeAlgorithmId } from '../registry';
import { CURRENT_ENVELOPE_VERSION, parseEnvelope } from '../envelope';
import { registry } from '../registry';

export class NodeCryptoProvider {
  // --- HASHING ---
  public async hash(req: HashRequest): Promise<HashResult> {
    registry.validate(req.algorithm, 'hash');
    const dataBuf = toBuffer(req.data, req.encoding || 'utf8');

    let nodeAlg: string;
    switch (normalizeAlgorithmId(req.algorithm)) {
      case 'SHA-256':
        nodeAlg = 'sha256';
        break;
      case 'SHA-384':
        nodeAlg = 'sha384';
        break;
      case 'SHA-512':
        nodeAlg = 'sha512';
        break;
      case 'SHA3-256':
        nodeAlg = 'sha3-256';
        break;
      case 'SHA3-384':
        nodeAlg = 'sha3-384';
        break;
      case 'SHA3-512':
        nodeAlg = 'sha3-512';
        break;
      default:
        throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Unsupported hash algorithm: ${req.algorithm}`);
    }

    const digestBuf = crypto.createHash(nodeAlg).update(dataBuf).digest();
    const outputEncoding = req.outputEncoding || 'hex';

    return {
      algorithm: req.algorithm,
      digest: encodeBuffer(digestBuf, outputEncoding),
      encoding: outputEncoding,
      byteLength: digestBuf.length,
    };
  }

  // --- HMAC ---
  public async hmac(req: HmacRequest): Promise<HmacResult> {
    registry.validate(req.algorithm, 'hmac');
    const keyBuf = toBuffer(req.key, req.keyEncoding || 'utf8');
    const dataBuf = toBuffer(req.data, req.dataEncoding || 'utf8');

    if (keyBuf.length === 0) {
      throw new CryptoEngineError('INVALID_KEY', 'HMAC key must not be empty.');
    }

    let nodeAlg: string;
    switch (normalizeAlgorithmId(req.algorithm)) {
      case 'HMAC-SHA-256':
        nodeAlg = 'sha256';
        break;
      case 'HMAC-SHA-384':
        nodeAlg = 'sha384';
        break;
      case 'HMAC-SHA-512':
        nodeAlg = 'sha512';
        break;
      default:
        throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Unsupported HMAC algorithm: ${req.algorithm}`);
    }

    const macBuf = crypto.createHmac(nodeAlg, keyBuf).update(dataBuf).digest();
    const outputEncoding = req.outputEncoding || 'hex';

    return {
      algorithm: req.algorithm,
      mac: encodeBuffer(macBuf, outputEncoding),
      encoding: outputEncoding,
    };
  }

  public async verifyHmac(req: HmacVerifyRequest): Promise<boolean> {
    registry.validate(req.algorithm, 'hmac_verify');
    const expected = await this.hmac({
      algorithm: req.algorithm,
      key: req.key,
      data: req.data,
      keyEncoding: req.keyEncoding,
      dataEncoding: req.dataEncoding,
      outputEncoding: req.macEncoding || 'hex',
    });

    const macBuf = toBuffer(req.mac, req.macEncoding || 'hex');
    const expectedBuf = toBuffer(expected.mac, expected.encoding);

    return constantTimeEqual(macBuf, expectedBuf);
  }

  // --- AES-256-GCM ---
  public async encrypt(req: EncryptRequest): Promise<EncryptedEnvelope> {
    registry.validate(req.algorithm, 'encrypt');
    if (req.algorithm !== 'AES-256-GCM') {
      throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Provider only supports AES-256-GCM for AEAD, got ${req.algorithm}`);
    }

    const keyBuf = toBuffer(req.key, req.keyEncoding || 'raw');
    if (keyBuf.length !== 32) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `AES-256-GCM requires exactly 32 bytes (256 bits) of key material, received ${keyBuf.length} bytes.`
      );
    }

    const plaintextBuf = toBuffer(req.plaintext, req.plaintextEncoding || 'utf8');
    // 96-bit (12-byte) cryptographically secure random IV
    const iv = generateSecureRandom(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);

    let aadBuf: Buffer | undefined;
    if (req.aad) {
      aadBuf = toBuffer(req.aad, req.aadEncoding || 'utf8');
      cipher.setAAD(aadBuf);
    }

    const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      v: CURRENT_ENVELOPE_VERSION,
      alg: 'AES-256-GCM',
      iv: encodeBuffer(iv, 'base64url'),
      ct: encodeBuffer(ciphertext, 'base64url'),
      tag: encodeBuffer(tag, 'base64url'),
      aad: aadBuf ? encodeBuffer(aadBuf, 'base64url') : null,
    };
  }

  public async decrypt(req: DecryptRequest): Promise<string> {
    const envelope = parseEnvelope(req.envelope);
    const keyBuf = toBuffer(req.key, req.keyEncoding || 'raw');

    if (keyBuf.length !== 32) {
      throw new CryptoEngineError(
        'INVALID_KEY',
        `AES-256-GCM requires exactly 32 bytes (256 bits) of key material, received ${keyBuf.length} bytes.`
      );
    }

    const iv = toBuffer(envelope.iv, 'base64url');
    const ciphertext = toBuffer(envelope.ct, 'base64url');
    const tag = toBuffer(envelope.tag, 'base64url');

    if (iv.length !== 12) {
      throw new CryptoEngineError('INVALID_NONCE', `AES-256-GCM nonce must be 12 bytes, got ${iv.length} bytes.`);
    }
    if (tag.length !== 16) {
      throw new CryptoEngineError('AUTHENTICATION_FAILED', `AES-256-GCM tag must be 16 bytes, got ${tag.length} bytes.`);
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
    decipher.setAuthTag(tag);

    if (envelope.aad) {
      const aadBuf = toBuffer(envelope.aad, 'base64url');
      decipher.setAAD(aadBuf);
    }

    let decrypted: Buffer;
    try {
      decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new CryptoEngineError(
        'AUTHENTICATION_FAILED',
        'Decryption failed: ciphertext integrity verification or authentication tag check failed.'
      );
    }

    const outputEncoding = req.outputEncoding || 'utf8';
    return encodeBuffer(decrypted, outputEncoding);
  }

  // --- DIGITAL SIGNATURES (Ed25519) ---
  public async generateEd25519KeyPair(): Promise<KeyPairResult> {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

    return {
      algorithm: 'ED25519',
      publicKey: publicKey.export({ type: 'spki', format: 'pem' }) as string,
      privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
      format: 'pem',
    };
  }

  public async sign(req: SignRequest): Promise<SignResult> {
    registry.validate(req.algorithm, 'sign');
    if (req.algorithm !== 'ED25519') {
      throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Provider only supports ED25519 signatures, got ${req.algorithm}`);
    }

    const messageBuf = toBuffer(req.message, req.messageEncoding || 'utf8');

    let privKey: crypto.KeyObject;
    try {
      if (typeof req.privateKey === 'string' && req.privateKey.includes('-----BEGIN')) {
        privKey = crypto.createPrivateKey({ key: req.privateKey, format: 'pem' });
      } else {
        const rawBuf = toBuffer(req.privateKey, req.privateKeyEncoding === 'raw' ? 'hex' : 'utf8');
        if (rawBuf.length === 32) {
          // Wrap raw 32-byte Ed25519 private seed into standard PKCS#8 DER envelope (RFC 8410)
          const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
          privKey = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, rawBuf]), format: 'der', type: 'pkcs8' });
        } else {
          privKey = crypto.createPrivateKey(req.privateKey);
        }
      }
    } catch {
      throw new CryptoEngineError('INVALID_KEY', 'Invalid or unparseable Ed25519 private key.');
    }

    try {
      const signatureBuf = crypto.sign(null, messageBuf, privKey);
      const signatureEncoding = req.signatureEncoding || 'hex';

      return {
        algorithm: 'ED25519',
        signature: encodeBuffer(signatureBuf, signatureEncoding),
        encoding: signatureEncoding,
      };
    } catch {
      throw new CryptoEngineError('INTERNAL_CRYPTO_ERROR', 'Failed to generate Ed25519 digital signature.');
    }
  }

  public async verify(req: VerifySignatureRequest): Promise<boolean> {
    registry.validate(req.algorithm, 'verify');
    if (req.algorithm !== 'ED25519') {
      throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Provider only supports ED25519 signatures, got ${req.algorithm}`);
    }

    const messageBuf = toBuffer(req.message, req.messageEncoding || 'utf8');
    const signatureBuf = toBuffer(req.signature, req.signatureEncoding || 'hex');

    if (signatureBuf.length !== 64) {
      return false; // Ed25519 signatures are strictly 64 bytes
    }

    let pubKey: crypto.KeyObject;
    try {
      if (typeof req.publicKey === 'string' && req.publicKey.includes('-----BEGIN')) {
        pubKey = crypto.createPublicKey({ key: req.publicKey, format: 'pem' });
      } else {
        const rawBuf = toBuffer(req.publicKey, req.publicKeyEncoding === 'raw' ? 'hex' : 'utf8');
        if (rawBuf.length === 32) {
          // Wrap raw 32-byte Ed25519 public key into standard SPKI DER envelope (RFC 8410)
          const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
          pubKey = crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, rawBuf]), format: 'der', type: 'spki' });
        } else {
          pubKey = crypto.createPublicKey(req.publicKey);
        }
      }
    } catch {
      throw new CryptoEngineError('INVALID_KEY', 'Invalid or unparseable Ed25519 public key.');
    }

    try {
      return crypto.verify(null, messageBuf, pubKey, signatureBuf);
    } catch {
      return false;
    }
  }

  // --- KEY AGREEMENT (X25519) ---
  public async generateX25519KeyPair(): Promise<KeyPairResult> {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');

    return {
      algorithm: 'X25519',
      publicKey: publicKey.export({ type: 'spki', format: 'pem' }) as string,
      privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
      format: 'pem',
    };
  }

  public async keyAgreement(req: KeyAgreementRequest): Promise<KeyAgreementResult> {
    registry.validate(req.algorithm, 'key_agreement');
    if (req.algorithm !== 'X25519') {
      throw new CryptoEngineError('UNSUPPORTED_ALGORITHM', `Provider only supports X25519 key agreement, got ${req.algorithm}`);
    }

    let privKey: crypto.KeyObject;
    let pubKey: crypto.KeyObject;

    try {
      if (typeof req.privateKey === 'string' && req.privateKey.includes('-----BEGIN')) {
        privKey = crypto.createPrivateKey({ key: req.privateKey, format: 'pem' });
      } else {
        const rawBuf = toBuffer(req.privateKey, req.privateKeyEncoding === 'raw' ? 'hex' : 'utf8');
        if (rawBuf.length === 32) {
          const pkcs8Prefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
          privKey = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, rawBuf]), format: 'der', type: 'pkcs8' });
        } else {
          privKey = crypto.createPrivateKey(req.privateKey);
        }
      }
    } catch {
      throw new CryptoEngineError('INVALID_KEY', 'Invalid X25519 private key.');
    }

    try {
      if (typeof req.publicKey === 'string' && req.publicKey.includes('-----BEGIN')) {
        pubKey = crypto.createPublicKey({ key: req.publicKey, format: 'pem' });
      } else {
        const rawBuf = toBuffer(req.publicKey, req.publicKeyEncoding === 'raw' ? 'hex' : 'utf8');
        if (rawBuf.length === 32) {
          const spkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');
          pubKey = crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, rawBuf]), format: 'der', type: 'spki' });
        } else {
          pubKey = crypto.createPublicKey(req.publicKey);
        }
      }
    } catch {
      throw new CryptoEngineError('INVALID_KEY', 'Invalid X25519 public key.');
    }

    try {
      const sharedSecret = crypto.diffieHellman({ privateKey: privKey, publicKey: pubKey });
      const outputEncoding = req.outputEncoding || 'hex';

      return {
        algorithm: 'X25519',
        sharedSecret: encodeBuffer(sharedSecret, outputEncoding),
        encoding: outputEncoding,
      };
    } catch (err: any) {
      throw new CryptoEngineError('INTERNAL_CRYPTO_ERROR', `X25519 key agreement failed: ${err.message}`);
    }
  }
}
