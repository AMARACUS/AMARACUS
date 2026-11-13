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
  KemKeygenRequest,
  KemKeygenResult,
  KemEncapsulateRequest,
  KemEncapsulateResult,
  KemDecapsulateRequest,
  KemDecapsulateResult,
  PqcSignatureKeygenRequest,
  PqcSignatureKeygenResult,
  PqcSignRequest,
  PqcSignResult,
  PqcVerifyRequest,
  PqcVerifyResult,
  HybridKeygenRequest,
  HybridKeygenResult,
  HybridEncapsulateRequest,
  HybridEncapsulateResult,
  HybridDecapsulateRequest,
  HybridDecapsulateResult,
} from './types';
import { registry } from './registry';
import { CryptoPolicyEngine } from './policy';
import { NodeCryptoProvider } from './providers/node-crypto-provider';
import { generateSecureRandom, encodeBuffer } from './encoding';
import {
  mlKemEngine,
  mlDsaEngine,
  hybridKemEngine,
  cryptoAgilityEngine,
} from './pqc';

export class CryptoEngineService {
  private readonly provider: NodeCryptoProvider;
  public readonly agility = cryptoAgilityEngine;

  constructor() {
    this.provider = new NodeCryptoProvider();
  }

  public async hash(req: HashRequest, policy = 'DEFAULT_SECURE'): Promise<HashResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'hash');
    return this.provider.hash(req);
  }

  public async hmac(req: HmacRequest, policy = 'DEFAULT_SECURE'): Promise<HmacResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'hmac');
    return this.provider.hmac(req);
  }

  public async verifyHmac(req: HmacVerifyRequest, policy = 'DEFAULT_SECURE'): Promise<boolean> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'hmac_verify');
    return this.provider.verifyHmac(req);
  }

  public async encrypt(req: EncryptRequest, policy = 'DEFAULT_SECURE'): Promise<EncryptedEnvelope> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'encrypt');
    return this.provider.encrypt(req);
  }

  public async decrypt(req: DecryptRequest, policy = 'DEFAULT_SECURE'): Promise<string> {
    return this.provider.decrypt(req);
  }

  public async sign(req: SignRequest, policy = 'DEFAULT_SECURE'): Promise<SignResult> {
    if (req.algorithm.startsWith('ML-DSA-')) {
      CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'sign');
      const pqcRes = await mlDsaEngine.sign({
        algorithm: req.algorithm as any,
        privateKey: req.privateKey,
        message: req.message,
      });
      return {
        signature: pqcRes.signature,
        encoding: 'hex',
        algorithm: req.algorithm,
      };
    }
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'sign');
    return this.provider.sign(req);
  }

  public async verify(req: VerifySignatureRequest, policy = 'DEFAULT_SECURE'): Promise<boolean> {
    if (req.algorithm.startsWith('ML-DSA-')) {
      CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'verify');
      const pqcRes = await mlDsaEngine.verify({
        algorithm: req.algorithm as any,
        publicKey: req.publicKey,
        message: req.message,
        signature: req.signature,
      });
      return pqcRes.valid;
    }
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'verify');
    return this.provider.verify(req);
  }

  public async keyAgreement(req: KeyAgreementRequest, policy = 'DEFAULT_SECURE'): Promise<KeyAgreementResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'key_agreement');
    return this.provider.keyAgreement(req);
  }

  public async generateKeyPair(algorithm: AlgorithmId): Promise<KeyPairResult | KemKeygenResult | PqcSignatureKeygenResult | HybridKeygenResult> {
    if (algorithm === 'ED25519') {
      return this.provider.generateEd25519KeyPair();
    }
    if (algorithm === 'X25519') {
      return this.provider.generateX25519KeyPair();
    }
    if (algorithm.startsWith('ML-KEM-')) {
      return this.kemKeygen({ algorithm: algorithm as any });
    }
    if (algorithm.startsWith('ML-DSA-')) {
      return this.pqcKeygen({ algorithm: algorithm as any });
    }
    if (algorithm === 'X25519+ML-KEM-768') {
      return this.hybridKeygen();
    }
    throw new Error(`Keypair generation not supported for algorithm ${algorithm}`);
  }

  public randomBytes(length: number, encoding: 'hex' | 'base64' | 'base64url' = 'hex'): { random: string; length: number } {
    const buf = generateSecureRandom(length);
    return {
      random: encodeBuffer(buf, encoding),
      length: buf.length,
    };
  }

  // =========================================================================
  // PHASE 6: POST-QUANTUM CRYPTOGRAPHY (PQC) ENGINES
  // =========================================================================

  // --- NIST FIPS 203: ML-KEM ---
  public async kemKeygen(req: KemKeygenRequest, policy = 'PQC_PREFERRED'): Promise<KemKeygenResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'kem_keygen');
    const encoding = (req as any).encoding || (req as any).outputEncoding || 'hex';
    return mlKemEngine.generateKeyPair(req.algorithm, encoding);
  }

  public async kemEncapsulate(req: KemEncapsulateRequest, policy = 'PQC_PREFERRED'): Promise<KemEncapsulateResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'kem_encapsulate');
    return mlKemEngine.encapsulate(req);
  }

  public async kemDecapsulate(req: KemDecapsulateRequest, policy = 'PQC_PREFERRED'): Promise<KemDecapsulateResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'kem_decapsulate');
    return mlKemEngine.decapsulate(req);
  }

  // --- NIST FIPS 204: ML-DSA ---
  public async pqcKeygen(req: PqcSignatureKeygenRequest, policy = 'PQC_PREFERRED'): Promise<PqcSignatureKeygenResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'pqc_sign');
    const encoding = (req as any).encoding || (req as any).outputEncoding || 'hex';
    return mlDsaEngine.generateKeyPair(req.algorithm, encoding);
  }

  public async pqcSign(req: PqcSignRequest, policy = 'PQC_PREFERRED'): Promise<PqcSignResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'pqc_sign');
    return mlDsaEngine.sign(req);
  }

  public async pqcVerify(req: PqcVerifyRequest, policy = 'PQC_PREFERRED'): Promise<PqcVerifyResult> {
    CryptoPolicyEngine.validateOperation(policy, req.algorithm, 'pqc_verify');
    return mlDsaEngine.verify(req);
  }

  // --- HYBRID KEY EXCHANGE (X25519 + ML-KEM-768) ---
  public async hybridKeygen(req?: HybridKeygenRequest, policy = 'PQC_PREFERRED'): Promise<HybridKeygenResult> {
    const algorithm = req?.algorithm || 'X25519+ML-KEM-768';
    CryptoPolicyEngine.validateOperation(policy, algorithm, 'hybrid_keygen');
    return hybridKemEngine.generateKeyPair();
  }

  public async hybridEncapsulate(req: HybridEncapsulateRequest, policy = 'PQC_PREFERRED'): Promise<HybridEncapsulateResult> {
    const alg = req.algorithm || 'X25519+ML-KEM-768';
    CryptoPolicyEngine.validateOperation(policy, alg, 'hybrid_encapsulate');
    return hybridKemEngine.encapsulate(req);
  }

  public async hybridDecapsulate(req: HybridDecapsulateRequest, policy = 'PQC_PREFERRED'): Promise<HybridDecapsulateResult> {
    const alg = req.algorithm || 'X25519+ML-KEM-768';
    CryptoPolicyEngine.validateOperation(policy, alg, 'hybrid_decapsulate');
    return hybridKemEngine.decapsulate(req);
  }
}

export const cryptoEngine = new CryptoEngineService();
