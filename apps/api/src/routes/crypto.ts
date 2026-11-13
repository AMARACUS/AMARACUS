/// <reference path="../types/express.d.ts" />
import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import {
  registry,
  cryptoEngine,
  CRYPTO_POLICIES,
  CryptoEngineError,
  AlgorithmId,
  TenantContext,
} from '@amaracus/crypto-core';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../middleware/auth';
import { createRateLimiter, payloadSizeLimiter } from '../middleware/rate-limiter';
import { db } from '../lib/data-store';
import { usageMeter } from '../lib/usage-meter';
import { requireOperationAllowance } from '../middleware/billing-guard';
import { cryptographicRuntime } from '../lib/runtime-service';

const router = Router({ mergeParams: true });

// Apply authentication, org membership, crypto permission, and rate limiting to all crypto routes
router.use(requireAuth);
router.use(requireOrgMember);
router.use(requireOrgPermission('crypto:execute'));
router.use(payloadSizeLimiter(1048576)); // 1MB limit
router.use(createRateLimiter({ limit: 300, windowMs: 60000 })); // 300 req/min for general crypto

// --- 1. ALGORITHM REGISTRY ---
router.get('/algorithms', (req: Request, res: Response) => {
  const algorithms = registry.getAll();
  res.json({
    data: algorithms,
    meta: {
      count: algorithms.length,
      registryVersion: '1.0.0',
    },
  });
});

// --- 2. CRYPTO POLICIES ---
router.get('/policies', (req: Request, res: Response) => {
  res.json({
    data: Object.values(CRYPTO_POLICIES),
    meta: {
      defaultPolicy: 'DEFAULT_SECURE',
    },
  });
});

// Helper for safe audit logging without leaking secrets or plaintexts
async function logSafeCryptoAudit(
  req: Request,
  operation: string,
  algorithm: string,
  status: 'SUCCESS' | 'FAILED',
  durationMs: number,
  extraMeta?: Record<string, any>
) {
  try {
    const operationId = (req.headers['idempotency-key'] as string) || (req as any).requestId || `op_${Date.now()}`;
    await db.createAuditEvent({
      organizationId: req.organizationId || null,
      userId: req.user?.id || null,
      action: `crypto:${operation}`,
      resourceType: 'CryptoOperation',
      resourceId: algorithm,
      metadata: {
        operation,
        algorithm,
        status,
        durationMs,
        ...extraMeta,
      },
      ipAddress: req.ip || null,
      userAgent: req.headers['user-agent'] || null,
    });

    // Record authoritative metered cryptographic usage on success
    if (status === 'SUCCESS' && req.organizationId) {
      await usageMeter.recordOperation({
        organizationId: req.organizationId,
        operationType: operation.toUpperCase(),
        quantity: 1,
        operationId,
      });
    }

    // Phase 10.5: Authoritative Cryptographic Operation persistence
    if (req.organizationId) {
      await db.createCryptographicOperation({
        id: (req as any).operationDbId || `op_${crypto.randomUUID()}`,
        requestId: (req as any).requestId || null,
        idempotencyKey: (req.headers['idempotency-key'] as string) || null,
        organizationId: req.organizationId,
        projectId: req.body?.projectId || (req.headers['x-project-id'] as string) || null,
        environmentId: req.body?.environmentId || (req.headers['x-environment-id'] as string) || null,
        operationType: operation.toUpperCase(),
        algorithm,
        keyId: req.body?.keyId || req.params?.keyId || null,
        status: status === 'SUCCESS' ? 'COMPLETED' : 'FAILED',
        durationMs,
        metadata: {
          operation,
          algorithm,
          status,
          durationMs,
          ...extraMeta,
        },
      });
    }
  } catch (err) {
    console.warn('[Usage Metering Warning] Could not record crypto operation usage:', err);
  }
}

// Guard all mutating cryptographic execution operations with Phase 11 billing checks
router.use(requireOperationAllowance(1));

// --- 3. HASH ---
router.post('/hash', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm, data, encoding, outputEncoding, policy } = req.body;

  if (!algorithm || data === undefined) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "algorithm" and "data" are required.' },
    });
    return;
  }

  try {
    const result = await cryptoEngine.hash(
      {
        algorithm: algorithm as AlgorithmId,
        data,
        encoding: encoding || 'utf8',
        outputEncoding: outputEncoding || 'hex',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hash', algorithm, 'SUCCESS', duration);

    res.json({
      data: result,
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hash', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 4. HMAC ---
router.post('/hmac', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm, key, data, dataEncoding, keyEncoding, outputEncoding, policy } = req.body;

  if (!algorithm || !key || data === undefined) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "algorithm", "key", and "data" are required.' },
    });
    return;
  }

  try {
    const result = await cryptoEngine.hmac(
      {
        algorithm: algorithm as AlgorithmId,
        key,
        data,
        dataEncoding: dataEncoding || 'utf8',
        keyEncoding: keyEncoding || 'utf8',
        outputEncoding: outputEncoding || 'hex',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hmac', algorithm, 'SUCCESS', duration);

    res.json({
      data: result,
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hmac', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 5. HMAC VERIFY ---
router.post('/hmac/verify', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm, key, data, mac, macEncoding, dataEncoding, keyEncoding, policy } = req.body;

  if (!algorithm || !key || data === undefined || !mac) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "algorithm", "key", "data", and "mac" are required.' },
    });
    return;
  }

  try {
    const valid = await cryptoEngine.verifyHmac(
      {
        algorithm: algorithm as AlgorithmId,
        key,
        data,
        mac,
        macEncoding: macEncoding || 'hex',
        dataEncoding: dataEncoding || 'utf8',
        keyEncoding: keyEncoding || 'utf8',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hmac_verify', algorithm, 'SUCCESS', duration);

    res.json({
      data: { valid, algorithm },
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hmac_verify', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 6. ENCRYPT (AES-256-GCM) ---
router.post('/encrypt', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'AES-256-GCM', key, plaintext, keyEncoding, plaintextEncoding, aad, aadEncoding, policy } = req.body;

  if (!key || plaintext === undefined) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "key" and "plaintext" are required.' },
    });
    return;
  }

  const normalizedAlg = (algorithm || 'AES-256-GCM').replace(/_/g, '-');
  const effectiveKeyEncoding =
    keyEncoding ||
    (typeof key === 'string' && /^[A-Za-z0-9+/=]+$/.test(key) && key.length % 4 === 0 && (key.length === 44 || key.length === 24 || key.length === 32)
      ? 'base64'
      : 'raw');

  try {
    const envelope = await cryptoEngine.encrypt(
      {
        algorithm: normalizedAlg as AlgorithmId,
        key,
        plaintext,
        keyEncoding: effectiveKeyEncoding,
        plaintextEncoding: plaintextEncoding || 'utf8',
        aad,
        aadEncoding: aadEncoding || 'utf8',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'encrypt', normalizedAlg, 'SUCCESS', duration);

    const envelopeResult = {
      ...envelope,
      ciphertext: envelope.ct,
      cipherText: envelope.ct,
    };

    res.json({
      data: envelopeResult,
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'encrypt', normalizedAlg, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 7. DECRYPT (AES-256-GCM) ---
router.post('/decrypt', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const rawCiphertext =
    req.body.ciphertext ||
    req.body.cipherText ||
    req.body.ct ||
    req.body.envelope?.ciphertext ||
    req.body.envelope?.cipherText ||
    req.body.envelope?.ct;

  const envelope = req.body.envelope
    ? {
        ...req.body.envelope,
        v: req.body.envelope.v || 1,
        alg: (req.body.envelope.alg || req.body.envelope.algorithm || 'AES-256-GCM').replace(/_/g, '-'),
        ct: rawCiphertext,
        ciphertext: rawCiphertext,
      }
    : {
        v: 1,
        alg: (req.body.algorithm || 'AES-256-GCM').replace(/_/g, '-'),
        iv: req.body.iv,
        ct: rawCiphertext,
        ciphertext: rawCiphertext,
        tag: req.body.tag,
        aad: req.body.aad || req.body.associatedData || null,
      };

  const { key, keyEncoding, outputEncoding, policy } = req.body;

  if (!envelope || !rawCiphertext || !key) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "envelope" (or "ciphertext") and "key" are required.' },
    });
    return;
  }

  const effectiveKeyEncoding =
    keyEncoding ||
    (typeof key === 'string' && /^[A-Za-z0-9+/=]+$/.test(key) && key.length % 4 === 0 && (key.length === 44 || key.length === 24 || key.length === 32)
      ? 'base64'
      : 'raw');

  try {
    const decrypted = await cryptoEngine.decrypt(
      {
        envelope: envelope as any,
        key,
        keyEncoding: effectiveKeyEncoding,
        outputEncoding: outputEncoding || 'utf8',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'decrypt', 'AES-256-GCM', 'SUCCESS', duration);

    res.json({
      data: { plaintext: decrypted },
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'decrypt', 'AES-256-GCM', 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 8. KEYPAIR GENERATION (DEMO / EPHEMERAL) ---
router.post('/keypair', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'ED25519' } = req.body;

  try {
    const keyPair = await cryptoEngine.generateKeyPair(algorithm as AlgorithmId);
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'generate_keypair', algorithm, 'SUCCESS', duration);

    res.json({
      data: keyPair,
      meta: {
        executionTimingMs: duration,
        notice: 'Ephemeral test keypair for playground and demo operations. Do not use for long-term secrets.',
      },
    });
  } catch (err: any) {
    handleCryptoError(err, res);
  }
});

// --- 9. SIGN (ED25519) ---
router.post('/sign', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'ED25519', privateKey, message, privateKeyEncoding, messageEncoding, signatureEncoding, policy } = req.body;

  if (!privateKey || message === undefined) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "privateKey" and "message" are required.' },
    });
    return;
  }

  try {
    const result = await cryptoEngine.sign(
      {
        algorithm: algorithm as AlgorithmId,
        privateKey,
        message,
        privateKeyEncoding,
        messageEncoding: messageEncoding || 'utf8',
        signatureEncoding: signatureEncoding || 'hex',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'sign', algorithm, 'SUCCESS', duration);

    res.json({
      data: result,
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'sign', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 10. VERIFY (ED25519) ---
router.post('/verify', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'ED25519', publicKey, message, signature, publicKeyEncoding, messageEncoding, signatureEncoding, policy } = req.body;

  if (!publicKey || message === undefined || !signature) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "publicKey", "message", and "signature" are required.' },
    });
    return;
  }

  try {
    const valid = await cryptoEngine.verify(
      {
        algorithm: algorithm as AlgorithmId,
        publicKey,
        message,
        signature,
        publicKeyEncoding,
        messageEncoding: messageEncoding || 'utf8',
        signatureEncoding: signatureEncoding || 'hex',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'verify', algorithm, 'SUCCESS', duration);

    res.json({
      data: { valid, algorithm },
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'verify', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 11. KEY AGREEMENT (X25519) ---
router.post('/key-agreement', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'X25519', privateKey, publicKey, privateKeyEncoding, publicKeyEncoding, outputEncoding, policy } = req.body;

  if (!privateKey || !publicKey) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "privateKey" and "publicKey" are required.' },
    });
    return;
  }

  try {
    const result = await cryptoEngine.keyAgreement(
      {
        algorithm: algorithm as AlgorithmId,
        privateKey,
        publicKey,
        privateKeyEncoding,
        publicKeyEncoding,
        outputEncoding: outputEncoding || 'hex',
      },
      policy || 'DEFAULT_SECURE'
    );

    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'key_agreement', algorithm, 'SUCCESS', duration);

    res.json({
      data: result,
      meta: { executionTimingMs: duration },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'key_agreement', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 12. SECURE RANDOM BYTES (CSPRNG) ---
router.post('/random', (req: Request, res: Response) => {
  const { length = 32, encoding = 'hex' } = req.body;

  const numBytes = parseInt(length, 10);
  if (isNaN(numBytes) || numBytes <= 0 || numBytes > 65536) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Field "length" must be an integer between 1 and 65536.' },
    });
    return;
  }

  try {
    const result = cryptoEngine.randomBytes(numBytes, encoding);
    res.json({
      data: result,
      meta: { provider: 'node-crypto-csprng' },
    });
  } catch (err: any) {
    handleCryptoError(err, res);
  }
});

// =========================================================================
// PHASE 6: POST-QUANTUM CRYPTOGRAPHY (PQC) ROUTES
// =========================================================================

// --- 13. PQC ALGORITHMS INVENTORY ---
router.get('/pqc/algorithms', (req: Request, res: Response) => {
  const pqc = registry.getPqcAlgorithms();
  const hybrid = registry.getHybridAlgorithms();
  res.json({
    data: {
      pqc,
      hybrid,
    },
    meta: {
      pqcCount: pqc.length,
      hybridCount: hybrid.length,
      fipsStandards: ['FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)', 'Hybrid X25519 + ML-KEM-768 (AMARACUS combiner, not IETF X-Wing)'],
    },
  });
});

// --- 14. CRYPTO AGILITY ENGINE ---
router.post('/pqc/agility/select', (req: Request, res: Response) => {
  const { operation, policy = 'DEFAULT_SECURE', minSecurityLevel, preferHybrid } = req.body;
  if (!operation) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Field "operation" is required.' },
    });
    return;
  }
  try {
    const selected = cryptoEngine.agility.selectAlgorithm({
      operation,
      policy,
      minSecurityLevel,
      preferHybrid,
    });
    res.json({
      data: {
        operation,
        selectedAlgorithm: selected,
        policy,
        algorithmMetadata: registry.get(selected),
      },
    });
  } catch (err: any) {
    handleCryptoError(err, res);
  }
});

router.post('/pqc/agility/migration-advice', (req: Request, res: Response) => {
  const { algorithm } = req.body;
  if (!algorithm) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Field "algorithm" is required.' },
    });
    return;
  }
  try {
    const advice = cryptoEngine.agility.getMigrationAdvice(algorithm as AlgorithmId);
    res.json({ data: advice });
  } catch (err: any) {
    handleCryptoError(err, res);
  }
});

// --- 15. ML-KEM (FIPS 203) KEY ENCAPSULATION ---
router.post('/kem/keygen', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'ML-KEM-768', encoding = 'hex', policy } = req.body;
  try {
    const result = await cryptoEngine.kemKeygen({ algorithm, encoding }, policy);
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'kem_keygen', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: { executionTimingMs: duration, standard: 'NIST FIPS 203' },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'kem_keygen', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

router.post('/kem/encapsulate', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'ML-KEM-768', publicKey, publicKeyEncoding, outputEncoding, policy } = req.body;
  if (!publicKey) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Field "publicKey" is required.' },
    });
    return;
  }
  try {
    const result = await cryptoEngine.kemEncapsulate(
      { algorithm, publicKey, publicKeyEncoding, outputEncoding },
      policy
    );
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'kem_encapsulate', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: { executionTimingMs: duration, standard: 'NIST FIPS 203' },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'kem_encapsulate', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

router.post('/kem/decapsulate', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const {
    algorithm = 'ML-KEM-768',
    privateKey,
    ciphertext,
    privateKeyEncoding,
    ciphertextEncoding,
    outputEncoding,
    policy,
  } = req.body;
  if (!privateKey || !ciphertext) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "privateKey" and "ciphertext" are required.' },
    });
    return;
  }
  try {
    const result = await cryptoEngine.kemDecapsulate(
      { algorithm, privateKey, ciphertext, privateKeyEncoding, ciphertextEncoding, outputEncoding },
      policy
    );
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'kem_decapsulate', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: { executionTimingMs: duration, standard: 'NIST FIPS 203' },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'kem_decapsulate', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 16. ML-DSA (FIPS 204) DIGITAL SIGNATURES ---
router.post('/signature/pqc-keygen', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'ML-DSA-65', encoding = 'hex', policy } = req.body;
  try {
    const result = await cryptoEngine.pqcKeygen({ algorithm, encoding }, policy);
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'pqc_signature_keygen', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: { executionTimingMs: duration, standard: 'NIST FIPS 204' },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'pqc_signature_keygen', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

router.post('/signature/pqc-sign', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const {
    algorithm = 'ML-DSA-65',
    privateKey,
    message,
    privateKeyEncoding,
    messageEncoding,
    signatureEncoding,
    outputEncoding,
    context,
    policy,
  } = req.body;
  if (!privateKey || message === undefined) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "privateKey" and "message" are required.' },
    });
    return;
  }
  try {
    const result = await cryptoEngine.pqcSign(
      {
        algorithm,
        privateKey,
        message,
        privateKeyEncoding,
        messageEncoding,
        signatureEncoding: signatureEncoding || outputEncoding || 'hex',
        outputEncoding,
        context,
      },
      policy
    );
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'pqc_signature_sign', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: { executionTimingMs: duration, standard: 'NIST FIPS 204' },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'pqc_signature_sign', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

router.post('/signature/pqc-verify', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const {
    algorithm = 'ML-DSA-65',
    publicKey,
    message,
    signature,
    publicKeyEncoding,
    messageEncoding,
    signatureEncoding,
    context,
    policy,
  } = req.body;
  if (!publicKey || message === undefined || !signature) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "publicKey", "message", and "signature" are required.' },
    });
    return;
  }
  try {
    const result = await cryptoEngine.pqcVerify(
      {
        algorithm,
        publicKey,
        message,
        signature,
        publicKeyEncoding,
        messageEncoding,
        signatureEncoding,
        context,
      },
      policy
    );
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'pqc_signature_verify', algorithm, result.valid ? 'SUCCESS' : 'FAILED', duration);
    res.json({
      data: result,
      meta: { executionTimingMs: duration, standard: 'NIST FIPS 204' },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'pqc_signature_verify', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

// --- 17. HYBRID POST-QUANTUM KEY EXCHANGE (X25519 + ML-KEM-768) ---
router.post('/hybrid/keygen', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'X25519+ML-KEM-768', encoding = 'hex', policy } = req.body;
  try {
    const result = await cryptoEngine.hybridKeygen({ algorithm, encoding }, policy);
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hybrid_keygen', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: {
        executionTimingMs: duration,
        standard: 'FIPS 203 + RFC 7748, HKDF-SHA256 combiner (not IETF X-Wing)',
        combiner: 'Dual-Combiner (HKDF-SHA256)',
      },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hybrid_keygen', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

router.post('/hybrid/encapsulate', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'X25519+ML-KEM-768', publicKey, encoding = 'hex', outputEncoding, policy } = req.body;
  if (!publicKey || !publicKey.x25519PublicKey || !publicKey.mlkemPublicKey) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Field "publicKey" must contain both "x25519PublicKey" and "mlkemPublicKey".' },
    });
    return;
  }
  try {
    const result = await cryptoEngine.hybridEncapsulate(
      { algorithm, publicKey, encoding, outputEncoding },
      policy
    );
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hybrid_encapsulate', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: {
        executionTimingMs: duration,
        standard: 'FIPS 203 + RFC 7748, HKDF-SHA256 combiner (not IETF X-Wing)',
      },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hybrid_encapsulate', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});

router.post('/hybrid/decapsulate', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { algorithm = 'X25519+ML-KEM-768', privateKey, ciphertext, encoding = 'hex', outputEncoding, policy } = req.body;
  if (!privateKey || !ciphertext) {
    res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Fields "privateKey" and "ciphertext" are required.' },
    });
    return;
  }
  try {
    const result = await cryptoEngine.hybridDecapsulate(
      { algorithm, privateKey, ciphertext, encoding, outputEncoding },
      policy
    );
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hybrid_decapsulate', algorithm, 'SUCCESS', duration);
    res.json({
      data: result,
      meta: {
        executionTimingMs: duration,
        standard: 'FIPS 203 + RFC 7748, HKDF-SHA256 combiner (not IETF X-Wing)',
      },
    });
  } catch (err: any) {
    const duration = Date.now() - startTime;
    await logSafeCryptoAudit(req, 'hybrid_decapsulate', algorithm, 'FAILED', duration);
    handleCryptoError(err, res);
  }
});
// ============================================================================
// Phase 10.5 — Universal Cryptographic Runtime Execution Endpoint
// POST /v1/organizations/:orgId/crypto/execute
// ============================================================================
router.post('/execute', async (req: Request, res: Response) => {
  const { keyId, keyReference, algorithm, policy, params = {}, idempotencyKey } = req.body;
  const type = req.body.type || req.body.operationType || 'ENCRYPT';
  const orgId = req.organizationId!;

  const tenantContext: TenantContext = {
    organizationId: orgId,
    projectId: req.body.projectId || (req.headers['x-project-id'] as string),
    environmentId: req.body.environmentId || (req.headers['x-environment-id'] as string),
    actorId: req.user?.id,
    actorType: req.user ? 'USER_SESSION' : 'API_KEY',
  };

  try {
    const result = await cryptographicRuntime.execute(
      {
        operationId: `op_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        requestId: (req as any).requestId,
        idempotencyKey: idempotencyKey || (req.headers['idempotency-key'] as string),
        type,
        keyId,
        keyReference,
        algorithm,
        policy,
        params,
      },
      tenantContext
    );

    if (!result.success) {
      return res.status(result.error?.statusCode || 400).json({
        error: result.error,
        operationId: result.operationId,
        requestId: result.requestId,
        status: result.status,
      });
    }

    res.json({
      data: result.data,
      meta: result.metadata,
      operationId: result.operationId,
      requestId: result.requestId,
      status: result.status,
    });
  } catch (err: any) {
    handleCryptoError(err, res);
  }
});

// ============================================================================
// Phase 10.5 — Cryptographic Operation Observability & History Endpoints
// GET /v1/organizations/:orgId/crypto/operations
// GET /v1/organizations/:orgId/crypto/operations/:operationId
// ============================================================================
router.get('/operations', async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
  const offset = req.query.offset ? parseInt(req.query.offset as string, 10) : 0;
  const status = req.query.status as string | undefined;
  const operationType = req.query.operationType as string | undefined;

  const operations = await db.listCryptographicOperations(orgId, { limit, offset, status, operationType });
  res.json({
    data: operations,
    meta: {
      count: operations.length,
      limit,
      offset,
    },
  });
});

router.get('/operations/:operationId', async (req: Request, res: Response) => {
  const op = await db.getCryptographicOperation(req.params.operationId);
  if (!op || op.organizationId !== req.organizationId) {
    return res.status(404).json({
      error: { code: 'NOT_FOUND', message: 'Cryptographic operation not found.' },
    });
  }

  res.json({ data: op });
});

// Safe centralized error translator: never leaks stack traces, keys, or plaintext
function handleCryptoError(err: any, res: Response) {
  if (err instanceof CryptoEngineError) {
    res.status(err.status).json({
      error: {
        code: err.code,
        message: err.message,
        details: err.details,
      },
    });
    return;
  }

  console.error('[Crypto API Unexpected Error]:', err.message);
  res.status(500).json({
    error: {
      code: 'INTERNAL_CRYPTO_ERROR',
      message: 'A secure cryptographic error occurred while processing the request.',
    },
  });
}

export default router;
