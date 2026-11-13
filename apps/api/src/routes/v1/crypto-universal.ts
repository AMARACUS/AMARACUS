import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import {
  registry,
  AlgorithmId,
  TenantContext,
  CryptoEngineError,
  EncryptedEnvelope,
  parseEnvelope,
  serializeEnvelope,
} from '@amaracus/crypto-core';
import { requireAuth, requireOrgMember } from '../../middleware/auth';
import { roleHasScope } from '../../lib/permissions';
import { hasRequiredScope } from '../../lib/api-keys';
import { createRateLimiter, organizationCryptoLimiter, payloadSizeLimiter } from '../../middleware/rate-limiter';
import { requireOperationAllowance } from '../../middleware/billing-guard';
import { cryptographicRuntime } from '../../lib/runtime-service';
import { db } from '../../lib/data-store';
import { CapabilityDiscoveryService } from '@amaracus/crypto-core';
import { publicError } from '../../middleware/response-formatter';

const router = Router();
const capabilityDiscovery = new CapabilityDiscoveryService();

const cryptoMiddleware = [
  requireAuth,
  requireOrgMember,
  payloadSizeLimiter(1048576),
  createRateLimiter({ limit: 300, windowMs: 60000 }), // per API key (or user), per route
  organizationCryptoLimiter(), // per organization, all routes and keys together
];

// ---------------------------------------------------------------------------
// Scope Enforcement Helper
// ---------------------------------------------------------------------------
function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    // User sessions are authorized by their organization role
    if (!req.apiKey) {
      if (roleHasScope(req.orgRole, scope)) return next();
      const requestId = (req as any).requestId || (req.headers['x-request-id'] as string) || `req_${Date.now()}`;
      return res.status(403).json({
        error: {
          code: 'FORBIDDEN',
          message: `Role '${req.orgRole}' is not permitted to perform '${scope}'.`,
          retryable: false,
        },
        operationId: null,
        requestId,
      });
    }

    if (!hasRequiredScope(req.apiKey.scopes, scope)) {
      const requestId = (req as any).requestId || (req.headers['x-request-id'] as string) || `req_${Date.now()}`;
      return res.status(403).json({
        error: {
          code: 'INSUFFICIENT_SCOPE',
          message: `Credential lacks the required '${scope}' scope for this operation.`,
          retryable: false,
        },
        operationId: null,
        requestId,
      });
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Standard Response Helpers
// ---------------------------------------------------------------------------
function sendUniversalSuccess(res: Response, req: Request, data: any, operationId: string) {
  const requestId = (req as any).requestId || (req.headers['x-request-id'] as string) || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);
  return res.status(200).json({
    data,
    operationId,
    requestId,
    status: 'COMPLETED',
  });
}

function sendUniversalError(
  res: Response,
  req: Request,
  status: number,
  code: string,
  message: string,
  operationId?: string | null,
  retryable: boolean = false
) {
  const requestId = (req as any).requestId || (req.headers['x-request-id'] as string) || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);
  return res.status(status).json({
    error: {
      code,
      message,
      retryable,
    },
    operationId: operationId || null,
    requestId,
  });
}

/**
 * Encodes decrypted bytes for JSON. UTF-8 is honoured only when the bytes are valid
 * UTF-8; otherwise the plaintext is returned as base64 rather than silently corrupted.
 */
function encodePlaintext(buf: Buffer, requested: string): { plaintext: string; encoding: string } {
  const encoding = ['base64', 'base64url', 'hex'].includes(requested) ? requested : 'utf8';
  if (encoding === 'utf8') {
    try {
      return { plaintext: new TextDecoder('utf-8', { fatal: true }).decode(buf), encoding: 'utf8' };
    } catch {
      return { plaintext: buf.toString('base64'), encoding: 'base64' };
    }
  }
  return { plaintext: buf.toString(encoding as BufferEncoding), encoding };
}

function buildTenantContext(req: Request): TenantContext {
  return {
    organizationId: req.organizationId!,
    projectId: req.projectId || (req.headers['x-project-id'] as string) || req.body?.projectId,
    environmentId: req.environmentId || (req.headers['x-environment-id'] as string) || req.body?.environmentId,
    actorId: req.apiKey?.id || req.user?.id,
    actorType: req.apiKey ? 'API_KEY' : 'USER_SESSION',
  };
}

// ===========================================================================
// 1. ENCRYPT API
// POST /v1/encrypt (or /api/v1/encrypt)
// ===========================================================================
router.post(
  '/encrypt',
  ...cryptoMiddleware,
  requireScope('crypto:encrypt'),
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const {
      key,
      rawKey,
      algorithm,
      data,
      plaintext,
      encoding = 'utf8',
      aad,
      version,
      policy = 'DEFAULT_SECURE',
    } = req.body;

    const keyId = key;
    if (!keyId && !rawKey) {
      return sendUniversalError(
        res,
        req,
        400,
        'INVALID_REQUEST',
        'Either "key" (logical key ID or name) or "rawKey" must be provided.'
      );
    }

    const inputData = data !== undefined ? data : plaintext;
    if (inputData === undefined || inputData === null) {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', 'Field "data" is required for encryption.');
    }

    // Convert input data to buffer safely according to requested encoding
    let plaintextBuf: Buffer;
    try {
      plaintextBuf = Buffer.isBuffer(inputData)
        ? inputData
        : Buffer.from(String(inputData), encoding === 'base64' ? 'base64' : 'utf8');
    } catch {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', `Failed to decode data using encoding '${encoding}'.`);
    }

    const tenantContext = buildTenantContext(req);
    const operationId = `op_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const idempotencyKey = (req.headers['idempotency-key'] as string) || req.body?.idempotencyKey;

    try {
      const result = await cryptographicRuntime.execute(
        {
          operationId,
          requestId: (req as any).requestId,
          idempotencyKey,
          type: 'ENCRYPT',
          keyId: keyId || undefined,
          algorithm: algorithm || undefined,
          policy,
          params: {
            plaintext: plaintextBuf,
            key: rawKey || undefined,
            keyEncoding: rawKey ? (typeof rawKey === 'string' && /^[0-9a-fA-F]{64}$/.test(rawKey) ? 'hex' : 'base64') : undefined,
            aad,
            version,
          },
        },
        tenantContext
      );

      if (!result.success) {
        const statusCode = result.error?.statusCode || 400;
        return sendUniversalError(
          res,
          req,
          statusCode,
          result.error?.code || 'OPERATION_FAILED',
          result.error?.message || 'Encryption failed.',
          result.operationId,
          result.error?.retryable
        );
      }

      const envData = result.data;
      return sendUniversalSuccess(
        res,
        req,
        {
          ciphertext: envData.ct,
          iv: envData.iv,
          tag: envData.tag,
          aad: aad !== undefined ? aad : undefined,
          // Provider-wrapped data key (Azure Key Vault / Managed HSM); decryption needs it
          wrappedDek: envData.wrappedDek || undefined,
          wrapAlg: envData.wrapAlg || undefined,
          // Everything needed to decrypt, as one opaque base64url string
          envelope: serializeEnvelope({
            ...envData,
            keyVersion: Number(result.metadata.keyVersion) || null,
          }),
          algorithm: result.metadata.algorithm,
          keyId: result.metadata.keyId || keyId || undefined,
          keyVersion: result.metadata.keyVersion !== undefined ? result.metadata.keyVersion : undefined,
          format: 'v1',
        },
        result.operationId
      );
    } catch (err: any) {
      const e = publicError(err, 'An unexpected cryptographic error occurred.');
      return sendUniversalError(res, req, e.status, e.code, e.message, operationId);
    }
  }
);

// ===========================================================================
// 2. DECRYPT API
// POST /v1/decrypt (or /api/v1/decrypt)
// ===========================================================================
router.post(
  '/decrypt',
  ...cryptoMiddleware,
  requireScope('crypto:decrypt'),
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const {
      key,
      rawKey,
      algorithm,
      ciphertext,
      iv,
      tag,
      aad,
      version,
      envelope,
      outputEncoding = 'utf8',
      policy = 'DEFAULT_SECURE',
    } = req.body;

    const keyId = key;
    if (!keyId && !rawKey) {
      return sendUniversalError(
        res,
        req,
        400,
        'INVALID_REQUEST',
        'Either "key" (logical key ID) or "rawKey" must be provided.'
      );
    }

    // Resolve envelope components
    let ct = ciphertext;
    let ivStr = iv;
    let tagStr = tag;
    let aadStr = aad;
    let wrappedDekStr = req.body.wrappedDek;
    let wrapAlgStr = req.body.wrapAlg;

    // The opaque string form returned by /v1/encrypt; its AAD is already base64url
    let parsedEnvelope: EncryptedEnvelope | null = null;
    if (typeof envelope === 'string') {
      try {
        parsedEnvelope = parseEnvelope(envelope);
      } catch (err: any) {
        return sendUniversalError(res, req, 400, 'INVALID_REQUEST', err.message || 'Malformed envelope.');
      }
    }

    if (envelope && typeof envelope === 'object') {
      wrappedDekStr = envelope.wrappedDek || wrappedDekStr;
      wrapAlgStr = envelope.wrapAlg || wrapAlgStr;
      ct = envelope.ct || envelope.ciphertext || ct;
      ivStr = envelope.iv || ivStr;
      tagStr = envelope.tag || tagStr;
      aadStr = envelope.aad !== undefined ? envelope.aad : aadStr;
    }

    if (!parsedEnvelope && (!ct || !ivStr || !tagStr)) {
      return sendUniversalError(
        res,
        req,
        400,
        'INVALID_REQUEST',
        'Fields "ciphertext", "iv", and "tag" (or a valid "envelope" object) are required for decryption.'
      );
    }

    // An "aad" sent with an envelope is the AAD the caller expects that envelope to carry (for
    // example the record and field it was stored under). The envelope's own AAD is what decrypts
    // it, so without this check an envelope copied into another record would decrypt anyway.
    if (envelope && aad !== undefined && aad !== null) {
      const expected = Buffer.isBuffer(aad) ? aad : Buffer.from(String(aad), 'utf8');
      let stored: Buffer | null = null;
      if (parsedEnvelope) {
        stored = parsedEnvelope.aad ? Buffer.from(parsedEnvelope.aad, 'base64url') : null;
      } else if (typeof envelope === 'object' && envelope.aad !== undefined && envelope.aad !== null) {
        stored = Buffer.isBuffer(envelope.aad) ? envelope.aad : Buffer.from(String(envelope.aad), 'utf8');
      } else {
        stored = expected; // an object envelope without AAD is decrypted with the caller's AAD
      }
      if (!stored || stored.length !== expected.length || !crypto.timingSafeEqual(stored, expected)) {
        return sendUniversalError(
          res,
          req,
          400,
          'AAD_MISMATCH',
          'The envelope was not encrypted with the AAD you sent, so it belongs to a different record or field.'
        );
      }
    }

    let internalEnvelopeAad: string | undefined = undefined;
    if (aadStr !== undefined && aadStr !== null) {
      internalEnvelopeAad = Buffer.isBuffer(aadStr)
        ? aadStr.toString('base64url')
        : Buffer.from(String(aadStr), 'utf8').toString('base64url');
    }

    const tenantContext = buildTenantContext(req);
    const operationId = `op_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const idempotencyKey = (req.headers['idempotency-key'] as string) || req.body?.idempotencyKey;

    try {
      const result = await cryptographicRuntime.execute(
        {
          operationId,
          requestId: (req as any).requestId,
          idempotencyKey,
          type: 'DECRYPT',
          keyId: keyId || undefined,
          algorithm: algorithm || undefined,
          policy,
          params: {
            envelope: parsedEnvelope || {
              v: 1,
              alg: algorithm || 'AES-256-GCM',
              iv: ivStr,
              tag: tagStr,
              ct,
              aad: internalEnvelopeAad,
              wrappedDek: wrappedDekStr || null,
              wrapAlg: wrapAlgStr || null,
            },
            key: rawKey || undefined,
            keyEncoding: rawKey ? (typeof rawKey === 'string' && /^[0-9a-fA-F]{64}$/.test(rawKey) ? 'hex' : 'base64') : undefined,
            version: version ?? parsedEnvelope?.keyVersion ?? (envelope && typeof envelope === 'object' ? envelope.keyVersion : undefined),
            outputEncoding: 'buffer',
          },
        },
        tenantContext
      );

      if (!result.success) {
        const statusCode = result.error?.statusCode || 400;
        return sendUniversalError(
          res,
          req,
          statusCode,
          result.error?.code || 'DECRYPTION_FAILED',
          result.error?.message || 'Decryption failed: authenticity check failed or key is invalid.',
          result.operationId,
          result.error?.retryable
        );
      }

      return sendUniversalSuccess(
        res,
        req,
        {
          ...encodePlaintext(result.data as Buffer, outputEncoding),
          algorithm: result.metadata.algorithm,
          keyId: result.metadata.keyId || keyId || undefined,
          keyVersion: result.metadata.keyVersion !== undefined ? result.metadata.keyVersion : undefined,
        },
        result.operationId
      );
    } catch (err: any) {
      const e = publicError(err, 'An unexpected error occurred during decryption.');
      return sendUniversalError(res, req, e.status, e.code, e.message, operationId);
    }
  }
);

// ===========================================================================
// 3. HASH API
// POST /v1/hash (or /api/v1/hash)
// ===========================================================================
router.post(
  '/hash',
  ...cryptoMiddleware,
  requireScope('crypto:hash'),
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const {
      algorithm = 'SHA-256',
      data,
      encoding = 'utf8',
      outputEncoding = 'hex',
      policy = 'DEFAULT_SECURE',
    } = req.body;

    if (data === undefined || data === null) {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', 'Field "data" is required for hashing.');
    }

    // Verify algorithm exists in central registry
    const normalizedAlg = String(algorithm).toUpperCase().replace(/_/g, '-');
    if (!registry.isAvailable(normalizedAlg) || !['sha-256', 'sha-384', 'sha-512', 'sha3-256', 'sha3-384', 'sha3-512'].includes(normalizedAlg.toLowerCase())) {
      return sendUniversalError(
        res,
        req,
        400,
        'ALGORITHM_UNSUPPORTED',
        `Algorithm '${algorithm}' is unsupported for cryptographic hashing. Supported algorithms: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512.`
      );
    }

    let dataBuf: Buffer;
    try {
      dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), encoding === 'base64' ? 'base64' : 'utf8');
    } catch {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', `Failed to decode data using encoding '${encoding}'.`);
    }

    const tenantContext = buildTenantContext(req);
    const operationId = `op_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const idempotencyKey = (req.headers['idempotency-key'] as string) || req.body?.idempotencyKey;

    try {
      const result = await cryptographicRuntime.execute(
        {
          operationId,
          requestId: (req as any).requestId,
          idempotencyKey,
          type: 'HASH',
          algorithm: normalizedAlg,
          policy,
          params: {
            data: dataBuf,
            outputEncoding: outputEncoding === 'base64' ? 'base64' : 'hex',
          },
        },
        tenantContext
      );

      if (!result.success) {
        return sendUniversalError(
          res,
          req,
          result.error?.statusCode || 400,
          result.error?.code || 'OPERATION_FAILED',
          result.error?.message || 'Hashing failed.',
          result.operationId
        );
      }

      return sendUniversalSuccess(
        res,
        req,
        {
          digest: result.data.digest,
          algorithm: result.metadata.algorithm,
          byteLength: Buffer.from(result.data.digest, outputEncoding === 'base64' ? 'base64' : 'hex').length,
          encoding: outputEncoding,
        },
        result.operationId
      );
    } catch (err: any) {
      const e = publicError(err, 'An unexpected hashing error occurred.');
      return sendUniversalError(res, req, e.status, e.code, e.message, operationId);
    }
  }
);

// ===========================================================================
// 4. SIGN API
// POST /v1/sign (or /api/v1/sign)
// ===========================================================================
router.post(
  '/sign',
  ...cryptoMiddleware,
  requireScope('crypto:sign'),
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const {
      key,
      privateKey,
      algorithm,
      data,
      encoding = 'utf8',
      outputEncoding = 'hex',
      version,
      policy = 'DEFAULT_SECURE',
    } = req.body;

    const keyId = key;
    if (!keyId && !privateKey) {
      return sendUniversalError(
        res,
        req,
        400,
        'INVALID_REQUEST',
        'Either "key" (logical signing key ID) or "privateKey" must be provided.'
      );
    }

    if (data === undefined || data === null) {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', 'Field "data" is required for digital signing.');
    }

    let dataBuf: Buffer;
    try {
      dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), encoding === 'base64' ? 'base64' : 'utf8');
    } catch {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', `Failed to decode data using encoding '${encoding}'.`);
    }

    const tenantContext = buildTenantContext(req);
    const operationId = `op_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const idempotencyKey = (req.headers['idempotency-key'] as string) || req.body?.idempotencyKey;

    try {
      const result = await cryptographicRuntime.execute(
        {
          operationId,
          requestId: (req as any).requestId,
          idempotencyKey,
          type: 'SIGN',
          keyId: keyId || undefined,
          algorithm: algorithm || undefined,
          policy,
          params: {
            data: dataBuf,
            privateKey: privateKey || undefined,
            version,
            encoding: outputEncoding === 'base64' ? 'base64' : 'hex',
          },
        },
        tenantContext
      );

      if (!result.success) {
        return sendUniversalError(
          res,
          req,
          result.error?.statusCode || 400,
          result.error?.code || 'OPERATION_FAILED',
          result.error?.message || 'Digital signing failed.',
          result.operationId
        );
      }

      return sendUniversalSuccess(
        res,
        req,
        {
          signature: result.data.signature,
          algorithm: result.metadata.algorithm,
          keyId: result.metadata.keyId || keyId || undefined,
          keyVersion: result.metadata.keyVersion !== undefined ? result.metadata.keyVersion : undefined,
          encoding: outputEncoding,
        },
        result.operationId
      );
    } catch (err: any) {
      const e = publicError(err, 'An unexpected signing error occurred.');
      return sendUniversalError(res, req, e.status, e.code, e.message, operationId);
    }
  }
);

// ===========================================================================
// 5. VERIFY API
// POST /v1/verify (or /api/v1/verify)
// ===========================================================================
router.post(
  '/verify',
  ...cryptoMiddleware,
  requireScope('crypto:verify'),
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const {
      key,
      publicKey,
      algorithm,
      data,
      signature,
      encoding = 'utf8',
      signatureEncoding = 'hex',
      version,
      policy = 'DEFAULT_SECURE',
    } = req.body;

    const keyId = key;
    if (!keyId && !publicKey) {
      return sendUniversalError(
        res,
        req,
        400,
        'INVALID_REQUEST',
        'Either "key" (logical key ID) or "publicKey" must be provided.'
      );
    }

    if (data === undefined || data === null) {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', 'Field "data" is required for signature verification.');
    }

    if (!signature) {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', 'Field "signature" is required for verification.');
    }

    let dataBuf: Buffer;
    try {
      dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), encoding === 'base64' ? 'base64' : 'utf8');
    } catch {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', `Failed to decode data using encoding '${encoding}'.`);
    }

    let sigBuf: Buffer;
    try {
      sigBuf = Buffer.isBuffer(signature)
        ? signature
        : Buffer.from(String(signature), signatureEncoding === 'base64' ? 'base64' : 'hex');
    } catch {
      return sendUniversalError(res, req, 400, 'INVALID_REQUEST', 'Failed to decode signature bytes.');
    }

    const tenantContext = buildTenantContext(req);
    const operationId = `op_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const idempotencyKey = (req.headers['idempotency-key'] as string) || req.body?.idempotencyKey;

    try {
      const result = await cryptographicRuntime.execute(
        {
          operationId,
          requestId: (req as any).requestId,
          idempotencyKey,
          type: 'VERIFY',
          keyId: keyId || undefined,
          algorithm: algorithm || undefined,
          policy,
          params: {
            data: dataBuf,
            signature: sigBuf,
            publicKey: publicKey || undefined,
            version,
            encoding: signatureEncoding,
          },
        },
        tenantContext
      );

      if (!result.success) {
        return sendUniversalError(
          res,
          req,
          result.error?.statusCode || 400,
          result.error?.code || 'OPERATION_FAILED',
          result.error?.message || 'Signature verification failed.',
          result.operationId
        );
      }

      return sendUniversalSuccess(
        res,
        req,
        {
          valid: Boolean(result.data),
          algorithm: result.metadata.algorithm,
          keyId: result.metadata.keyId || keyId || undefined,
        },
        result.operationId
      );
    } catch (err: any) {
      const e = publicError(err, 'An unexpected verification error occurred.');
      return sendUniversalError(res, req, e.status, e.code, e.message, operationId);
    }
  }
);

// ===========================================================================
// 6. CAPABILITY DISCOVERY API
// GET /v1/capabilities (or /api/v1/capabilities)
// ===========================================================================
router.get('/capabilities', async (req: Request, res: Response) => {
  try {
    const rawSummary = await capabilityDiscovery.getPlatformCapabilities();
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    res.setHeader('x-request-id', requestId);

    // Clean, public-safe capability summary
    const publicCapabilities = {
      version: '1.0.0',
      supportedOperations: ['ENCRYPT', 'DECRYPT', 'HASH', 'SIGN', 'VERIFY', 'KEY_GEN', 'KEY_ROTATION'],
      supportedAlgorithms: [
        { id: 'AES-256-GCM', category: 'SYMMETRIC_AEAD', fipsApproved: true, keySizeBits: 256, standard: 'NIST SP 800-38D' },
        { id: 'ED25519', category: 'ASYMMETRIC_SIGNING', fipsApproved: true, standard: 'RFC 8032' },
        { id: 'SHA-256', category: 'HASH', fipsApproved: true, digestBits: 256, standard: 'NIST FIPS 180-4' },
        { id: 'SHA-384', category: 'HASH', fipsApproved: true, digestBits: 384, standard: 'NIST FIPS 180-4' },
        { id: 'SHA-512', category: 'HASH', fipsApproved: true, digestBits: 512, standard: 'NIST FIPS 180-4' },
        { id: 'SHA3-256', category: 'HASH', fipsApproved: true, digestBits: 256, standard: 'NIST FIPS 202' },
        { id: 'HMAC-SHA256', category: 'MAC', fipsApproved: true, standard: 'RFC 2104' },
        { id: 'ML-KEM-768', category: 'PQC_KEM', fipsApproved: true, standard: 'NIST FIPS 203' },
        { id: 'ML-DSA-65', category: 'PQC_SIGNATURE', fipsApproved: true, standard: 'NIST FIPS 204' },
      ],
      defaultAlgorithms: {
        encryption: 'AES-256-GCM',
        hashing: 'SHA-256',
        signing: 'ED25519',
      },
      securityProfiles: ['DEFAULT_SECURE', 'FIPS_COMPLIANT', 'PQC_PREFERRED'],
      features: {
        envelopeEncryption: true,
        logicalKeyManagement: true,
        keyRotation: true,
        postQuantumCryptography: rawSummary.pqcSupported,
        hardwareBackedHSM: rawSummary.hsmSupported,
        // The algorithms above are FIPS-approved, but the runtime (Node/OpenSSL + noble)
        // is not a FIPS 140-3 validated module.
        fipsCompliant: false,
        zeroSecretLeakage: true,
        billingUsageProtection: true,
      },
    };

    return res.status(200).json({
      data: publicCapabilities,
      requestId,
    });
  } catch (err: any) {
    return sendUniversalError(res, req, 500, 'INTERNAL_ERROR', 'Failed to retrieve platform capabilities.');
  }
});

// ===========================================================================
// 7. ALGORITHMS CATALOG API
// GET /v1/algorithms (or /api/v1/algorithms)
// ===========================================================================
router.get('/algorithms', async (req: Request, res: Response) => {
  const algorithms = registry.getAll();
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);

  return res.status(200).json({
    data: algorithms,
    meta: {
      count: algorithms.length,
      registryVersion: '1.0.0',
    },
    requestId,
  });
});

// ===========================================================================
// 8. OPERATION OBSERVABILITY API
// GET /v1/operations/:operationId
// ===========================================================================
router.get(
  '/operations/:operationId',
  requireAuth,
  requireOrgMember,
  async (req: Request, res: Response) => {
    const op = await db.getCryptographicOperation(req.params.operationId);
    if (!op || op.organizationId !== req.organizationId) {
      return sendUniversalError(res, req, 404, 'NOT_FOUND', 'Cryptographic operation not found.');
    }

  const requestId = (req as any).requestId || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);

  return res.status(200).json({
    data: {
      id: op.id,
      operationType: op.operationType,
      algorithm: op.algorithm,
      keyId: op.keyId,
      status: op.status,
      durationMs: op.durationMs,
      createdAt: op.createdAt,
      updatedAt: op.updatedAt,
    },
    operationId: op.id,
    requestId,
    status: op.status,
  });
});

export default router;
