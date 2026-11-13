import { Router, Request, Response } from 'express';
import { registry, cryptoEngine, CryptoEngineError } from '@amaracus/crypto-core';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendError } from '../../middleware/response-formatter';
import { requireOperationAllowance } from '../../middleware/billing-guard';
import { createRateLimiter, organizationCryptoLimiter } from '../../middleware/rate-limiter';
import { usageMeter } from '../../lib/usage-meter';

const router = Router();

// Authentication, org membership and rate limiting. Post-quantum ML-KEM and ML-DSA are
// included on every plan (the same algorithms were already open to all plans under
// /v1/crypto); each call still counts against the plan's operation allowance.
router.use(requireAuth);
router.use(requireOrgMember);
router.use(createRateLimiter({ limit: 300, windowMs: 60000 }));
router.use(organizationCryptoLimiter());

// Helper: Authoritatively record billable PQC operation strictly on successful execution
async function recordBillablePqcOp(req: Request, operationType: string) {
  try {
    const orgId = req.organizationId || (req as any).activeOrgId;
    if (orgId) {
      const operationId = (req.headers['idempotency-key'] as string) || (req as any).requestId;
      await usageMeter.recordOperation({
        organizationId: orgId,
        operationType,
        quantity: 1,
        operationId,
      });
    }
  } catch (err) {
    console.warn(`[Usage Metering Warning] Could not record ${operationType} usage:`, err);
  }
}

// GET /api/v1/pqc/algorithms - List supported PQC algorithms
router.get('/algorithms', requireScope('pqc:read'), (req: Request, res: Response) => {
  const allAlgs = registry.getAll();
  const pqcAlgs = allAlgs.filter((a) => a.family === 'PQC' || a.family === 'HYBRID');
  return sendSuccess(res, pqcAlgs);
});

// POST /api/v1/pqc/keypair - Generate PQC keypair (ML-KEM or ML-DSA)
router.post('/keypair', requireScope('pqc:execute'), requireOperationAllowance(1), async (req: Request, res: Response) => {
  try {
    const requestedAlg = req.body.algorithm || 'ML-KEM-768';
    const rawAlg = requestedAlg.toUpperCase().replace(/_/g, '-');
    const { outputEncoding = 'base64' } = req.body;
    let keypair: any;

    if (rawAlg.startsWith('ML-KEM')) {
      keypair = await cryptoEngine.kemKeygen({ algorithm: rawAlg as any, outputEncoding } as any);
    } else if (rawAlg.startsWith('ML-DSA')) {
      keypair = await cryptoEngine.pqcKeygen({ algorithm: rawAlg as any, outputEncoding } as any);
    } else if (rawAlg === 'X25519+ML-KEM-768' || rawAlg.startsWith('HYBRID')) {
      keypair = await cryptoEngine.hybridKeygen({ algorithm: 'X25519+ML-KEM-768', outputEncoding } as any);
    } else {
      return sendError(res, 400, 'ALGORITHM_NOT_SUPPORTED', `Unsupported PQC algorithm: '${req.body.algorithm}'.`);
    }

    await recordBillablePqcOp(req, 'PQC_KEYGEN');
    return sendSuccess(res, {
      ...keypair,
      algorithm: requestedAlg,
    });
  } catch (err: any) {
    return sendError(res, err.status || 500, err.code || 'INTERNAL_ERROR', err.message || 'Keypair generation failed.');
  }
});

// POST /api/v1/pqc/encapsulate - Encapsulate shared secret using ML-KEM or the X25519+ML-KEM-768 hybrid
router.post('/encapsulate', requireScope('pqc:execute'), requireOperationAllowance(1), async (req: Request, res: Response) => {
  try {
    const rawAlg = (req.body.algorithm || 'ML-KEM-768').toUpperCase().replace(/_/g, '-');
    const { publicKey, policy } = req.body;

    if (!publicKey) {
      return sendError(res, 400, 'VALIDATION_FAILED', 'Field "publicKey" is required.');
    }

    const effectivePublicKeyEncoding =
      req.body.publicKeyEncoding ||
      (typeof publicKey === 'string' && /^[0-9a-fA-F]+$/.test(publicKey.trim()) && publicKey.trim().length > 200
        ? 'hex'
        : 'base64');
    const effectiveOutputEncoding = req.body.outputEncoding || effectivePublicKeyEncoding;

    let result: any;
    if (rawAlg === 'X25519+ML-KEM-768' || rawAlg.startsWith('HYBRID')) {
      result = await cryptoEngine.hybridEncapsulate(
        { algorithm: 'X25519+ML-KEM-768', publicKey, publicKeyEncoding: effectivePublicKeyEncoding, outputEncoding: effectiveOutputEncoding } as any,
        policy
      );
    } else {
      result = await cryptoEngine.kemEncapsulate(
        { algorithm: rawAlg as any, publicKey, publicKeyEncoding: effectivePublicKeyEncoding, outputEncoding: effectiveOutputEncoding },
        policy
      );
    }

    const normalizedResult = {
      ...result,
      algorithm: req.body.algorithm || result?.algorithm,
      ciphertext: result?.cipherText || result?.ciphertext,
      cipherText: result?.cipherText || result?.ciphertext,
    };

    await recordBillablePqcOp(req, 'PQC_ENCAPSULATE');
    return sendSuccess(res, normalizedResult);
  } catch (err: any) {
    return sendError(res, err.status || 500, err.code || 'INTERNAL_ERROR', err.message || 'Encapsulation failed.');
  }
});

// POST /api/v1/pqc/decapsulate - Decapsulate ciphertext with private key
router.post('/decapsulate', requireScope('pqc:execute'), requireOperationAllowance(1), async (req: Request, res: Response) => {
  try {
    const rawAlg = (req.body.algorithm || 'ML-KEM-768').toUpperCase().replace(/_/g, '-');
    const ciphertext = req.body.ciphertext || req.body.cipherText;
    const { privateKey, policy } = req.body;

    if (!privateKey || !ciphertext) {
      return sendError(res, 400, 'VALIDATION_FAILED', 'Fields "privateKey" and "ciphertext" are required.');
    }

    const effectivePrivateKeyEncoding =
      req.body.privateKeyEncoding ||
      (typeof privateKey === 'string' && /^[0-9a-fA-F]+$/.test(privateKey.trim()) && privateKey.trim().length > 200
        ? 'hex'
        : 'base64');
    const effectiveCiphertextEncoding =
      req.body.ciphertextEncoding ||
      (typeof ciphertext === 'string' && /^[0-9a-fA-F]+$/.test(ciphertext.trim()) && ciphertext.trim().length > 200
        ? 'hex'
        : 'base64');
    const effectiveOutputEncoding = req.body.outputEncoding || effectivePrivateKeyEncoding;

    let result: any;
    if (rawAlg === 'X25519+ML-KEM-768' || rawAlg.startsWith('HYBRID')) {
      result = await cryptoEngine.hybridDecapsulate(
        {
          algorithm: 'X25519+ML-KEM-768',
          privateKey,
          ciphertext,
          privateKeyEncoding: effectivePrivateKeyEncoding,
          ciphertextEncoding: effectiveCiphertextEncoding,
          outputEncoding: effectiveOutputEncoding,
        } as any,
        policy
      );
    } else {
      result = await cryptoEngine.kemDecapsulate(
        {
          algorithm: rawAlg as any,
          privateKey,
          ciphertext,
          privateKeyEncoding: effectivePrivateKeyEncoding,
          ciphertextEncoding: effectiveCiphertextEncoding,
          outputEncoding: effectiveOutputEncoding,
        },
        policy
      );
    }

    await recordBillablePqcOp(req, 'PQC_DECAPSULATE');
    return sendSuccess(res, {
      ...result,
      algorithm: req.body.algorithm || result?.algorithm,
    });
  } catch (err: any) {
    return sendError(res, err.status || 500, err.code || 'INTERNAL_ERROR', err.message || 'Decapsulation failed.');
  }
});

// POST /api/v1/pqc/sign - Sign message with ML-DSA
router.post('/sign', requireScope('pqc:execute'), requireOperationAllowance(1), async (req: Request, res: Response) => {
  try {
    const {
      algorithm = 'ML-DSA-65',
      privateKey,
      message,
      privateKeyEncoding = 'base64',
      messageEncoding = 'utf8',
      outputEncoding = 'base64',
      policy,
    } = req.body;

    if (!privateKey || message === undefined) {
      return sendError(res, 400, 'VALIDATION_FAILED', 'Fields "privateKey" and "message" are required.');
    }

    const result = await cryptoEngine.pqcSign(
      { algorithm, privateKey, message, privateKeyEncoding, messageEncoding, outputEncoding },
      policy
    );

    await recordBillablePqcOp(req, 'PQC_SIGN');
    return sendSuccess(res, result);
  } catch (err: any) {
    return sendError(res, err.status || 500, err.code || 'INTERNAL_ERROR', err.message || 'Signature generation failed.');
  }
});

// POST /api/v1/pqc/verify - Verify ML-DSA signature
router.post('/verify', requireScope('pqc:execute'), requireOperationAllowance(1), async (req: Request, res: Response) => {
  try {
    const {
      algorithm = 'ML-DSA-65',
      publicKey,
      message,
      signature,
      publicKeyEncoding = 'base64',
      messageEncoding = 'utf8',
      signatureEncoding = 'base64',
      policy,
    } = req.body;

    if (!publicKey || message === undefined || !signature) {
      return sendError(res, 400, 'VALIDATION_FAILED', 'Fields "publicKey", "message", and "signature" are required.');
    }

    const result = await cryptoEngine.pqcVerify(
      { algorithm, publicKey, message, signature, publicKeyEncoding, messageEncoding, signatureEncoding },
      policy
    );

    await recordBillablePqcOp(req, 'PQC_VERIFY');
    return sendSuccess(res, result);
  } catch (err: any) {
    return sendError(res, err.status || 500, err.code || 'INTERNAL_ERROR', err.message || 'Signature verification failed.');
  }
});

export default router;
