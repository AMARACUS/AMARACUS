import { Router, Request, Response } from 'express';
import { requireAuth, requireOrgMember } from '../../middleware/auth';
import { payloadSizeLimiter, createRateLimiter } from '../../middleware/rate-limiter';
import { requireOperationAllowance } from '../../middleware/billing-guard';
import { managedOperationService } from '../../lib/managed-operation-service';
import { db } from '../../lib/data-store';
import { TenantContext } from '@amaracus/crypto-core';
import { sendCaughtError, publicError } from '../../middleware/response-formatter';

const router = Router();

const opMiddleware = [
  requireAuth,
  requireOrgMember,
  payloadSizeLimiter(2097152), // 2MB limit
  createRateLimiter({ limit: 300, windowMs: 60000 }),
];

function buildTenantContext(req: Request): TenantContext {
  return {
    organizationId: req.organizationId!,
    projectId: req.projectId || (req.headers['x-project-id'] as string) || req.body?.projectId,
    environmentId: req.environmentId || (req.headers['x-environment-id'] as string) || req.body?.environmentId,
    actorId: req.apiKey?.id || req.user?.id,
    actorType: req.apiKey ? 'API_KEY' : 'USER_SESSION',
  };
}

// Operation types the cryptographic runtime can actually execute. Anything else
// (FHE, MPC, ZK, batch types) would be queued and then always fail, so reject it up front.
const SUPPORTED_OPERATION_TYPES = new Set([
  'ENCRYPT',
  'DECRYPT',
  'SIGN',
  'PQC_SIGN',
  'VERIFY',
  'PQC_VERIFY',
  'HASH',
  'HMAC',
  'KEY_GEN',
  'KEM_KEYGEN',
  'KEY_ROTATION',
]);

const STRING_FIELDS = ['keyId', 'algorithm', 'idempotencyKey', 'projectId', 'environmentId'];
const NUMBER_FIELDS = ['timeoutMs', 'maxRetries', 'ttlSeconds'];
const BUFFER_LIKE_PARAMS = ['plaintext', 'aad', 'data', 'signature', 'key'];

/**
 * Returns an error message for a malformed submission, or null when it is well formed.
 */
function validateSubmission(body: any): string | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'Request body must be a JSON object.';
  }
  const type = body.type ?? body.operationType ?? 'ENCRYPT';
  if (typeof type !== 'string' || !SUPPORTED_OPERATION_TYPES.has(type)) {
    return `Unsupported operation type. Supported types: ${[...SUPPORTED_OPERATION_TYPES].join(', ')}.`;
  }
  for (const field of STRING_FIELDS) {
    if (body[field] !== undefined && typeof body[field] !== 'string') {
      return `'${field}' must be a string.`;
    }
  }
  for (const field of NUMBER_FIELDS) {
    if (body[field] !== undefined && (typeof body[field] !== 'number' || !Number.isFinite(body[field]) || body[field] < 0)) {
      return `'${field}' must be a non-negative number.`;
    }
  }
  if (body.mode !== undefined && body.mode !== 'sync' && body.mode !== 'async') {
    return "'mode' must be 'sync' or 'async'.";
  }
  if (body.params !== undefined && (body.params === null || typeof body.params !== 'object' || Array.isArray(body.params))) {
    return "'params' must be an object.";
  }
  for (const field of BUFFER_LIKE_PARAMS) {
    const value = body.params?.[field];
    if (value !== undefined && typeof value !== 'string') {
      return `'params.${field}' must be a string.`;
    }
  }
  return null;
}

/**
 * GET /v1/operations/metrics
 * System and tenant operational observability, queue depth, and concurrency metrics.
 */
router.get('/metrics', ...opMiddleware, async (req: Request, res: Response) => {
  try {
    const metrics = await managedOperationService.getMetrics(req.organizationId);
    return res.status(200).json({
      data: metrics,
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * POST /v1/operations
 * Unified submission endpoint for managed cryptographic operations (Sync or Async).
 */
router.post(
  '/',
  ...opMiddleware,
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const requestId =
      (req.headers['x-request-id'] as string) || (req as any).requestId || `req_${Date.now()}`;
    const validationError = validateSubmission(req.body);
    if (validationError) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: validationError, retryable: false },
        requestId,
      });
    }

    const idempotencyKey =
      (req.headers['x-idempotency-key'] as string) || req.body?.idempotencyKey || undefined;

    const opType = req.body.type ?? req.body.operationType ?? 'ENCRYPT';
    const {
      keyId,
      algorithm,
      mode,
      priority,
      timeoutMs,
      maxRetries,
      ttlSeconds,
      allowQueueFallback,
      ...payload
    } = req.body || {};

    const context = buildTenantContext(req);

    const request = {
      type: opType,
      keyId,
      algorithm,
      idempotencyKey,
      requestId,
      ...payload,
    };

    try {
      const response = await managedOperationService.submitOperation(request, context, {
        mode,
        priority,
        timeoutMs,
        maxRetries,
        ttlSeconds,
        allowQueueFallback,
      });

      // Record audit event for operational traceability
      db.createAuditEvent({
        organizationId: context.organizationId,
        userId: context.actorId || 'system',
        action: `OPERATION_${opType.toUpperCase()}`,
        resourceType: 'MANAGED_OPERATION',
        resourceId: response.operationId,
        metadata: {
          algorithm,
          mode: response.mode,
          durationMs: response.durationMs,
        },
      }).catch(() => {});

      res.setHeader('x-request-id', requestId);

      if (response.mode === 'async') {
        return res.status(202).json({
          operationId: response.operationId,
          requestId,
          status: response.status,
          mode: 'async',
          pollUrl: response.pollUrl,
          expiresAt: response.expiresAt,
        });
      }

      return res.status(200).json({
        operationId: response.operationId,
        requestId,
        status: response.status,
        mode: 'sync',
        durationMs: response.durationMs,
        data: response.result,
        expiresAt: response.expiresAt,
      });
    } catch (err: any) {
      const statusCode =
        err.statusCode ||
        err.status ||
        (err.code === 'CONCURRENCY_LIMIT_EXCEEDED'
          ? 429
          : err.code === 'KEY_NOT_FOUND'
          ? 404
          : err.code === 'INVALID_REQUEST' || err.code === 'INVALID_PARAMS'
          ? 400
          : 500);
      const rawMsg = err.message || 'Operation execution failed.';
      const sanitizedMsg = rawMsg
        .replace(/[0-9a-fA-F]{32,}/g, '[REDACTED]')
        .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[REDACTED]');

      return res.status(statusCode).json({
        error: {
          code: err.code || 'OPERATION_FAILED',
          message: sanitizedMsg,
          retryable: statusCode === 429 || statusCode >= 500,
        },
        requestId,
      });
    }
  }
);

/**
 * GET /v1/operations
 * List operations belonging to authenticated organization.
 */
router.get('/', ...opMiddleware, async (req: Request, res: Response) => {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 50));
  const offset = Math.max(0, parseInt(req.query.offset as string, 10) || 0);
  const status = req.query.status as string | undefined;
  const operationType = (req.query.type as string) || (req.query.operationType as string) || undefined;

  try {
    const operations = await managedOperationService.listOperations(req.organizationId!, {
      limit,
      offset,
      status,
      operationType,
    });

    const sanitized = operations.map((op) => ({
      id: op.id,
      operationType: op.operationType,
      status: op.status,
      algorithm: op.algorithm,
      keyId: op.keyId,
      providerId: op.providerId,
      durationMs: op.durationMs,
      retryCount: op.retryCount,
      expiresAt: op.expiresAt,
      createdAt: op.createdAt,
      updatedAt: op.updatedAt,
      error: op.error,
    }));

    return res.status(200).json({
      data: sanitized,
      limit,
      offset,
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * GET /v1/operations/:id
 * Retrieve single operation status and details (with IDOR protection).
 */
router.get('/:id', ...opMiddleware, async (req: Request, res: Response) => {
  const operationId = req.params.id;
  try {
    const op = await managedOperationService.getOperation(operationId, req.organizationId!);
    if (!op) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Cryptographic operation '${operationId}' not found.` },
      });
    }

    return res.status(200).json({
      data: {
        id: op.id,
        operationType: op.operationType,
        status: op.status,
        algorithm: op.algorithm,
        keyId: op.keyId,
        providerId: op.providerId,
        durationMs: op.durationMs,
        retryCount: op.retryCount,
        expiresAt: op.expiresAt,
        createdAt: op.createdAt,
        updatedAt: op.updatedAt,
        error: op.error,
      },
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * GET /v1/operations/:id/result
 * Retrieve execution result of completed operation or current polling status.
 */
router.get('/:id/result', ...opMiddleware, async (req: Request, res: Response) => {
  const operationId = req.params.id;
  try {
    const resultObj = await managedOperationService.getOperationResult(
      operationId,
      req.organizationId!
    );

    if (resultObj.status === 'COMPLETED') {
      return res.status(200).json({
        operationId,
        status: 'COMPLETED',
        data: resultObj.result,
        durationMs: resultObj.durationMs,
      });
    }

    if (['FAILED', 'TIMED_OUT', 'CANCELED', 'DEAD_LETTER', 'EXPIRED'].includes(resultObj.status)) {
      return res.status(200).json({
        operationId,
        status: resultObj.status,
        error: resultObj.error,
        durationMs: resultObj.durationMs,
      });
    }

    // In-flight (QUEUED / EXECUTING)
    return res.status(202).json({
      operationId,
      status: resultObj.status,
      retryAfterMs: resultObj.retryAfterMs || 500,
    });
  } catch (err: any) {
    const e = publicError(err, 'The operation request failed.');
    return res.status(e.status).json({
      error: { code: e.code, message: e.message },
    });
  }
});

/**
 * POST /v1/operations/:id/cancel
 * Cancel an active or queued operation.
 */
router.post('/:id/cancel', ...opMiddleware, async (req: Request, res: Response) => {
  const operationId = req.params.id;
  try {
    const cancelRes = await managedOperationService.cancelOperation(
      operationId,
      req.organizationId!
    );

    return res.status(200).json({
      operationId,
      status: cancelRes.status,
      canceled: cancelRes.success,
    });
  } catch (err: any) {
    const e = publicError(err, 'The operation request failed.');
    return res.status(e.status).json({
      error: { code: e.code, message: e.message },
    });
  }
});

export default router;
