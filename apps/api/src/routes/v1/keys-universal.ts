import { Router, Request, Response, NextFunction } from 'express';
import {
  KeyManagementService,
  KeyLifecycleValidator,
  KeyProviderType,
  KeyPurpose,
  AlgorithmId,
} from '@amaracus/crypto-core';
import { requireAuth, requireOrgMember } from '../../middleware/auth';
import { hasRequiredScope } from '../../lib/api-keys';
import { createRateLimiter, payloadSizeLimiter } from '../../middleware/rate-limiter';
import { requireOperationAllowance } from '../../middleware/billing-guard';
import { db, CryptographicKeyRecord, CryptographicKeyVersionRecord } from '../../lib/data-store';
import { entitlementEngine } from '../../lib/entitlement-engine';
import { checkManagedKeyProvider } from '../../lib/entitlements';
import { publicError } from '../../middleware/response-formatter';
import { isSelfHosted } from '../../lib/edition';
import { usageMeter } from '../../lib/usage-meter';

const router = Router();
const kmsService = new KeyManagementService();

// Common middleware stack
router.use(requireAuth);
router.use(requireOrgMember);
router.use(payloadSizeLimiter(1048576));
router.use(createRateLimiter({ limit: 300, windowMs: 60000 }));

// Helper: Strip sensitive internal fields and private keys from key responses
function sanitizeKey(key: CryptographicKeyRecord) {
  const { versions, ...rest } = key;
  return {
    id: rest.id,
    name: rest.name,
    description: rest.description,
    algorithm: rest.algorithm,
    purpose: rest.purpose,
    status: rest.status,
    currentVersion: rest.currentVersion,
    createdAt: rest.createdAt,
    updatedAt: rest.updatedAt,
    projectId: rest.projectId,
    environmentId: rest.environmentId,
    versions: versions ? versions.map(sanitizeVersion) : undefined,
  };
}

function sanitizeVersion(ver: CryptographicKeyVersionRecord) {
  return {
    id: ver.id,
    version: ver.version,
    status: ver.status,
    publicKey: ver.publicKey || null,
    keyFingerprint: ver.keyFingerprint || null,
    createdAt: ver.createdAt,
  };
}

function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.apiKey) {
      return next();
    }
    if (!hasRequiredScope(req.apiKey.scopes, scope)) {
      const requestId = (req as any).requestId || (req.headers['x-request-id'] as string) || `req_${Date.now()}`;
      return res.status(403).json({
        error: {
          code: 'INSUFFICIENT_SCOPE',
          message: `Credential lacks the required '${scope}' scope.`,
          retryable: false,
        },
        requestId,
      });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// 1. LIST KEYS
// GET /v1/keys
// ---------------------------------------------------------------------------
router.get('/', requireScope('keys:read'), async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const limit = Math.min(parseInt(req.query.limit as string, 10) || 50, 100);
  const offset = parseInt(req.query.offset as string, 10) || 0;
  const purpose = req.query.purpose as string | undefined;
  const status = req.query.status as string | undefined;
  const algorithm = req.query.algorithm as string | undefined;

  let allKeys = await db.listKeys({
    organizationId: orgId,
    status,
  });

  if (purpose) {
    allKeys = allKeys.filter((k) => k.purpose === purpose);
  }
  if (algorithm) {
    allKeys = allKeys.filter((k) => k.algorithm.toLowerCase() === algorithm.toLowerCase());
  }

  const pagedKeys = allKeys.slice(offset, offset + limit);
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);

  return res.status(200).json({
    data: pagedKeys.map(sanitizeKey),
    meta: {
      count: pagedKeys.length,
      total: allKeys.length,
      limit,
      offset,
    },
    requestId,
  });
});

// ---------------------------------------------------------------------------
// 2. CREATE LOGICAL KEY
// POST /v1/keys
// ---------------------------------------------------------------------------
router.post(
  '/',
  requireScope('keys:create'),
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const orgId = req.organizationId!;
    const {
      name,
      algorithm,
      purpose,
      description,
      provider = 'LOCAL_DEV',
      metadata,
    } = req.body;

    if (!name || !algorithm || !purpose) {
      const requestId = (req as any).requestId || `req_${Date.now()}`;
      return res.status(400).json({
        error: {
          code: 'INVALID_REQUEST',
          message: 'Fields "name", "algorithm", and "purpose" are required to create a key.',
          retryable: false,
        },
        requestId,
      });
    }

    const providerError = await checkManagedKeyProvider(orgId, provider);
    if (providerError) {
      return res.status(providerError.status).json({
        error: { code: providerError.code, message: providerError.message, retryable: false },
        requestId: (req as any).requestId || `req_${Date.now()}`,
      });
    }

    // Resolve project and environment: Use explicitly supplied, or credential-scoped, or organization default
    let projId = req.body.projectId || req.projectId;
    let envId = req.body.environmentId || req.environmentId;

    if (!projId || !envId) {
      const orgProjects = await db.getProjectsByOrg(orgId);
      if (orgProjects.length === 0) {
        // Auto-provision a default project if none exists
        const defaultProj = await db.createProject({
          name: 'Default Project',
          slug: `default-project-${Date.now()}`,
          organizationId: orgId,
        });
        projId = defaultProj.id;
        const envs = await db.getEnvironmentsByProject(projId);
        envId = envs[0]?.id || 'env_prod_default';
      } else {
        projId = projId || orgProjects[0].id;
        const envs = await db.getEnvironmentsByProject(projId);
        envId = envId || envs[0]?.id || 'env_prod_default';
      }
    }

    // Enforce plan key quota limits
    const limitCheck = await entitlementEngine.checkResourceLimit(orgId, 'keys');
    if (!limitCheck.allowed) {
      const requestId = (req as any).requestId || `req_${Date.now()}`;
      return res.status(403).json({
        error: {
          code: 'KEY_LIMIT_REACHED',
          message: limitCheck.reason,
          retryable: false,
        },
        requestId,
      });
    }

    // Check unique key name per environment
    const existingKey = await db.findKeyByName(orgId, projId, envId, name);
    if (existingKey) {
      const requestId = (req as any).requestId || `req_${Date.now()}`;
      return res.status(409).json({
        error: {
          code: 'KEY_ALREADY_EXISTS',
          message: `A key with name '${name}' already exists in this environment.`,
          retryable: false,
        },
        requestId,
      });
    }

    try {
      // Delegate key material generation to KMS provider
      const providerKeyResult = await kmsService.createKey({
        name,
        algorithm: algorithm as AlgorithmId,
        purpose: purpose as KeyPurpose,
        organizationId: orgId,
        projectId: projId,
        environmentId: envId,
        provider: provider as KeyProviderType,
        metadata,
      });

      // Persist logical key in database
      const newKey = await db.createKey({
        name,
        description,
        organizationId: orgId,
        projectId: projId,
        environmentId: envId,
        algorithm,
        purpose,
        provider,
        status: 'ACTIVE',
        metadata,
      });

      // Persist active version 1 in database
      await db.createKeyVersion({
        keyId: newKey.id,
        version: 1,
        providerKeyId: providerKeyResult.providerKeyId,
        status: 'ACTIVE',
        publicKey: providerKeyResult.publicKey,
        encryptedKeyMaterial: providerKeyResult.encryptedKeyMaterial,
        keyFingerprint: providerKeyResult.keyFingerprint,
        metadata: providerKeyResult.metadata,
      });

      // Audit event
      await db.createAuditEvent({
        organizationId: orgId,
        userId: req.apiKey?.id || req.user?.id || null,
        action: 'key.create',
        resourceType: 'CryptographicKey',
        resourceId: newKey.id,
        metadata: {
          name,
          algorithm,
          purpose,
          provider,
          version: 1,
        },
      });

      const requestId = (req as any).requestId || `req_${Date.now()}`;
      res.setHeader('x-request-id', requestId);

      // Self-hosted: key generation is a billable operation in the local usage ledger (AMARACUS
      // Additional Commercial Terms, section 5.1). AMARACUS Cloud billing for this route is unchanged.
      if (isSelfHosted()) {
        try {
          await usageMeter.recordOperation({
            organizationId: orgId,
            operationType: 'KEY_GEN',
            quantity: 1,
            operationId: (req.headers['idempotency-key'] as string) || `keygen_${newKey.id}`,
            keyId: newKey.id,
          });
        } catch (meterErr) {
          console.warn('[Usage Ledger] Could not record key creation:', meterErr);
        }
      }

      return res.status(201).json({
        data: sanitizeKey(newKey),
        requestId,
      });
    } catch (err: any) {
      const requestId = (req as any).requestId || `req_${Date.now()}`;
      const e = publicError(err, 'Failed to create logical cryptographic key.');
      return res.status(e.status).json({
        error: { code: e.code, message: e.message, retryable: false },
        requestId,
      });
    }
  }
);

// ---------------------------------------------------------------------------
// 3. PROVIDER DISCOVERY
// GET /v1/keys/providers
// ---------------------------------------------------------------------------
router.get('/providers', requireScope('keys:read'), async (req: Request, res: Response) => {
  try {
    const health = await kmsService.getAllProviderHealth();
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    res.setHeader('x-request-id', requestId);
    return res.status(200).json({
      data: health,
      meta: {
        count: health.length,
        timestamp: new Date().toISOString(),
      },
      requestId,
    });
  } catch (err: any) {
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    return res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: err.message || 'Failed to retrieve KMS provider health reports.',
        retryable: false,
      },
      requestId,
    });
  }
});

// ---------------------------------------------------------------------------
// 4. GET KEY METADATA
// GET /v1/keys/:keyId
// ---------------------------------------------------------------------------
router.get('/:keyId', requireScope('keys:read'), async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const key = await db.findKeyById(req.params.keyId, orgId);

  if (!key || key.organizationId !== orgId) {
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    return res.status(404).json({
      error: {
        code: 'KEY_NOT_FOUND',
        message: 'Cryptographic key not found.',
        retryable: false,
      },
      requestId,
    });
  }

  const versions = await db.listKeyVersions(key.id);
  const keyWithVersions = {
    ...key,
    versions,
  };

  const requestId = (req as any).requestId || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);

  return res.status(200).json({
    data: sanitizeKey(keyWithVersions),
    requestId,
  });
});

// ---------------------------------------------------------------------------
// 4. ROTATE KEY VERSION
// POST /v1/keys/:keyId/rotate
// ---------------------------------------------------------------------------
router.post(
  '/:keyId/rotate',
  requireScope('keys:rotate'),
  requireOperationAllowance(1),
  async (req: Request, res: Response) => {
    const orgId = req.organizationId!;
    const key = await db.findKeyById(req.params.keyId, orgId);

    if (!key || key.organizationId !== orgId) {
      const requestId = (req as any).requestId || `req_${Date.now()}`;
      return res.status(404).json({
        error: {
          code: 'KEY_NOT_FOUND',
          message: 'Cryptographic key not found.',
          retryable: false,
        },
        requestId,
      });
    }

    try {
      KeyLifecycleValidator.validateOperationAllowed(key.status as any, 'rotate');

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (!currentVer) {
        throw new Error('Current active key version record is missing.');
      }

      // Delegate rotation to KMS provider
      const providerRes = await kmsService.rotateKey({
        key: {
          ...key,
          purpose: key.purpose as KeyPurpose,
          provider: key.provider as KeyProviderType,
          status: key.status as any,
          algorithm: key.algorithm as AlgorithmId,
        },
        currentActiveVersion: {
          ...currentVer,
          status: currentVer.status as any,
        },
      });

      const nextVersionNum = key.currentVersion + 1;

      // Deprecate previous version
      await db.updateKeyVersion(currentVer.id, { status: 'DEPRECATED' });

      // Create new active version
      const newVersion = await db.createKeyVersion({
        keyId: key.id,
        version: nextVersionNum,
        providerKeyId: providerRes.providerKeyId,
        status: 'ACTIVE',
        publicKey: providerRes.publicKey,
        encryptedKeyMaterial: providerRes.encryptedKeyMaterial,
        keyFingerprint: providerRes.keyFingerprint,
        metadata: providerRes.metadata,
      });

      // Update key record
      const updatedKey = await db.updateKey(key.id, {
        currentVersion: nextVersionNum,
        rotatedAt: new Date(),
      });

      // Audit event
      await db.createAuditEvent({
        organizationId: orgId,
        userId: req.apiKey?.id || req.user?.id || null,
        action: 'key.rotate',
        resourceType: 'CryptographicKey',
        resourceId: key.id,
        metadata: {
          fromVersion: currentVer.version,
          toVersion: nextVersionNum,
        },
      });

      const requestId = (req as any).requestId || `req_${Date.now()}`;
      res.setHeader('x-request-id', requestId);

      return res.status(200).json({
        data: {
          ...sanitizeKey(updatedKey || key),
          currentVersion: nextVersionNum,
          rotatedVersion: sanitizeVersion(newVersion),
        },
        requestId,
      });
    } catch (err: any) {
      const requestId = (req as any).requestId || `req_${Date.now()}`;
      return res.status(err.statusCode || 400).json({
        error: {
          code: err.code || 'ROTATION_FAILED',
          message: err.message || 'Key rotation failed.',
          retryable: false,
        },
        requestId,
      });
    }
  }
);

// ---------------------------------------------------------------------------
// 5. UPDATE KEY STATUS (ENABLE / DISABLE)
// PATCH /v1/keys/:keyId
// ---------------------------------------------------------------------------
router.patch('/:keyId', requireScope('keys:write'), async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const key = await db.findKeyById(req.params.keyId, orgId);

  if (!key || key.organizationId !== orgId) {
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    return res.status(404).json({
      error: {
        code: 'KEY_NOT_FOUND',
        message: 'Cryptographic key not found.',
        retryable: false,
      },
      requestId,
    });
  }

  const { status, description } = req.body;
  if (status && !['ACTIVE', 'DISABLED', 'REVOKED'].includes(status)) {
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    return res.status(400).json({
      error: {
        code: 'INVALID_STATUS',
        message: 'Status must be "ACTIVE", "DISABLED" or "REVOKED".',
        retryable: false,
      },
      requestId,
    });
  }

  // Revocation and destruction are one-way: such keys never change status again.
  const currentStatus = String(key.status || '').toUpperCase();
  if (status && status !== currentStatus && (currentStatus === 'REVOKED' || currentStatus === 'DESTROYED')) {
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    return res.status(409).json({
      error: {
        code: currentStatus === 'REVOKED' ? 'KEY_REVOKED' : 'KEY_DESTROYED',
        message: `Key is ${currentStatus}; its status can no longer change.`,
        retryable: false,
      },
      requestId,
    });
  }

  const updatePayload: any = {};
  if (status) {
    updatePayload.status = status;
    if (status === 'DISABLED') updatePayload.disabledAt = new Date();
    if (status === 'REVOKED') updatePayload.revokedAt = new Date();
  }
  if (description !== undefined) {
    updatePayload.description = description;
  }

  const updatedKey = await db.updateKey(key.id, updatePayload);

  await db.createAuditEvent({
    organizationId: orgId,
    userId: req.apiKey?.id || req.user?.id || null,
    action: `key.${status === 'DISABLED' ? 'disable' : status === 'REVOKED' ? 'revoke' : 'update'}`,
    resourceType: 'CryptographicKey',
    resourceId: key.id,
    metadata: {
      status,
    },
  });

  const requestId = (req as any).requestId || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);

  return res.status(200).json({
    data: sanitizeKey(updatedKey || key),
    requestId,
  });
});

// ---------------------------------------------------------------------------
// 6. DELETE KEY
// DELETE /v1/keys/:keyId
// ---------------------------------------------------------------------------
router.delete('/:keyId', requireScope('keys:delete'), async (req: Request, res: Response) => {
  const orgId = req.organizationId!;
  const key = await db.findKeyById(req.params.keyId, orgId);

  if (!key || key.organizationId !== orgId) {
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    return res.status(404).json({
      error: {
        code: 'KEY_NOT_FOUND',
        message: 'Cryptographic key not found.',
        retryable: false,
      },
      requestId,
    });
  }

  if (key.status === 'DESTROYED') {
    const requestId = (req as any).requestId || `req_${Date.now()}`;
    return res.status(409).json({
      error: { code: 'CONFLICT', message: 'Cryptographic key is already destroyed.', retryable: false },
      requestId,
    });
  }

  // The key record stays as an audit tombstone; every version's wrapped key material is erased
  const updatedKey = await db.updateKey(key.id, {
    status: 'DESTROYED',
    destroyedAt: new Date(),
  });
  for (const v of await db.listKeyVersions(key.id)) {
    await db.updateKeyVersion(v.id, { status: 'DESTROYED', destroyedAt: new Date(), encryptedKeyMaterial: null });
  }

  await db.createAuditEvent({
    organizationId: orgId,
    userId: req.apiKey?.id || req.user?.id || null,
    action: 'key.destroy',
    resourceType: 'CryptographicKey',
    resourceId: key.id,
    metadata: {
      action: 'DESTROYED',
    },
  });

  const requestId = (req as any).requestId || `req_${Date.now()}`;
  res.setHeader('x-request-id', requestId);

  return res.status(200).json({
    data: {
      id: key.id,
      status: 'DESTROYED',
      message: 'Cryptographic key destroyed successfully.',
    },
    requestId,
  });
});

export default router;
