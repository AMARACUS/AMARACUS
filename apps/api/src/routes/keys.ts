import { selfHostGate, selfHostMeterOnSuccess } from '../middleware/selfhost-metering';
/// <reference path="../types/express.d.ts" />
import { Router, Request, Response, NextFunction } from 'express';
import {
  KeyManagementService,
  KeyLifecycleValidator,
  CryptoEngineError,
  KeyProviderType,
  KeyPurpose,
  AlgorithmId,
} from '@amaracus/crypto-core';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../middleware/auth';
import { createRateLimiter, payloadSizeLimiter } from '../middleware/rate-limiter';
import { db, CryptographicKeyRecord, CryptographicKeyVersionRecord } from '../lib/data-store';
import { entitlementEngine } from '../lib/entitlement-engine';
import { checkManagedKeyProvider } from '../lib/entitlements';
import { requireOperationAllowance } from '../middleware/billing-guard';
import { usageMeter } from '../lib/usage-meter';

/** Decodes a request field as UTF-8 text (default), base64 or hex bytes. */
function decodeInput(value: unknown, encoding?: string): Buffer {
  const enc = encoding === 'base64' || encoding === 'hex' ? encoding : 'utf8';
  return Buffer.from(String(value), enc);
}

/** UTF-8 only when the bytes are valid UTF-8; otherwise base64, never a lossy string. */
function encodeOutput(buf: Buffer, requested?: string): { plaintext: string; encoding: string } {
  if (requested === 'base64' || requested === 'hex') {
    return { plaintext: buf.toString(requested), encoding: requested };
  }
  try {
    return { plaintext: new TextDecoder('utf-8', { fatal: true }).decode(buf), encoding: 'utf8' };
  } catch {
    return { plaintext: buf.toString('base64'), encoding: 'base64' };
  }
}

const router = Router({ mergeParams: true });
const kmsService = new KeyManagementService();

// Common middleware for all key routes:
router.use(requireAuth);
router.use(requireOrgMember);
router.use(payloadSizeLimiter(1048576)); // 1MB payload limit
router.use(createRateLimiter({ limit: 300, windowMs: 60000 })); // 300 req/min

// Helper: Strip sensitive internal fields from key responses
function sanitizeKey(key: CryptographicKeyRecord) {
  const { versions, ...rest } = key;
  return {
    ...rest,
    versions: versions ? versions.map(sanitizeVersion) : undefined,
  };
}

function sanitizeVersion(ver: CryptographicKeyVersionRecord) {
  const { encryptedKeyMaterial, ...safeVer } = ver;
  return safeVer;
}

// Helper: Safe audit logging
async function logKeyAudit(
  req: Request,
  action: string,
  keyId: string,
  metadata?: Record<string, any>
) {
  try {
    await db.createAuditEvent({
      organizationId: req.organizationId || null,
      userId: req.user?.id || null,
      action,
      resourceType: 'CryptographicKey',
      resourceId: keyId,
      metadata: {
        ...metadata,
        ipAddress: req.ip || null,
      },
      ipAddress: req.ip || null,
      userAgent: req.headers['user-agent'] || null,
    });

    if (action.startsWith('key.') && ['key.encrypt', 'key.decrypt', 'key.sign', 'key.verify'].includes(action)) {
      const opType = action.replace('key.', '').toUpperCase();
      await db.createCryptographicOperation({
        organizationId: req.organizationId!,
        operationType: opType,
        keyId,
        status: 'COMPLETED',
        metadata,
      });
    }
  } catch (err) {
    console.warn('[Audit Warning] Failed to record key audit event:', err);
  }
}

// -------------------------------------------------------------
// 1. PROVIDER DISCOVERY
// GET /v1/organizations/:orgId/keys/providers
// -------------------------------------------------------------
router.get(
  '/providers',
  requireOrgPermission('kms:providers:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const health = await kmsService.getAllProviderHealth();
      res.json({
        data: health,
        meta: {
          count: health.length,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// -------------------------------------------------------------
// 2. KEY CREATION & INVENTORY
// POST /v1/organizations/:orgId/keys
// -------------------------------------------------------------
router.post(
  '/',
  requireOrgPermission('keys:create'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        name,
        description,
        projectId,
        environmentId,
        algorithm,
        purpose,
        provider = 'LOCAL_DEV',
        metadata,
      } = req.body;

      if (!name || !projectId || !environmentId || !algorithm || !purpose) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Missing required fields: name, projectId, environmentId, algorithm, purpose.',
          },
        });
      }

      const orgId = req.organizationId!;

      const providerError = await checkManagedKeyProvider(orgId, provider);
      if (providerError) {
        return res.status(providerError.status).json({
          error: { code: providerError.code, message: providerError.message },
        });
      }

      // Enforce plan key limit
      const limitCheck = await entitlementEngine.checkResourceLimit(orgId, 'keys');
      if (!limitCheck.allowed) {
        return res.status(403).json({
          error: {
            code: 'KEY_LIMIT_REACHED',
            message: limitCheck.reason,
            plan: limitCheck.planId,
            currentCount: limitCheck.currentCount,
            maxLimit: limitCheck.maxLimit,
            upgradeRequired: true,
          },
        });
      }

      // Validate project belongs to org
      const project = await db.getProjectById(projectId);
      if (!project || project.organizationId !== orgId) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Project not found in this organization.' },
        });
      }

      // Validate environment belongs to project
      const environment = await db.getEnvironmentById(environmentId);
      if (!environment || environment.projectId !== projectId) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Environment not found in this project.' },
        });
      }

      // Check unique key name per environment
      const existingKey = await db.findKeyByName(orgId, projectId, environmentId, name);
      if (existingKey) {
        return res.status(409).json({
          error: {
            code: 'KEY_NAME_EXISTS',
            message: `A cryptographic key with name '${name}' already exists in this environment.`,
          },
        });
      }

      // Provider delegation for key generation
      const providerKeyResult = await kmsService.createKey({
        name,
        algorithm: algorithm as AlgorithmId,
        purpose: purpose as KeyPurpose,
        organizationId: orgId,
        projectId,
        environmentId,
        provider: provider as KeyProviderType,
        metadata,
      });

      // Persist managed key in database
      const newKey = await db.createKey({
        name,
        description,
        organizationId: orgId,
        projectId,
        environmentId,
        algorithm,
        purpose,
        provider,
        status: 'ACTIVE',
        metadata,
      });

      // Persist version 1 in database
      const version1 = await db.createKeyVersion({
        keyId: newKey.id,
        version: 1,
        providerKeyId: providerKeyResult.providerKeyId,
        status: 'ACTIVE',
        publicKey: providerKeyResult.publicKey,
        encryptedKeyMaterial: providerKeyResult.encryptedKeyMaterial,
        keyFingerprint: providerKeyResult.keyFingerprint,
        metadata: providerKeyResult.metadata,
      });

      await logKeyAudit(req, 'key.create', newKey.id, {
        name,
        algorithm,
        purpose,
        provider,
        version: 1,
      });

      // Authoritatively meter successful cryptographic key generation
      try {
        const operationId = (req.headers['idempotency-key'] as string) || (req as any).requestId;
        await usageMeter.recordOperation({
          organizationId: orgId,
          operationType: 'KEY_GEN',
          quantity: 1,
          operationId,
          keyId: newKey.id,
          projectId,
        });
      } catch (meterErr) {
        console.warn('[Usage Metering Warning] Could not record key creation usage:', meterErr);
      }

      const fullKey = await db.findKeyById(newKey.id, orgId);
      res.status(201).json({
        data: sanitizeKey(fullKey || { ...newKey, versions: [version1] }),
      });
    } catch (err) {
      next(err);
    }
  }
);

// GET /v1/organizations/:orgId/keys
router.get(
  '/',
  requireOrgPermission('keys:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { projectId, environmentId, status, search } = req.query;
      const keys = await db.listKeys({
        organizationId: req.organizationId!,
        projectId: projectId as string | undefined,
        environmentId: environmentId as string | undefined,
        status: status as string | undefined,
        search: search as string | undefined,
      });

      res.json({
        data: keys.map(sanitizeKey),
        meta: {
          count: keys.length,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// GET /v1/organizations/:orgId/keys/:keyId
router.get(
  '/:keyId',
  requireOrgPermission('keys:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      res.json({
        data: sanitizeKey(key),
      });
    } catch (err) {
      next(err);
    }
  }
);

// -------------------------------------------------------------
// 3. KEY VERSIONS
// GET /v1/organizations/:orgId/keys/:keyId/versions
// -------------------------------------------------------------
router.get(
  '/:keyId/versions',
  requireOrgPermission('keys:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      const versions = await db.listKeyVersions(key.id);
      res.json({
        data: versions.map(sanitizeVersion),
        meta: { count: versions.length },
      });
    } catch (err) {
      next(err);
    }
  }
);

// GET /v1/organizations/:orgId/keys/:keyId/versions/:version
router.get(
  '/:keyId/versions/:version',
  requireOrgPermission('keys:read'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      const verNum = parseInt(req.params.version, 10);
      if (isNaN(verNum)) {
        return res.status(400).json({
          error: { code: 'INVALID_INPUT', message: 'Version must be a valid integer.' },
        });
      }

      const version = await db.findKeyVersionByNumber(key.id, verNum);
      if (!version) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: `Version ${verNum} not found for this key.` },
        });
      }

      res.json({
        data: sanitizeVersion(version),
      });
    } catch (err) {
      next(err);
    }
  }
);

// -------------------------------------------------------------
// 4. KEY LIFECYCLE MANAGEMENT
// -------------------------------------------------------------

// POST /v1/organizations/:orgId/keys/:keyId/rotate
router.post(
  '/:keyId/rotate',
  requireOrgPermission('keys:rotate'),
  requireOperationAllowance(1),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      KeyLifecycleValidator.validateOperationAllowed(key.status as any, 'rotate');

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (!currentVer) {
        return res.status(500).json({
          error: { code: 'INTERNAL_ERROR', message: 'Current key version record is missing.' },
        });
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

      // Update parent key metadata
      const updatedKey = await db.updateKey(key.id, {
        currentVersion: nextVersionNum,
        rotatedAt: new Date(),
      });

      await logKeyAudit(req, 'key.rotate', key.id, {
        previousVersion: key.currentVersion,
        newVersion: nextVersionNum,
      });

      res.json({
        data: {
          key: sanitizeKey(updatedKey),
          newVersion: sanitizeVersion(newVersion),
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/disable
router.post(
  '/:keyId/disable',
  requireOrgPermission('keys:disable'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      KeyLifecycleValidator.validateTransition(key.status as any, 'DISABLED');

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (currentVer) {
        await kmsService.disableKey(key as any, currentVer as any);
      }

      const updated = await db.updateKey(key.id, {
        status: 'DISABLED',
        disabledAt: new Date(),
      });

      await logKeyAudit(req, 'key.disable', key.id);

      res.json({ data: sanitizeKey(updated) });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/enable
router.post(
  '/:keyId/enable',
  requireOrgPermission('keys:enable'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      KeyLifecycleValidator.validateTransition(key.status as any, 'ACTIVE');

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (currentVer) {
        await kmsService.enableKey(key as any, currentVer as any);
      }

      const updated = await db.updateKey(key.id, {
        status: 'ACTIVE',
        disabledAt: null,
      });

      await logKeyAudit(req, 'key.enable', key.id);

      res.json({ data: sanitizeKey(updated) });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/revoke
router.post(
  '/:keyId/revoke',
  requireOrgPermission('keys:revoke'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { reason } = req.body;
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      KeyLifecycleValidator.validateTransition(key.status as any, 'REVOKED');

      const updated = await db.updateKey(key.id, {
        status: 'REVOKED',
        revokedAt: new Date(),
        metadata: {
          ...(key.metadata || {}),
          revocationReason: reason || 'Not specified',
        },
      });

      // Also mark all versions revoked
      const versions = await db.listKeyVersions(key.id);
      for (const v of versions) {
        await db.updateKeyVersion(v.id, { status: 'REVOKED', revokedAt: new Date() });
      }

      await logKeyAudit(req, 'key.revoke', key.id, { reason });

      res.json({ data: sanitizeKey(updated) });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/schedule-deletion
router.post(
  '/:keyId/schedule-deletion',
  requireOrgPermission('keys:destroy'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const days = parseInt(req.body.pendingDays || '7', 10);
      if (isNaN(days) || days < 7 || days > 30) {
        return res.status(400).json({
          error: {
            code: 'INVALID_INPUT',
            message: 'Pending window for scheduled deletion must be between 7 and 30 days.',
          },
        });
      }

      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      KeyLifecycleValidator.validateTransition(key.status as any, 'SCHEDULED_FOR_DELETION');

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      let deletionDate: Date = new Date(Date.now() + days * 86400000);

      if (currentVer) {
        deletionDate = await kmsService.scheduleDeletion(key as any, currentVer as any, days);
      }

      const updated = await db.updateKey(key.id, {
        status: 'SCHEDULED_FOR_DELETION',
        scheduledDeletionAt: deletionDate,
      });

      await logKeyAudit(req, 'key.schedule_deletion', key.id, {
        pendingDays: days,
        scheduledDate: deletionDate.toISOString(),
      });

      res.json({ data: sanitizeKey(updated) });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/cancel-deletion
router.post(
  '/:keyId/cancel-deletion',
  requireOrgPermission('keys:destroy'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      if (key.status !== 'SCHEDULED_FOR_DELETION') {
        return res.status(400).json({
          error: {
            code: 'INVALID_STATE_TRANSITION',
            message: 'Key is not currently scheduled for deletion.',
          },
        });
      }

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (currentVer) {
        await kmsService.cancelDeletion(key as any, currentVer as any);
      }

      const updated = await db.updateKey(key.id, {
        status: 'ACTIVE',
        scheduledDeletionAt: null,
      });

      await logKeyAudit(req, 'key.cancel_deletion', key.id);

      res.json({ data: sanitizeKey(updated) });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/recover
router.post(
  '/:keyId/recover',
  requireOrgPermission('keys:destroy'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      if (key.status !== 'SCHEDULED_FOR_DELETION' && key.status !== 'DISABLED') {
        return res.status(400).json({
          error: {
            code: 'INVALID_STATE_TRANSITION',
            message: `Key in status '${key.status}' cannot be recovered. Only SCHEDULED_FOR_DELETION or DISABLED keys can be recovered.`,
          },
        });
      }

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (currentVer) {
        await kmsService.recoverKey(key as any, currentVer as any);
      }

      const updated = await db.updateKey(key.id, {
        status: 'ACTIVE',
        scheduledDeletionAt: null,
        disabledAt: null,
      });

      await logKeyAudit(req, 'key.recover', key.id);

      res.json({ data: sanitizeKey(updated), message: 'Key successfully recovered and set to ACTIVE.' });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/purge
router.post(
  '/:keyId/purge',
  requireOrgPermission('keys:destroy'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      KeyLifecycleValidator.validateTransition(key.status as any, 'DESTROYED');

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (currentVer) {
        await kmsService.purgeKey(key as any, currentVer as any);
      }

      const updated = await db.updateKey(key.id, {
        status: 'DESTROYED',
        destroyedAt: new Date(),
      });

      const versions = await db.listKeyVersions(key.id);
      for (const v of versions) {
        await db.updateKeyVersion(v.id, {
          status: 'DESTROYED',
          destroyedAt: new Date(),
          encryptedKeyMaterial: null,
        });
      }

      await logKeyAudit(req, 'key.purge', key.id);

      res.json({
        data: sanitizeKey(updated),
        message: 'Key permanently purged and destroyed from provider storage.',
      });
    } catch (err) {
      next(err);
    }
  }
);

// DELETE /v1/organizations/:orgId/keys/:keyId
router.delete(
  '/:keyId',
  requireOrgPermission('keys:destroy'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      KeyLifecycleValidator.validateTransition(key.status as any, 'DESTROYED');

      const currentVer = await db.findKeyVersionByNumber(key.id, key.currentVersion);
      if (currentVer) {
        await kmsService.destroyKey(key as any, currentVer as any);
      }

      const updated = await db.updateKey(key.id, {
        status: 'DESTROYED',
        destroyedAt: new Date(),
      });

      // Mark all versions destroyed
      const versions = await db.listKeyVersions(key.id);
      for (const v of versions) {
        await db.updateKeyVersion(v.id, {
          status: 'DESTROYED',
          destroyedAt: new Date(),
          encryptedKeyMaterial: null, // Scrub encrypted key material immediately
        });
      }

      await logKeyAudit(req, 'key.destroy', key.id);

      res.json({
        data: sanitizeKey(updated),
        message: 'Key has been permanently destroyed and is now a terminal tombstone.',
      });
    } catch (err) {
      next(err);
    }
  }
);

// -------------------------------------------------------------
// 5. CRYPTOGRAPHIC OPERATIONS WITH MANAGED KEYS
// -------------------------------------------------------------

// POST /v1/organizations/:orgId/keys/:keyId/encrypt
router.post(
  '/:keyId/encrypt',
  requireOrgPermission('keys:use:encrypt'),
  requireOperationAllowance(1),
  selfHostMeterOnSuccess('ENCRYPT'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { plaintext, aad, version, encoding } = req.body;
      if (!plaintext) {
        return res.status(400).json({
          error: { code: 'INVALID_INPUT', message: 'Plaintext payload is required.' },
        });
      }

      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      const verNum = version ? parseInt(version, 10) : key.currentVersion;
      const keyVersion = await db.findKeyVersionByNumber(key.id, verNum);
      if (!keyVersion) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: `Key version ${verNum} not found.` },
        });
      }

      const ptBuffer = decodeInput(plaintext, encoding);
      const aadBuffer = aad ? Buffer.from(aad, 'utf8') : undefined;

      const envelope = await kmsService.encryptWithKey(
        key as any,
        keyVersion as any,
        ptBuffer,
        aadBuffer
      );

      await logKeyAudit(req, 'key.encrypt', key.id, { version: verNum });

      res.json({
        data: {
          envelope,
          keyId: key.id,
          version: verNum,
          algorithm: key.algorithm,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/decrypt
router.post(
  '/:keyId/decrypt',
  requireOrgPermission('keys:use:decrypt'),
  requireOperationAllowance(1),
  selfHostMeterOnSuccess('DECRYPT'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { envelope, version, outputEncoding } = req.body;
      if (!envelope) {
        return res.status(400).json({
          error: { code: 'INVALID_INPUT', message: 'Ciphertext envelope is required.' },
        });
      }

      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      const verNum = version ? parseInt(version, 10) : key.currentVersion;
      const keyVersion = await db.findKeyVersionByNumber(key.id, verNum);
      if (!keyVersion) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: `Key version ${verNum} not found.` },
        });
      }

      const plaintextBuffer = await kmsService.decryptWithKey(
        key as any,
        keyVersion as any,
        envelope
      );

      await logKeyAudit(req, 'key.decrypt', key.id, { version: verNum });

      res.json({
        data: {
          ...encodeOutput(plaintextBuffer, outputEncoding),
          keyId: key.id,
          version: verNum,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/sign
router.post(
  '/:keyId/sign',
  requireOrgPermission('keys:use:sign'),
  selfHostGate(),
  selfHostMeterOnSuccess('SIGN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { data, version } = req.body;
      if (!data) {
        return res.status(400).json({
          error: { code: 'INVALID_INPUT', message: 'Data to sign is required.' },
        });
      }

      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      const verNum = version ? parseInt(version, 10) : key.currentVersion;
      const keyVersion = await db.findKeyVersionByNumber(key.id, verNum);
      if (!keyVersion) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: `Key version ${verNum} not found.` },
        });
      }

      const dataBuffer = decodeInput(data, req.body.dataEncoding);
      const sigBuffer = await kmsService.signWithKey(
        key as any,
        keyVersion as any,
        dataBuffer
      );

      await logKeyAudit(req, 'key.sign', key.id, { version: verNum });

      res.json({
        data: {
          signature: sigBuffer.toString('hex'),
          encoding: 'hex',
          keyId: key.id,
          version: verNum,
          algorithm: key.algorithm,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// POST /v1/organizations/:orgId/keys/:keyId/verify
router.post(
  '/:keyId/verify',
  requireOrgPermission('keys:use:verify'),
  selfHostMeterOnSuccess('VERIFY'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { data, signature, version, encoding = 'hex' } = req.body;
      if (!data || !signature) {
        return res.status(400).json({
          error: { code: 'INVALID_INPUT', message: 'Data and signature are required.' },
        });
      }

      const key = await db.findKeyById(req.params.keyId, req.organizationId!);
      if (!key) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Cryptographic key not found.' },
        });
      }

      const verNum = version ? parseInt(version, 10) : key.currentVersion;
      const keyVersion = await db.findKeyVersionByNumber(key.id, verNum);
      if (!keyVersion) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: `Key version ${verNum} not found.` },
        });
      }

      const dataBuffer = decodeInput(data, req.body.dataEncoding);
      const sigBuffer = Buffer.from(signature, encoding === 'base64' ? 'base64' : 'hex');

      const isValid = await kmsService.verifyWithKey(
        key as any,
        keyVersion as any,
        dataBuffer,
        sigBuffer
      );

      await logKeyAudit(req, 'key.verify', key.id, { version: verNum, isValid });

      res.json({
        data: {
          isValid,
          keyId: key.id,
          version: verNum,
          algorithm: key.algorithm,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

export default router;
