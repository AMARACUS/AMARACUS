import { Router, Request, Response } from 'express';
import { db } from '../../lib/data-store';
import { generateAmaracusApiKey, validateScopes, ApiKeyEnvironment } from '../../lib/api-keys';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { requirePaidPlan } from '../../middleware/billing-guard';
import { validateAllowedIps } from '../../lib/ip-allowlist';
import { clearAutoLock } from '../../lib/decrypt-alerts';
import { sendSuccess, sendCollection, sendError, sendCaughtError } from '../../middleware/response-formatter';

const router = Router();

// GET /api/v1/credentials - List credentials for the active organization
router.get(
  '/',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credentials = await db.getCredentialsByOrg(orgId);

      const items = credentials.map((c) => ({
        id: c.id,
        name: c.name,
        prefix: c.prefix,
        environmentId: c.environmentId,
        projectId: c.projectId,
        scopes: c.scopes || [],
        allowedIps: c.allowedIps || [],
        status: c.status || (c.revokedAt ? 'REVOKED' : 'ACTIVE'),
        createdBy: c.createdBy,
        lastUsedAt: c.lastUsedAt,
        expiresAt: c.expiresAt,
        revokedAt: c.revokedAt,
        createdAt: c.createdAt,
      }));

      return sendCollection(res, items, { hasMore: false, total: items.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to list API credentials.');
    }
  }
);

// POST /api/v1/credentials - Create new scoped API credential (reveals raw key once)
router.post(
  '/',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:manage'),
  requirePaidPlan(),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const { name, environmentId, projectId, scopes, env, expiresInDays, allowedIps } = req.body;
      const ipCheck = validateAllowedIps(allowedIps);
      if (!ipCheck.ok) {
        return sendError(res, 400, 'VALIDATION_FAILED', ipCheck.error);
      }

      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return sendError(res, 400, 'VALIDATION_FAILED', 'Credential name is required.');
      }

      if (!environmentId) {
        return sendError(res, 400, 'VALIDATION_FAILED', 'Environment ID is required.');
      }

      const envObj = await db.getEnvironmentById(environmentId);
      if (!envObj) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Target environment not found.');
      }

      if (scopes && Array.isArray(scopes)) {
        const validation = validateScopes(scopes);
        if (!validation.valid) {
          return sendError(
            res,
            400,
            'VALIDATION_FAILED',
            `Invalid scopes provided: [${validation.invalidScopes.join(', ')}]`
          );
        }
      }

      const keyEnv: ApiKeyEnvironment = env === 'test' || envObj.type === 'development' ? 'test' : 'live';
      const { fullKey, prefix, keyHash } = generateAmaracusApiKey(keyEnv);

      const expiresAt = expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000) : null;

      const credential = await db.createApiCredential({
        organizationId: orgId,
        projectId: projectId || envObj.projectId,
        environmentId,
        name: name.trim(),
        prefix,
        keyHash,
        scopes: scopes || ['*'],
        allowedIps: ipCheck.value,
        status: 'ACTIVE',
        createdBy: req.user?.id || 'api_key',
        expiresAt,
      });

      await db.createAuditEvent({
        organizationId: orgId,
        userId: req.user?.id,
        action: 'api_credential.create',
        resourceType: 'ApiCredential',
        resourceId: credential.id,
        metadata: { name: credential.name, prefix: credential.prefix, environmentId, scopes: credential.scopes },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({
        data: {
          credential: {
            id: credential.id,
            name: credential.name,
            prefix: credential.prefix,
            environmentId: credential.environmentId,
            projectId: credential.projectId,
            scopes: credential.scopes,
            allowedIps: credential.allowedIps || [],
            status: credential.status,
            expiresAt: credential.expiresAt,
            createdAt: credential.createdAt,
          },
          apiKey: fullKey,
          rawApiKey: fullKey,
          warning: 'Save this API key securely now. For security reasons, it will never be displayed again.',
        },
        requestId: (req as any).requestId,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to generate API credential.');
    }
  }
);

// GET /api/v1/credentials/:id - Inspect metadata for a specific credential
router.get(
  '/:id',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credential = await db.findCredentialById(req.params.id);

      if (!credential || credential.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'API credential not found.');
      }

      return sendSuccess(res, {
        id: credential.id,
        name: credential.name,
        prefix: credential.prefix,
        environmentId: credential.environmentId,
        projectId: credential.projectId,
        scopes: credential.scopes || [],
        allowedIps: credential.allowedIps || [],
        status: credential.status || (credential.revokedAt ? 'REVOKED' : 'ACTIVE'),
        createdBy: credential.createdBy,
        lastUsedAt: credential.lastUsedAt,
        expiresAt: credential.expiresAt,
        revokedAt: credential.revokedAt,
        createdAt: credential.createdAt,
        updatedAt: credential.updatedAt,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to retrieve API credential.');
    }
  }
);

// POST /api/v1/credentials/:id/rotate - Rotate an existing credential (generates new secret)
router.post(
  '/:id/rotate',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:manage'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credential = await db.findCredentialById(req.params.id);

      if (!credential || credential.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'API credential not found.');
      }

      const keyEnv: ApiKeyEnvironment = credential.prefix.includes('_test_') ? 'test' : 'live';
      const { fullKey, prefix, keyHash } = generateAmaracusApiKey(keyEnv);

      const updated = await db.rotateCredential(credential.id, prefix, keyHash);

      await db.createAuditEvent({
        organizationId: orgId,
        userId: req.user?.id,
        action: 'api_credential.rotate',
        resourceType: 'ApiCredential',
        resourceId: credential.id,
        metadata: { oldPrefix: credential.prefix, newPrefix: prefix },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return sendSuccess(res, {
        credential: {
          id: updated?.id,
          name: updated?.name,
          prefix: updated?.prefix,
          status: updated?.status,
          updatedAt: updated?.updatedAt,
        },
        newApiKey: fullKey,
        apiKey: fullKey,
        rawApiKey: fullKey,
        warning: 'Your credential was rotated. The previous key secret is immediately invalid.',
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to rotate API credential.');
    }
  }
);

// PATCH /api/v1/credentials/:id - Update credential status or name
router.patch(
  '/:id',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:manage'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credential = await db.findCredentialById(req.params.id);

      if (!credential || credential.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'API credential not found.');
      }

      const { status, allowedIps } = req.body;
      let updated = credential;

      if (allowedIps !== undefined) {
        const ipCheck = validateAllowedIps(allowedIps);
        if (!ipCheck.ok) {
          return sendError(res, 400, 'VALIDATION_FAILED', ipCheck.error);
        }
        updated = (await db.updateCredentialAllowedIps(credential.id, ipCheck.value)) || updated;
        await db.createAuditEvent({
          organizationId: orgId,
          userId: req.user?.id || req.apiKey?.id,
          action: 'api_credential.allowed_ips_updated',
          resourceType: 'ApiCredential',
          resourceId: credential.id,
          metadata: { allowedIps: ipCheck.value || [] },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
      }

      if (status) {
        if (!['ACTIVE', 'DISABLED'].includes(status)) {
          return sendError(res, 400, 'VALIDATION_FAILED', "Status must be 'ACTIVE' or 'DISABLED'.");
        }
        if (credential.status === 'REVOKED') {
          return sendError(res, 400, 'INVALID_STATE', 'Revoked credentials cannot be updated.');
        }
        updated = (await db.updateCredentialStatus(credential.id, status)) || updated;
        if (status === 'ACTIVE') clearAutoLock(credential.id);
      }

      // Never return the key hash.
      return sendSuccess(res, {
        id: updated.id,
        name: updated.name,
        prefix: updated.prefix,
        environmentId: updated.environmentId,
        projectId: updated.projectId,
        scopes: updated.scopes || [],
        allowedIps: updated.allowedIps || [],
        status: updated.status,
        lastUsedAt: updated.lastUsedAt,
        expiresAt: updated.expiresAt,
        revokedAt: updated.revokedAt,
        createdAt: updated.createdAt,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to update API credential.');
    }
  }
);

// POST /api/v1/credentials/:id/disable - Disable a credential
router.post(
  '/:id/disable',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:manage'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credential = await db.findCredentialById(req.params.id);

      if (!credential || credential.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'API credential not found.');
      }

      const updated = await db.updateCredentialStatus(credential.id, 'DISABLED');

      await db.createAuditEvent({
        organizationId: orgId,
        userId: req.user?.id,
        action: 'api_credential.disable',
        resourceType: 'ApiCredential',
        resourceId: credential.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return sendSuccess(res, { success: true, credential: updated });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to disable API credential.');
    }
  }
);

// POST /api/v1/credentials/:id/enable - Re-enable a disabled credential
router.post(
  '/:id/enable',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:manage'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credential = await db.findCredentialById(req.params.id);

      if (!credential || credential.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'API credential not found.');
      }

      if (credential.status === 'REVOKED') {
        return sendError(res, 400, 'INVALID_STATE', 'Revoked credentials cannot be re-enabled. Please create a new credential.');
      }

      const updated = await db.updateCredentialStatus(credential.id, 'ACTIVE');
      clearAutoLock(credential.id);

      await db.createAuditEvent({
        organizationId: orgId,
        userId: req.user?.id,
        action: 'api_credential.enable',
        resourceType: 'ApiCredential',
        resourceId: credential.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      const { keyHash: _keyHash, ...publicView } = (updated || credential) as any;
      return sendSuccess(res, { success: true, credential: publicView });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to enable API credential.');
    }
  }
);

// DELETE /api/v1/credentials/:id - Permanently revoke a credential
router.delete(
  '/:id',
  requireAuth,
  requireOrgMember,
  requireScope('credentials:manage'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credential = await db.findCredentialById(req.params.id);

      if (!credential || credential.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'API credential not found.');
      }

      await db.updateCredentialStatus(credential.id, 'REVOKED');

      await db.createAuditEvent({
        organizationId: orgId,
        userId: req.user?.id,
        action: 'api_credential.revoke',
        resourceType: 'ApiCredential',
        resourceId: credential.id,
        metadata: { prefix: credential.prefix },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return sendSuccess(res, {
        success: true,
        message: `API credential '${credential.prefix}' has been permanently revoked.`,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to revoke API credential.');
    }
  }
);

export default router;
