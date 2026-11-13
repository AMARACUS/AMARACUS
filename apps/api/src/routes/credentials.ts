import { Router, Request, Response } from 'express';
import { db } from '../lib/data-store';
import { generateApiKey } from '../lib/crypto-security';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../middleware/auth';
import { requirePaidPlan } from '../middleware/billing-guard';
import { sendCaughtError } from '../middleware/response-formatter';

const router = Router({ mergeParams: true });

// GET /v1/organizations/:orgId/credentials - List credentials
router.get(
  '/',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('credentials:read'),
  async (req: Request, res: Response) => {
    try {
      const credentials = await db.getCredentialsByOrg(req.organizationId!);
      return res.json({
        credentials: credentials.map((c) => ({
          id: c.id,
          name: c.name,
          prefix: c.prefix,
          environmentId: c.environmentId,
          revokedAt: c.revokedAt,
          createdAt: c.createdAt,
        })),
      });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to fetch credentials.');
    }
  }
);

// POST /v1/organizations/:orgId/credentials - Generate new credential (reveals raw key once)
router.post(
  '/',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('credentials:create'),
  requirePaidPlan(),
  async (req: Request, res: Response) => {
    try {
      const { name, environmentId, envType } = req.body;

      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          error: { code: 'VALIDATION_ERROR', message: 'Credential name is required.' },
        });
      }

      if (!environmentId) {
        return res.status(400).json({
          error: { code: 'VALIDATION_ERROR', message: 'Target environment ID is required.' },
        });
      }

      const env = await db.getEnvironmentById(environmentId);
      if (!env) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Target environment not found.' },
        });
      }

      const { fullKey, prefix, keyHash } = generateApiKey(envType || env.type || 'live');

      const credential = await db.createApiCredential({
        organizationId: req.organizationId!,
        environmentId,
        name: name.trim(),
        prefix,
        keyHash,
      });

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'api_credential.create',
        resourceType: 'ApiCredential',
        resourceId: credential.id,
        metadata: { name: credential.name, prefix: credential.prefix, environmentId },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({
        credential: {
          id: credential.id,
          name: credential.name,
          prefix: credential.prefix,
          environmentId: credential.environmentId,
          createdAt: credential.createdAt,
        },
        rawKey: fullKey,
        warning: 'Store this key securely now. For security reasons, it will never be displayed again.',
      });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to generate credential.');
    }
  }
);

// DELETE /v1/organizations/:orgId/credentials/:credentialId - Revoke credential
router.delete(
  '/:credentialId',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('credentials:revoke'),
  async (req: Request, res: Response) => {
    try {
      const { credentialId } = req.params;
      const credentials = await db.getCredentialsByOrg(req.organizationId!);
      const target = credentials.find((c) => c.id === credentialId);

      if (!target) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Credential not found in this organization.' },
        });
      }

      await db.revokeCredential(credentialId);

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'api_credential.revoke',
        resourceType: 'ApiCredential',
        resourceId: credentialId,
        metadata: { name: target.name, prefix: target.prefix },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ success: true, message: 'Credential successfully revoked.' });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to revoke credential.');
    }
  }
);

export default router;
