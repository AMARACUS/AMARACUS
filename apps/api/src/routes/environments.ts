import { Router, Request, Response } from 'express';
import { db } from '../lib/data-store';
import { requireAuth, requireOrgMember, requireOrgPermission, validateOwnershipChain } from '../middleware/auth';
import { sendCaughtError } from '../middleware/response-formatter';

const router = Router({ mergeParams: true });

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'env';
}

// GET /v1/organizations/:orgId/projects/:projectId/environments
router.get(
  '/',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('environments:read'),
  validateOwnershipChain,
  async (req: Request, res: Response) => {
    try {
      const environments = await db.getEnvironmentsByProject(req.project!.id);
      return res.json({ environments });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to fetch environments.');
    }
  }
);

// POST /v1/organizations/:orgId/projects/:projectId/environments
router.post(
  '/',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('environments:create'),
  validateOwnershipChain,
  async (req: Request, res: Response) => {
    try {
      const { name, type } = req.body;
      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          error: { code: 'VALIDATION_ERROR', message: 'Environment name is required.' },
        });
      }

      const slug = slugify(name);
      const existing = await db.getEnvironmentsByProject(req.project!.id);
      if (existing.some((e) => e.slug === slug)) {
        return res.status(409).json({
          error: { code: 'CONFLICT', message: 'An environment with this name or slug already exists.' },
        });
      }

      const env = await db.createEnvironment({
        projectId: req.project!.id,
        name: name.trim(),
        slug,
        type: type || 'custom',
      });

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'environment.create',
        resourceType: 'Environment',
        resourceId: env.id,
        metadata: { projectId: req.project!.id, name: env.name, type: env.type },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({ environment: env });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to create environment.');
    }
  }
);

// DELETE /v1/organizations/:orgId/projects/:projectId/environments/:envId
router.delete(
  '/:envId',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('environments:delete'),
  validateOwnershipChain,
  async (req: Request, res: Response) => {
    try {
      await db.deleteEnvironment(req.environment!.id);

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'environment.delete',
        resourceType: 'Environment',
        resourceId: req.environment!.id,
        metadata: { name: req.environment!.name },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ success: true });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to delete environment.');
    }
  }
);

export default router;
