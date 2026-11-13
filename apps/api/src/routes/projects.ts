/// <reference path="../types/express.d.ts" />
import { Router, Request, Response } from 'express';
import { db } from '../lib/data-store';
import { entitlementEngine } from '../lib/entitlement-engine';
import { requireAuth, requireOrgMember, requireOrgPermission, validateOwnershipChain } from '../middleware/auth';
import { sendCaughtError } from '../middleware/response-formatter';

const router = Router({ mergeParams: true });

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'project';
}

// GET /v1/organizations/:orgId/projects
router.get(
  '/',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('projects:read'),
  async (req: Request, res: Response) => {
    try {
      const projects = await db.getProjectsByOrg(req.organizationId!);
      return res.json({ projects });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to fetch projects.');
    }
  }
);

// POST /v1/organizations/:orgId/projects
router.post(
  '/',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('projects:create'),
  async (req: Request, res: Response) => {
    try {
      const { name, slug, description } = req.body;

      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          error: { code: 'VALIDATION_ERROR', message: 'Project name is required.' },
        });
      }

      // Enforce plan project limit
      const limitCheck = await entitlementEngine.checkResourceLimit(req.organizationId!, 'projects');
      if (!limitCheck.allowed) {
        return res.status(403).json({
          error: {
            code: 'PROJECT_LIMIT_REACHED',
            message: limitCheck.reason,
            plan: limitCheck.planId,
            currentCount: limitCheck.currentCount,
            maxLimit: limitCheck.maxLimit,
            upgradeRequired: true,
          },
        });
      }

      let projectSlug = (slug ? slugify(slug) : slugify(name));
      const existingProjects = await db.getProjectsByOrg(req.organizationId!);
      if (existingProjects.some((p) => p.slug === projectSlug)) {
        projectSlug = `${projectSlug}-${Math.floor(1000 + Math.random() * 9000)}`;
      }

      const project = await db.createProject({
        organizationId: req.organizationId!,
        name: name.trim(),
        slug: projectSlug,
        description: description?.trim() || null,
      });

      // Auto-provision default environments
      const prod = await db.createEnvironment({ projectId: project.id, name: 'Production', slug: 'production', type: 'production' });
      const staging = await db.createEnvironment({ projectId: project.id, name: 'Staging', slug: 'staging', type: 'staging' });
      const dev = await db.createEnvironment({ projectId: project.id, name: 'Development', slug: 'development', type: 'development' });

      project.environments = [prod, staging, dev];

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'project.create',
        resourceType: 'Project',
        resourceId: project.id,
        metadata: { name: project.name, slug: project.slug },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({ project });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to create project.');
    }
  }
);

// GET /v1/organizations/:orgId/projects/:projectId
router.get(
  '/:projectId',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('projects:read'),
  validateOwnershipChain,
  async (req: Request, res: Response) => {
    return res.json({ project: req.project });
  }
);

// DELETE /v1/organizations/:orgId/projects/:projectId
router.delete(
  '/:projectId',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('projects:delete'),
  validateOwnershipChain,
  async (req: Request, res: Response) => {
    try {
      await db.deleteProject(req.project!.id);

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'project.delete',
        resourceType: 'Project',
        resourceId: req.project!.id,
        metadata: { name: req.project!.name },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ success: true });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to delete project.');
    }
  }
);

export default router;
