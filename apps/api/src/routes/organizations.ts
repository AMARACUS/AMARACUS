import { Router, Request, Response } from 'express';
import { db } from '../lib/data-store';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../middleware/auth';
import { canManageTargetRole, Role } from '../lib/permissions';
import { entitlementEngine } from '../lib/entitlement-engine';
import { sendCaughtError } from '../middleware/response-formatter';

const router = Router();

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'organization';
}

// GET /v1/organizations - List organizations for the authenticated user
router.get('/', requireAuth, async (req: Request, res: Response) => {
  try {
    const orgs = await db.getUserOrganizations(req.user!.id);
    return res.json({
      organizations: orgs.map((o) => ({
        id: o.organization.id,
        name: o.organization.name,
        slug: o.organization.slug,
        role: o.role,
        createdAt: o.organization.createdAt,
      })),
    });
  } catch (error) {
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to retrieve organizations.');
  }
});

// POST /v1/organizations - Create a new organization
router.post('/', requireAuth, async (req: Request, res: Response) => {
  try {
    const { name } = req.body;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Organization name is required.' },
      });
    }

    let slug = slugify(name);
    const existing = await db.findOrgBySlug(slug);
    if (existing) {
      slug = `${slug}-${Math.floor(1000 + Math.random() * 9000)}`;
    }

    const org = await db.createOrganization({
      name: name.trim(),
      slug,
    });

    // Caller is assigned OWNER
    await db.addMember({
      organizationId: org.id,
      userId: req.user!.id,
      role: 'OWNER',
    });

    // Auto-provision initial project & environments
    const project = await db.createProject({
      organizationId: org.id,
      name: 'Default Project',
      slug: 'default-project',
      description: 'Primary project for cryptographic workloads.',
    });

    await db.createEnvironment({ projectId: project.id, name: 'Production', slug: 'production', type: 'production' });
    await db.createEnvironment({ projectId: project.id, name: 'Staging', slug: 'staging', type: 'staging' });
    await db.createEnvironment({ projectId: project.id, name: 'Development', slug: 'development', type: 'development' });

    // Set as active organization for current session
    if (req.session) {
      await db.updateSessionActiveOrg(req.session.sessionToken, org.id);
    }

    await db.createAuditEvent({
      organizationId: org.id,
      userId: req.user!.id,
      action: 'organization.create',
      resourceType: 'Organization',
      resourceId: org.id,
      metadata: { name: org.name, slug: org.slug },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(201).json({
      organization: {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role: 'OWNER',
        createdAt: org.createdAt,
      },
    });
  } catch (error) {
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to create organization.');
  }
});

// POST /v1/organizations/:orgId/switch - Switch active organization in session
router.post('/:orgId/switch', requireAuth, requireOrgMember, async (req: Request, res: Response) => {
  try {
    const org = await db.findOrgById(req.organizationId!);
    if (req.session) {
      await db.updateSessionActiveOrg(req.session.sessionToken, req.organizationId!);
    }

    return res.json({
      success: true,
      activeOrganization: {
        id: org!.id,
        name: org!.name,
        slug: org!.slug,
        role: req.orgRole,
      },
    });
  } catch (error) {
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to switch organization.');
  }
});

// GET /v1/organizations/:orgId - Get organization details
router.get('/:orgId', requireAuth, requireOrgMember, async (req: Request, res: Response) => {
  const org = await db.findOrgById(req.organizationId!);
  return res.json({
    organization: {
      id: org!.id,
      name: org!.name,
      slug: org!.slug,
      role: req.orgRole,
      createdAt: org!.createdAt,
    },
  });
});

// PATCH /v1/organizations/:orgId - Update organization settings
router.patch(
  '/:orgId',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('org:update'),
  async (req: Request, res: Response) => {
    try {
      const { name } = req.body;
      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          error: { code: 'VALIDATION_ERROR', message: 'Organization name is required.' },
        });
      }

      const updated = await db.updateOrg(req.organizationId!, { name: name.trim() });

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'organization.update',
        resourceType: 'Organization',
        resourceId: req.organizationId,
        metadata: { updatedName: name.trim() },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({
        organization: {
          id: updated!.id,
          name: updated!.name,
          slug: updated!.slug,
          role: req.orgRole,
        },
      });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to update organization.');
    }
  }
);

// GET /v1/organizations/:orgId/members - List members
router.get(
  '/:orgId/members',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('members:read'),
  async (req: Request, res: Response) => {
    try {
      const members = await db.getOrgMembers(req.organizationId!);
      return res.json({
        members: members.map((m) => ({
          id: m.id,
          userId: m.userId,
          role: m.role,
          email: m.user.email,
          name: m.user.name,
          createdAt: m.createdAt,
        })),
      });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to fetch organization members.');
    }
  }
);

// POST /v1/organizations/:orgId/members - Add/Invite member
router.post(
  '/:orgId/members',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('members:invite'),
  async (req: Request, res: Response) => {
    try {
      const { email, role } = req.body;
      if (!email || !role || !['OWNER', 'ADMIN', 'MEMBER'].includes(role)) {
        return res.status(400).json({
          error: { code: 'VALIDATION_ERROR', message: 'Valid email and role (OWNER, ADMIN, MEMBER) are required.' },
        });
      }

      if (!canManageTargetRole(req.orgRole!, role as Role)) {
        return res.status(403).json({
          error: { code: 'FORBIDDEN', message: `Your role (${req.orgRole}) cannot assign the ${role} role.` },
        });
      }

      // Enforce plan member limit
      const limitCheck = await entitlementEngine.checkResourceLimit(req.organizationId!, 'members');
      if (!limitCheck.allowed) {
        return res.status(403).json({
          error: {
            code: 'MEMBER_LIMIT_REACHED',
            message: limitCheck.reason,
            plan: limitCheck.planId,
            currentCount: limitCheck.currentCount,
            maxLimit: limitCheck.maxLimit,
            upgradeRequired: true,
          },
        });
      }

      let targetUser = await db.findUserByEmail(email);
      if (!targetUser) {
        // In a complete SaaS, an invitation email is dispatched. Here we create a provisioned user record or stub
        targetUser = await db.createUser({
          email,
          name: email.split('@')[0],
          passwordHash: 'pending_invitation_hash',
        });
      }

      const existingMember = await db.getMember(req.organizationId!, targetUser.id);
      if (existingMember) {
        return res.status(409).json({
          error: { code: 'CONFLICT', message: 'User is already a member of this organization.' },
        });
      }

      const member = await db.addMember({
        organizationId: req.organizationId!,
        userId: targetUser.id,
        role: role as Role,
      });

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'member.invite',
        resourceType: 'OrganizationMember',
        resourceId: member.id,
        metadata: { invitedEmail: email, assignedRole: role },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({
        member: {
          id: member.id,
          userId: member.userId,
          role: member.role,
          email: targetUser.email,
          name: targetUser.name,
        },
      });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to add member.');
    }
  }
);

// DELETE /v1/organizations/:orgId/members/:memberId - Remove member
router.delete(
  '/:orgId/members/:memberId',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('members:remove'),
  async (req: Request, res: Response) => {
    try {
      const { memberId } = req.params;
      const members = await db.getOrgMembers(req.organizationId!);
      const target = members.find((m) => m.id === memberId);

      if (!target) {
        return res.status(404).json({
          error: { code: 'NOT_FOUND', message: 'Member not found.' },
        });
      }

      if (target.role === 'OWNER' && req.orgRole !== 'OWNER') {
        return res.status(403).json({
          error: { code: 'FORBIDDEN', message: 'Only an owner can remove another owner.' },
        });
      }

      // Count owners to prevent removing the sole owner
      const owners = members.filter((m) => m.role === 'OWNER');
      if (target.role === 'OWNER' && owners.length <= 1) {
        return res.status(400).json({
          error: { code: 'BAD_REQUEST', message: 'Cannot remove the sole owner of an organization.' },
        });
      }

      await db.removeMember(req.organizationId!, memberId);

      await db.createAuditEvent({
        organizationId: req.organizationId,
        userId: req.user!.id,
        action: 'member.remove',
        resourceType: 'OrganizationMember',
        resourceId: memberId,
        metadata: { removedUserId: target.userId },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ success: true });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to remove member.');
    }
  }
);

export default router;
