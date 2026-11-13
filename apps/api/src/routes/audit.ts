import { Router, Request, Response } from 'express';
import { db } from '../lib/data-store';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../middleware/auth';
import { sendCaughtError } from '../middleware/response-formatter';

const router = Router({ mergeParams: true });

// GET /v1/organizations/:orgId/audit - Query audit events for organization
router.get(
  '/',
  requireAuth,
  requireOrgMember,
  requireOrgPermission('audit:read'),
  async (req: Request, res: Response) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
      // Page back with ?before=<nextBefore from the previous page>; filter with ?action=crypto.decrypt
      let before: Date | undefined;
      if (typeof req.query.before === 'string' && req.query.before) {
        before = new Date(req.query.before);
        if (Number.isNaN(before.getTime())) {
          return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: '"before" must be an ISO date-time.' } });
        }
      }
      const action = typeof req.query.action === 'string' && req.query.action ? req.query.action : undefined;
      const events = await db.getAuditEventsByOrg(req.organizationId!, limit, { before, action });
      const last = events[events.length - 1];

      return res.json({
        auditEvents: events.map((e) => ({
          id: e.id,
          action: e.action,
          actorId: e.userId,
          resourceType: e.resourceType,
          resourceId: e.resourceId,
          metadata: e.metadata,
          ipAddress: e.ipAddress,
          createdAt: e.createdAt,
        })),
        nextBefore: events.length === limit && last ? new Date(last.createdAt).toISOString() : null,
      });
    } catch (error) {
      return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to fetch audit events.');
    }
  }
);

export default router;
