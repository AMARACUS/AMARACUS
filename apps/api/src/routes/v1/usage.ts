import { Router, Request, Response } from 'express';
import { db } from '../../lib/data-store';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendError, sendCaughtError } from '../../middleware/response-formatter';

const router = Router();

// GET /api/v1/usage - Get aggregated API usage telemetry
router.get(
  '/',
  requireAuth,
  requireOrgMember,
  requireScope('usage:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const credentialId = req.query.credentialId as string;
      const from = req.query.from ? new Date(req.query.from as string) : undefined;
      const to = req.query.to ? new Date(req.query.to as string) : undefined;

      const metrics = await db.getApiUsageMetrics(orgId, { credentialId, from, to });
      return sendSuccess(res, {
        ...metrics,
        avgLatencyMs: metrics.averageLatencyMs,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to retrieve API usage metrics.');
    }
  }
);

export default router;
