import { Router, Request, Response } from 'express';
import { db } from '../../lib/data-store';
import { asyncJobEngine, AsyncJobType } from '../../lib/async-job-engine';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendCollection, sendError, sendCaughtError } from '../../middleware/response-formatter';

const router = Router();

// GET /api/v1/jobs - List background jobs
router.get(
  '/',
  requireAuth,
  requireOrgMember,
  requireScope('jobs:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      const jobs = await db.getAsyncJobsByOrg(orgId, limit);

      return sendCollection(res, jobs, { hasMore: false, total: jobs.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to list asynchronous jobs.');
    }
  }
);

// POST /api/v1/jobs - Submit an asynchronous cryptographic job
router.post(
  '/',
  requireAuth,
  requireOrgMember,
  requireScope('jobs:write'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const { type, input, payload } = req.body;

      if (!type || !['ZK_PROVE', 'FHE_EVALUATE', 'DISCOVERY_SCAN'].includes(type)) {
        return sendError(
          res,
          400,
          'VALIDATION_FAILED',
          "Job type must be one of: 'ZK_PROVE', 'FHE_EVALUATE', 'DISCOVERY_SCAN' (MPC_COMPUTE is disabled)."
        );
      }

      const job = await asyncJobEngine.submitJob(orgId, type as AsyncJobType, input || payload || {}, {
        projectId: req.projectId,
        environmentId: req.environmentId,
      });

      return res.status(202).json({
        data: {
          id: job.id,
          jobId: job.id,
          type: job.type,
          status: job.status,
          progress: job.progress,
          createdAt: job.createdAt,
        },
        requestId: (req as any).requestId,
      });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to submit asynchronous job.');
    }
  }
);

// GET /api/v1/jobs/:id - Inspect job status & results
router.get(
  '/:id',
  requireAuth,
  requireOrgMember,
  requireScope('jobs:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const job = await db.getAsyncJobById(req.params.id);

      if (!job || job.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Job not found.');
      }

      return sendSuccess(res, job);
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to retrieve job status.');
    }
  }
);

// POST /api/v1/jobs/:id/cancel - Cancel a job
router.post(
  '/:id/cancel',
  requireAuth,
  requireOrgMember,
  requireScope('jobs:write'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const job = await db.getAsyncJobById(req.params.id);

      if (!job || job.organizationId !== orgId) {
        return sendError(res, 404, 'RESOURCE_NOT_FOUND', 'Job not found.');
      }

      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(job.status)) {
        return sendError(res, 400, 'INVALID_STATE', `Cannot cancel job in state '${job.status}'.`);
      }

      const updated = await db.updateAsyncJob(job.id, { status: 'CANCELLED' });
      return sendSuccess(res, { success: true, job: updated });
    } catch (err: any) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Failed to cancel job.');
    }
  }
);

export default router;
