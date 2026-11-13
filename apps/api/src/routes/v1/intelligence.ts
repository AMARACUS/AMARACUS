/**
 * @file apps/api/src/routes/v1/intelligence.ts
 * Enterprise Cryptographic Intelligence & Autonomous Optimization REST API Endpoints (Phase 21)
 */

import { Router, Request, Response } from 'express';
import { cryptoIntelligenceService } from '../../lib/crypto-intelligence-service';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendCollection, sendError, sendCaughtError } from '../../middleware/response-formatter';
import { RecommendationCategory, RecommendationStatus, SeverityLevel } from '@amaracus/crypto-core';

const router = Router();

// Perimeter security: All intelligence endpoints require authentication and org membership
router.use(requireAuth);
router.use(requireOrgMember);

/**
 * GET /api/v1/intelligence/recommendations
 * Lists prioritized, evidence-backed optimization recommendations for the organization.
 */
router.get(
  '/recommendations',
  requireScope('intelligence:recommendations'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const category = req.query.category as RecommendationCategory | undefined;
      const status = req.query.status as RecommendationStatus | undefined;
      const severity = req.query.severity as SeverityLevel | undefined;
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
      const offset = req.query.offset ? parseInt(req.query.offset as string, 10) : 0;

      const { recommendations, total } = await cryptoIntelligenceService.listRecommendations(orgId, {
        category,
        status,
        severity,
        limit,
        offset,
      });

      return sendCollection(res, recommendations, { hasMore: offset + recommendations.length < total, total });
    } catch (err: any) {
      return sendCaughtError(res, err, 'RECOMMENDATIONS_FETCH_FAILED', err.message);
    }
  }
);

/**
 * GET /api/v1/intelligence/recommendations/:id
 * Retrieves a single recommendation by ID.
 */
router.get(
  '/recommendations/:id',
  requireScope('intelligence:recommendations'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const id = req.params.id;

      const recommendation = await cryptoIntelligenceService.getRecommendation(orgId, id);
      if (!recommendation) {
        return sendError(res, 404, 'RECOMMENDATION_NOT_FOUND', `Recommendation "${id}" not found.`);
      }

      return sendSuccess(res, recommendation);
    } catch (err: any) {
      return sendCaughtError(res, err, 'RECOMMENDATION_FETCH_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/intelligence/recommendations/:id/accept
 * Accepts a recommendation and runs an automatic dry-run impact simulation.
 */
router.post(
  '/recommendations/:id/accept',
  requireScope('intelligence:optimize'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const id = req.params.id;
      const actorId = req.apiKey?.id || (req as any).user?.id || 'anonymous';
      const { reason } = req.body || {};

      const updated = await cryptoIntelligenceService.acceptRecommendation(orgId, id, { reason }, actorId);
      return sendSuccess(res, updated);
    } catch (err: any) {
      const statusCode = err.message.includes('not found') ? 404 : 500;
      return sendError(res, statusCode, 'RECOMMENDATION_ACCEPT_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/intelligence/recommendations/:id/reject
 * Rejects a recommendation with user feedback.
 */
router.post(
  '/recommendations/:id/reject',
  requireScope('intelligence:optimize'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const id = req.params.id;
      const actorId = req.apiKey?.id || (req as any).user?.id || 'anonymous';
      const { reason } = req.body || {};

      const updated = await cryptoIntelligenceService.rejectRecommendation(orgId, id, { reason }, actorId);
      return sendSuccess(res, updated);
    } catch (err: any) {
      const statusCode = err.message.includes('not found') ? 404 : 500;
      return sendError(res, statusCode, 'RECOMMENDATION_REJECT_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/intelligence/recommendations/:id/dismiss
 * Dismisses a recommendation with explanation.
 */
router.post(
  '/recommendations/:id/dismiss',
  requireScope('intelligence:optimize'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const id = req.params.id;
      const actorId = req.apiKey?.id || (req as any).user?.id || 'anonymous';
      const { reason } = req.body || {};

      const updated = await cryptoIntelligenceService.dismissRecommendation(orgId, id, { reason }, actorId);
      return sendSuccess(res, updated);
    } catch (err: any) {
      const statusCode = err.message.includes('not found') ? 404 : 500;
      return sendError(res, statusCode, 'RECOMMENDATION_DISMISS_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/intelligence/recommendations/:id/dry-run
 * Conducts a non-destructive dry-run impact evaluation of the recommendation.
 */
router.post(
  '/recommendations/:id/dry-run',
  requireScope('intelligence:recommendations'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const id = req.params.id;

      const dryRun = await cryptoIntelligenceService.dryRunRecommendation(orgId, id);
      return sendSuccess(res, dryRun);
    } catch (err: any) {
      const statusCode = err.message.includes('not found') ? 404 : 500;
      return sendError(res, statusCode, 'DRY_RUN_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/intelligence/recommendations/:id/execute
 * Executes an accepted recommendation with Four-Eyes principle validation.
 */
router.post(
  '/recommendations/:id/execute',
  requireScope('intelligence:remediate'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const id = req.params.id;
      const actorId = req.apiKey?.id || (req as any).user?.id || 'anonymous';

      const executed = await cryptoIntelligenceService.executeRecommendation(orgId, id, actorId);
      return sendSuccess(res, executed);
    } catch (err: any) {
      const statusCode = err.message.includes('Four-eyes')
        ? 403
        : err.message.includes('not found')
        ? 404
        : 400;
      return sendError(res, statusCode, 'RECOMMENDATION_EXECUTION_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/intelligence/analyze
 * Triggers a fresh live evidence analysis across the organization's inventory and telemetry.
 */
router.post(
  '/analyze',
  requireScope('intelligence:analyze'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const { targetResourceIds, categories } = req.body || {};

      const result = await cryptoIntelligenceService.runAnalysis(orgId, { targetResourceIds, categories });
      return sendSuccess(res, result);
    } catch (err: any) {
      return sendCaughtError(res, err, 'ANALYSIS_EXECUTION_FAILED', err.message);
    }
  }
);

export default router;
