import { Router, Request, Response } from 'express';
import { migrationRunner } from '../../lib/migration-runner';
import { db } from '../../lib/data-store';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendCollection, sendError, sendCaughtError } from '../../middleware/response-formatter';
import { MigrationDependencyGraphBuilder } from '@amaracus/crypto-core';

const router = Router();

// All routes require authentication and organization membership
router.use(requireAuth);
router.use(requireOrgMember);

/**
 * GET & POST /api/v1/migrations/assess
 * Run live discovery assessment across organization assets and return explainable recommendations.
 */
router.all('/assess', requireScope('migrations:read'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const assessments = await migrationRunner.assess(orgId);
    return sendCollection(res, assessments, { hasMore: false, total: assessments.length });
  } catch (err: any) {
    return sendCaughtError(res, err, 'ASSESSMENT_FAILED', err.message || 'Failed to assess cryptographic inventory.');
  }
});

/**
 * POST /api/v1/migrations/plans
 * Create a new cryptographic migration plan in DRAFT status.
 */
router.post('/plans', requireScope('migrations:plan'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const userId = (req as any).user?.id || (req as any).apiKey?.id || 'system';
    const {
      name,
      description,
      migrationType,
      sourceResourceId,
      targetResourceId,
      sourceAlgorithm,
      targetAlgorithm,
      sourceProvider,
      targetProvider,
      projectId,
      environmentId,
    } = req.body;

    if (!name || typeof name !== 'string') {
      return sendError(res, 400, 'VALIDATION_FAILED', 'Plan name is required.');
    }
    if (!migrationType || typeof migrationType !== 'string') {
      return sendError(res, 400, 'VALIDATION_FAILED', 'Migration type is required.');
    }
    if (!sourceResourceId || !sourceAlgorithm || !targetAlgorithm) {
      return sendError(res, 400, 'VALIDATION_FAILED', 'sourceResourceId, sourceAlgorithm, and targetAlgorithm are required.');
    }

    const plan = await migrationRunner.createPlan({
      organizationId: orgId,
      projectId,
      environmentId,
      name: name.trim(),
      description: description?.trim(),
      migrationType: migrationType as any,
      sourceResourceId,
      targetResourceId,
      sourceAlgorithm,
      targetAlgorithm,
      sourceProvider,
      targetProvider,
      proposerId: userId,
    });

    return res.status(201).json({
      data: plan,
      requestId: (req as any).requestId,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'PLAN_CREATION_FAILED', err.message || 'Failed to create migration plan.');
  }
});

/**
 * GET /api/v1/migrations/plans
 * List all migration plans for the organization.
 */
router.get('/plans', requireScope('migrations:read'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const rawPlans = await db.listCryptoMigrationPlans(orgId);
    const plans = rawPlans.map((p) => {
      const meta = p.metadata || {};
      return {
        id: p.id,
        organizationId: p.organizationId,
        name: p.name,
        description: p.description,
        migrationType: p.migrationStrategy,
        status: p.status,
        sourceAlgorithm: p.currentAlgorithm,
        targetAlgorithm: p.targetAlgorithm,
        sourceResourceId: (p.affectedAssetIds && p.affectedAssetIds[0]) || p.id,
        targetResourceId: meta.targetResourceId || null,
        proposerId: p.owner,
        approverId: meta.approverId || null,
        approvedAt: meta.approvedAt || null,
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
      };
    });

    return sendCollection(res, plans, { hasMore: false, total: plans.length });
  } catch (err: any) {
    return sendCaughtError(res, err, 'LIST_PLANS_FAILED', err.message || 'Failed to list migration plans.');
  }
});

/**
 * GET /api/v1/migrations/plans/:id
 * Retrieve details for a specific migration plan, including dependency graph and simulation details.
 */
router.get('/plans/:id', requireScope('migrations:read'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const planId = req.params.id;
    const raw = await db.getCryptoMigrationPlan(orgId, planId);

    if (!raw) {
      return sendError(res, 404, 'RESOURCE_NOT_FOUND', `Migration plan '${planId}' not found.`);
    }

    const meta = raw.metadata || {};
    const depGraph = MigrationDependencyGraphBuilder.buildGraph({
      id: (raw.affectedAssetIds && raw.affectedAssetIds[0]) || raw.id,
      name: raw.name,
      assetType: 'KEY',
      algorithm: raw.currentAlgorithm,
      provider: meta.sourceProvider,
    });

    const plan = {
      id: raw.id,
      organizationId: raw.organizationId,
      name: raw.name,
      description: raw.description,
      migrationType: raw.migrationStrategy,
      status: raw.status,
      sourceAlgorithm: raw.currentAlgorithm,
      targetAlgorithm: raw.targetAlgorithm,
      sourceResourceId: (raw.affectedAssetIds && raw.affectedAssetIds[0]) || raw.id,
      targetResourceId: meta.targetResourceId || null,
      sourceProvider: meta.sourceProvider || null,
      targetProvider: meta.targetProvider || null,
      proposerId: raw.owner,
      approverId: meta.approverId || null,
      approvedAt: meta.approvedAt || null,
      dependencyGraph: depGraph,
      simulationReport: meta.simulationReport || null,
      verificationResult: meta.verificationResult || null,
      rollbackPlan: meta.rollbackPlan || null,
      errorMessage: meta.errorMessage || null,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
    };

    return sendSuccess(res, plan);
  } catch (err: any) {
    return sendCaughtError(res, err, 'GET_PLAN_FAILED', err.message || 'Failed to retrieve migration plan.');
  }
});

/**
 * POST /api/v1/migrations/plans/:id/simulate
 * Run non-destructive simulation on a migration plan.
 */
router.post('/plans/:id/simulate', requireScope('migrations:plan'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const planId = req.params.id;
    const report = await migrationRunner.simulatePlan(orgId, planId);
    return sendSuccess(res, report);
  } catch (err: any) {
    if (err.message?.includes('not found')) {
      return sendError(res, 404, 'RESOURCE_NOT_FOUND', err.message);
    }
    return sendCaughtError(res, err, 'SIMULATION_FAILED', err.message || 'Failed to simulate migration plan.');
  }
});

/**
 * POST /api/v1/migrations/plans/:id/approve
 * Approve a migration plan with backend separation of duties enforcement.
 */
router.post('/plans/:id/approve', requireScope('migrations:approve'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const planId = req.params.id;
    const approverId = (req as any).user?.id || (req as any).apiKey?.id || 'system';
    const approverRole = (req as any).orgRole || 'ADMIN';

    const plan = await migrationRunner.approvePlan(orgId, planId, approverId, approverRole);
    return sendSuccess(res, plan);
  } catch (err: any) {
    if (err.message?.includes('not found')) {
      return sendError(res, 404, 'RESOURCE_NOT_FOUND', err.message);
    }
    if (err.message?.includes('SEPARATION_OF_DUTIES_VIOLATION')) {
      return sendError(res, 403, 'SEPARATION_OF_DUTIES_VIOLATION', err.message);
    }
    return sendError(res, 400, 'APPROVAL_FAILED', err.message || 'Failed to approve migration plan.');
  }
});

/**
 * POST /api/v1/migrations/plans/:id/execute
 * Execute an approved migration plan.
 */
router.post('/plans/:id/execute', requireScope('migrations:execute'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const planId = req.params.id;
    const executorId = (req as any).user?.id || (req as any).apiKey?.id || 'system';

    const plan = await migrationRunner.executePlan(orgId, planId, executorId);
    return sendSuccess(res, plan);
  } catch (err: any) {
    if (err.message?.includes('not found')) {
      return sendError(res, 404, 'RESOURCE_NOT_FOUND', err.message);
    }
    return sendCaughtError(res, err, 'EXECUTION_FAILED', err.message || 'Failed to execute migration plan.');
  }
});

/**
 * POST /api/v1/migrations/plans/:id/rollback
 * Revert a reversible completed migration plan.
 */
router.post('/plans/:id/rollback', requireScope('migrations:execute'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const planId = req.params.id;
    const actorId = (req as any).user?.id || (req as any).apiKey?.id || 'system';

    const plan = await migrationRunner.rollbackPlan(orgId, planId, actorId);
    return sendSuccess(res, plan);
  } catch (err: any) {
    if (err.message?.includes('not found')) {
      return sendError(res, 404, 'RESOURCE_NOT_FOUND', err.message);
    }
    return sendError(res, 400, 'ROLLBACK_FAILED', err.message || 'Failed to rollback migration plan.');
  }
});

/**
 * POST /api/v1/migrations/re-encrypt
 * Controlled batch data re-encryption for Envelope v1 ciphertexts.
 */
router.post('/re-encrypt', requireScope('crypto:execute'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const { sourceKeyId, targetKeyId, envelopes } = req.body;

    if (!sourceKeyId || !targetKeyId) {
      return sendError(res, 400, 'VALIDATION_FAILED', 'sourceKeyId and targetKeyId are required.');
    }
    if (!envelopes || !Array.isArray(envelopes) || envelopes.length === 0) {
      return sendError(res, 400, 'VALIDATION_FAILED', 'envelopes array is required and must not be empty.');
    }

    const result = await migrationRunner.reEncryptBatch({
      organizationId: orgId,
      sourceKeyId,
      targetKeyId,
      envelopes,
    });

    return sendSuccess(res, result);
  } catch (err: any) {
    return sendCaughtError(res, err, 'RE_ENCRYPTION_FAILED', err.message || 'Data re-encryption failed.');
  }
});

export default router;
