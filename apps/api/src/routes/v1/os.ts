/**
 * @file apps/api/src/routes/v1/os.ts
 * Enterprise Cryptographic Operating System REST API Endpoints (Phase 20)
 */

import { Router, Request, Response } from 'express';
import { cryptoOsOrchestrator } from '../../lib/crypto-os-orchestrator';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendCollection, sendError, sendCaughtError } from '../../middleware/response-formatter';
import { CryptoResourceType } from '@amaracus/crypto-core';

const router = Router();

// Perimeter security: All OS endpoints require valid session/API-key and org membership
router.use(requireAuth);
router.use(requireOrgMember);

/**
 * GET /api/v1/os/inventory
 * Retrieves unified cryptographic resource inventory.
 */
router.get('/inventory', requireScope('os:read'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const type = req.query.type as CryptoResourceType | undefined;
    const verifiedOnly = req.query.verifiedOnly === 'true';

    const resources = await cryptoOsOrchestrator.getUnifiedInventory(orgId, {
      type,
      verifiedOnly,
    });

    return sendCollection(res, resources, { hasMore: false, total: resources.length });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INVENTORY_FETCH_FAILED', err.message);
  }
});

/**
 * POST /api/v1/os/resources
 * Registers a new resource in the unified inventory.
 */
router.post('/resources', requireScope('os:write'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const { id, type, name, status, algorithm, provider, metadata, verified, verificationSource } = req.body;

    if (!id || !type || !name) {
      return sendError(res, 400, 'INVALID_INPUT', 'id, type, and name are required.');
    }

    const now = new Date().toISOString();
    const resource = {
      id,
      type,
      name,
      orgId,
      status: status || 'ACTIVE',
      verified: verified !== false,
      verificationSource: verificationSource || 'DIRECT_STORAGE',
      algorithm,
      provider,
      metadata: metadata || {},
      createdAt: now,
      updatedAt: now,
    };

    cryptoOsOrchestrator.registerResource(orgId, resource);
    return sendSuccess(res, resource, 201);
  } catch (err: any) {
    return sendCaughtError(res, err, 'RESOURCE_REGISTRATION_FAILED', err.message);
  }
});

/**
 * GET /api/v1/os/posture
 * Retrieves consolidated cryptographic security posture, health score, and deduplicated findings.
 */
router.get('/posture', requireScope('os:posture'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const posture = await cryptoOsOrchestrator.getUnifiedPosture(orgId);
    return sendSuccess(res, posture);
  } catch (err: any) {
    return sendCaughtError(res, err, 'POSTURE_EVALUATION_FAILED', err.message);
  }
});

/**
 * GET /api/v1/os/templates
 * Lists available enterprise workflow templates.
 */
router.get('/templates', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const templates = cryptoOsOrchestrator.listTemplates();
    return sendCollection(res, templates, { hasMore: false, total: templates.length });
  } catch (err: any) {
    return sendCaughtError(res, err, 'TEMPLATES_FETCH_FAILED', err.message);
  }
});

/**
 * POST /api/v1/os/templates/:templateId/instantiate
 * Instantiates a workflow from an enterprise template.
 */
router.post('/templates/:templateId/instantiate', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const userId = (req as any).user?.id || (req as any).apiKey?.id || 'system_proposer';
    const { templateId } = req.params;
    const { name, projectId, envId, customParameters } = req.body;

    const workflow = cryptoOsOrchestrator.createWorkflowFromTemplate(orgId, templateId, {
      proposerId: userId,
      name,
      projectId,
      envId,
      customParameters,
    });

    return sendSuccess(res, workflow, 201);
  } catch (err: any) {
    return sendError(res, 400, 'TEMPLATE_INSTANTIATION_FAILED', err.message);
  }
});

/**
 * GET /api/v1/os/workflows
 * Lists workflows in the organization.
 */
router.get('/workflows', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const workflows = cryptoOsOrchestrator.listWorkflows(orgId);
    return sendCollection(res, workflows, { hasMore: false, total: workflows.length });
  } catch (err: any) {
    return sendCaughtError(res, err, 'WORKFLOWS_FETCH_FAILED', err.message);
  }
});

/**
 * POST /api/v1/os/workflows
 * Creates a custom workflow instance.
 */
router.post('/workflows', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const userId = (req as any).user?.id || (req as any).apiKey?.id || 'system_proposer';
    const { name, description, steps, requiresDualApproval, projectId, envId } = req.body;

    if (!name || !steps || !Array.isArray(steps) || steps.length === 0) {
      return sendError(res, 400, 'INVALID_INPUT', 'name and an array of steps are required.');
    }

    const workflow = cryptoOsOrchestrator.createCustomWorkflow(orgId, {
      name,
      description,
      proposerId: userId,
      requiresDualApproval,
      projectId,
      envId,
      steps,
    });

    return sendSuccess(res, workflow, 201);
  } catch (err: any) {
    return sendError(res, 400, 'WORKFLOW_CREATION_FAILED', err.message);
  }
});

/**
 * GET /api/v1/os/workflows/:id
 * Retrieves details for a specific workflow.
 */
router.get('/workflows/:id', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const workflow = cryptoOsOrchestrator.getWorkflow(orgId, req.params.id);
    if (!workflow) {
      return sendError(res, 404, 'NOT_FOUND', `Workflow '${req.params.id}' not found`);
    }
    return sendSuccess(res, workflow);
  } catch (err: any) {
    return sendCaughtError(res, err, 'WORKFLOW_FETCH_FAILED', err.message);
  }
});

/**
 * POST /api/v1/os/workflows/:id/approve
 * Approves a workflow under server-side separation of duties (proposer != approver).
 */
router.post('/workflows/:id/approve', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const approverId = req.body.approverId || (req as any).user?.id || (req as any).apiKey?.id;

    if (!approverId) {
      return sendError(res, 400, 'INVALID_INPUT', 'approverId is required.');
    }

    const workflow = cryptoOsOrchestrator.approveWorkflow(orgId, req.params.id, approverId);
    return sendSuccess(res, workflow);
  } catch (err: any) {
    if (err.code === 'SEPARATION_OF_DUTIES_VIOLATION') {
      return sendError(res, 403, 'SEPARATION_OF_DUTIES_VIOLATION', err.message);
    }
    return sendError(res, 400, 'WORKFLOW_APPROVAL_FAILED', err.message);
  }
});

/**
 * POST /api/v1/os/workflows/:id/execute
 * Executes an approved workflow step by step.
 */
router.post('/workflows/:id/execute', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const executedBy = (req as any).user?.id || (req as any).apiKey?.id || 'system_executor';

    const workflow = await cryptoOsOrchestrator.executeWorkflow(orgId, req.params.id, executedBy);
    return sendSuccess(res, workflow);
  } catch (err: any) {
    return sendError(res, 400, 'WORKFLOW_EXECUTION_FAILED', err.message);
  }
});

/**
 * POST /api/v1/os/workflows/:id/cancel
 * Cancels a workflow with an explicit reason.
 */
router.post('/workflows/:id/cancel', requireScope('os:workflows'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const reason = req.body.reason || 'User cancelled workflow';

    const workflow = cryptoOsOrchestrator.cancelWorkflow(orgId, req.params.id, reason);
    return sendSuccess(res, workflow);
  } catch (err: any) {
    return sendError(res, 400, 'WORKFLOW_CANCELLATION_FAILED', err.message);
  }
});

/**
 * POST /api/v1/os/automations/evaluate
 * Evaluates active automation rules and returns proactive alerts and recommendations.
 */
router.post('/automations/evaluate', requireScope('os:automation'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const result = await cryptoOsOrchestrator.evaluateAutomations(orgId);
    return sendSuccess(res, result);
  } catch (err: any) {
    return sendCaughtError(res, err, 'AUTOMATION_EVALUATION_FAILED', err.message);
  }
});

export default router;
