/**
 * AMARACUS Cryptographic Infrastructure — Policy Management API
 *
 * REST control plane for policy governance, versioning, assignments,
 * dry-run evaluation, simulation, and operational telemetry.
 */

import { Router, Request, Response } from 'express';
import { requireAuth, requireOrgMember, requireOrgPermission } from '../../middleware/auth';
import { payloadSizeLimiter, createRateLimiter } from '../../middleware/rate-limiter';
import { db } from '../../lib/data-store';
import { policyService } from '../../lib/policy-service';
import { policyObservability } from '../../lib/policy-observability';
import { CryptographicAiBoundary } from '@amaracus/crypto-core';
import { sendCaughtError } from '../../middleware/response-formatter';

const router = Router();

const policyMiddleware = [
  requireAuth,
  requireOrgMember,
  payloadSizeLimiter(1048576), // 1MB payload limit
  createRateLimiter({ limit: 300, windowMs: 60000 }),
];

function formatPolicy(p: any) {
  if (!p) return p;
  return {
    ...p,
    version: p.currentVersion ?? p.version ?? 1,
    scope: p.scope ?? 'ORGANIZATION',
    status: p.isActive !== false ? 'ACTIVE' : 'ARCHIVED',
  };
}

/**
 * GET /v1/policies/metrics
 * Policy observability, decision histograms, violation counts, and alerts.
 */
router.get('/metrics', ...policyMiddleware, requireOrgPermission('policy:read'), async (req: Request, res: Response) => {
  try {
    const metrics = policyObservability.getSnapshot();
    const mapped = {
      ...metrics,
      evaluationCount: metrics.evaluationsTotal,
      decisionDistribution: metrics.decisions,
      avgLatencyMs: metrics.latencies?.avgMs ?? 0,
      p95LatencyMs: metrics.latencies?.p95Ms ?? 0,
      cacheHitRatio: (metrics.cache?.hitRatePercent ?? 100) / 100,
      anomalyAlerts: metrics.alerts ?? [],
    };
    return res.status(200).json({
      data: mapped,
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * GET /v1/policies
 * List all cryptographic policies belonging to the authenticated organization.
 */
router.get('/', ...policyMiddleware, requireOrgPermission('policy:read'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const policies = await db.listPolicies(orgId);

    return res.status(200).json({
      data: policies.map(formatPolicy),
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * POST /v1/policies
 * Create a new cryptographic policy document.
 */
router.post('/', ...policyMiddleware, requireOrgPermission('policy:create'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const { name, description, rules, enforcementMode = 'ENFORCE', metadata } = req.body;

    if (!name || typeof name !== 'string') {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Field "name" is required and must be a string.' },
      });
    }

    if (!rules || !Array.isArray(rules)) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Field "rules" is required and must be an array of policy rules.' },
      });
    }

    const created = await db.createPolicy({
      organizationId: orgId,
      name,
      description,
      rules,
      enforcementMode,
      metadata,
      actorId: req.apiKey?.id || req.user?.id || 'admin',
    });

    policyService.invalidateTenantCache(orgId);

    await db.createAuditEvent({
      organizationId: orgId,
      userId: req.apiKey?.id || req.user?.id || null,
      action: 'POLICY_CREATED',
      resourceType: 'CryptographicPolicy',
      resourceId: created.id,
      metadata: { name: created.name, version: created.currentVersion },
    });

    return res.status(201).json({
      data: formatPolicy(created),
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * GET /v1/policies/:id
 * Retrieve a specific policy by ID with version history.
 */
router.get('/:id', ...policyMiddleware, requireOrgPermission('policy:read'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const { id } = req.params;

    const policy = await db.getPolicy(id, orgId);
    if (!policy) {
      return res.status(404).json({
        error: { code: 'POLICY_NOT_FOUND', message: `Policy '${id}' not found in organization.` },
      });
    }

    const versions = await db.listPolicyVersions(id);

    return res.status(200).json({
      data: {
        ...formatPolicy(policy),
        versions: versions.map(formatPolicy),
      },
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * PATCH /v1/policies/:id
 * Update policy rules, name, or description. Automatically bumps version and stores version record.
 */
router.patch('/:id', ...policyMiddleware, requireOrgPermission('policy:update'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const { id } = req.params;
    const { name, description, rules, enforcementMode, isActive, changeSummary } = req.body;

    const existing = await db.getPolicy(id, orgId);
    if (!existing) {
      return res.status(404).json({
        error: { code: 'POLICY_NOT_FOUND', message: `Policy '${id}' not found in organization.` },
      });
    }

    const updated = await db.updatePolicy(
      id,
      orgId,
      {
        name: name !== undefined ? name : undefined,
        description: description !== undefined ? description : undefined,
        rules: rules !== undefined ? rules : undefined,
        enforcementMode: enforcementMode !== undefined ? enforcementMode : undefined,
        isActive: isActive !== undefined ? isActive : undefined,
      },
      req.apiKey?.id || req.user?.id || 'admin',
      changeSummary
    );

    policyService.invalidateTenantCache(orgId);

    await db.createAuditEvent({
      organizationId: orgId,
      userId: req.apiKey?.id || req.user?.id || null,
      action: 'POLICY_UPDATED',
      resourceType: 'CryptographicPolicy',
      resourceId: updated.id,
      metadata: { name: updated.name, version: updated.currentVersion, changeSummary },
    });

    return res.status(200).json({
      data: formatPolicy(updated),
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * DELETE /v1/policies/:id
 * Delete a policy document.
 */
router.delete('/:id', ...policyMiddleware, requireOrgPermission('policy:delete'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const { id } = req.params;

    const existing = await db.getPolicy(id, orgId);
    if (!existing) {
      return res.status(404).json({
        error: { code: 'POLICY_NOT_FOUND', message: `Policy '${id}' not found in organization.` },
      });
    }

    await db.deletePolicy(id, orgId);
    policyService.invalidateTenantCache(orgId);

    await db.createAuditEvent({
      organizationId: orgId,
      userId: req.apiKey?.id || req.user?.id || null,
      action: 'POLICY_DELETED',
      resourceType: 'CryptographicPolicy',
      resourceId: id,
    });

    return res.status(200).json({
      data: { id, deleted: true, success: true },
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * POST /v1/policies/:id/simulate
 * Simulates a policy against tenant keys and sample operations without executing cryptography.
 */
router.post('/:id/simulate', ...policyMiddleware, requireOrgPermission('policy:simulate'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const { id } = req.params;

    const policy = await db.getPolicy(id, orgId);
    if (!policy) {
      return res.status(404).json({
        error: { code: 'POLICY_NOT_FOUND', message: `Policy '${id}' not found in organization.` },
      });
    }

    const impact = await policyService.simulatePolicy(orgId, {
      name: policy.name,
      rules: policy.rules,
    });

    return res.status(200).json({
      data: impact,
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

/**
 * POST /v1/policies/dry-run
 * Dry-run evaluate an operation against active or proposed policy without executing.
 */
router.post('/dry-run', ...policyMiddleware, requireOrgPermission('policy:simulate'), async (req: Request, res: Response) => {
  try {
    const orgId = req.organizationId!;
    const {
      operationType,
      algorithm,
      keyId,
      policy,
      proposedPolicy,
      dataClassification,
    } = req.body;

    if (!operationType) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: 'Field "operationType" is required for dry-run evaluation.' },
      });
    }

    let keyReference: any = null;
    let keyAgeDays: number | undefined = undefined;

    if (keyId) {
      const key = await db.findKeyById(keyId, orgId);
      if (key) {
        keyReference = {
          id: key.id,
          name: key.name,
          organizationId: key.organizationId,
          algorithm: key.algorithm,
          purpose: key.purpose,
          provider: key.provider,
          providerKeyId: key.id,
          currentVersion: key.currentVersion,
          status: key.status,
          isHsmBacked: key.provider === 'AZURE_MANAGED_HSM',
          isCustomerManaged: key.provider?.startsWith('CUSTOMER_') || false,
        };
        keyAgeDays = key.createdAt
          ? Math.floor((Date.now() - new Date(key.createdAt).getTime()) / (1000 * 60 * 60 * 24))
          : 0;
      }
    }

    const decision = await policyService.evaluate(
      {
        organizationId: orgId,
        projectId: req.projectId || (req.headers['x-project-id'] as string) || req.body?.projectId,
        environmentId: req.environmentId || (req.headers['x-environment-id'] as string) || req.body?.environmentId,
        operationType,
        algorithm: algorithm || keyReference?.algorithm,
        keyId,
        keyReference,
        keyAgeDays,
        complianceProfile: policy,
        dataClassification,
      },
      policy
    );

    const explanation = CryptographicAiBoundary.explainDecision(decision);

    return res.status(200).json({
      data: {
        decision: decision.decision,
        allowed: decision.allowed,
        policyVersion: decision.policyVersion,
        reasons: decision.reasons,
        requirements: decision.requirements,
        warnings: decision.warnings,
        recommendations: decision.recommendations,
        trace: decision.trace,
        explanation,
      },
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`,
    });
  } catch (err: any) {
    return sendCaughtError(res, err, 'INTERNAL_ERROR', err.message);
  }
});

export default router;
