/**
 * @file apps/api/src/routes/v1/compliance.ts
 * Enterprise Cryptographic Trust, Compliance & Assurance REST API Endpoints (Phase 22)
 */

import { Router, Request, Response } from 'express';
import { complianceAssuranceService } from '../../lib/compliance-assurance-service';
import { requireAuth, requireOrgMember, requireScope } from '../../middleware/auth';
import { sendSuccess, sendCollection, sendError, sendCaughtError } from '../../middleware/response-formatter';
import { ComplianceFrameworkId, EvidenceType } from '@amaracus/crypto-core';

const router = Router();

// Perimeter security: All compliance endpoints require valid authentication and organization membership
router.use(requireAuth);
router.use(requireOrgMember);

/**
 * GET /api/v1/compliance/frameworks
 * Lists all registered compliance frameworks.
 */
router.get(
  '/frameworks',
  requireScope('compliance:read'),
  async (req: Request, res: Response) => {
    try {
      const frameworks = complianceAssuranceService.getFrameworks();
      return sendCollection(res, frameworks, { hasMore: false, total: frameworks.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'FRAMEWORKS_FETCH_FAILED', err.message);
    }
  }
);

/**
 * GET /api/v1/compliance/frameworks/:id
 * Retrieves details for a specific compliance framework.
 */
router.get(
  '/frameworks/:id',
  requireScope('compliance:read'),
  async (req: Request, res: Response) => {
    try {
      const frameworkId = req.params.id as ComplianceFrameworkId;
      const framework = complianceAssuranceService.getFramework(frameworkId);
      if (!framework) {
        return sendError(res, 404, 'FRAMEWORK_NOT_FOUND', `Framework "${frameworkId}" not found.`);
      }
      return sendSuccess(res, framework);
    } catch (err: any) {
      return sendCaughtError(res, err, 'FRAMEWORK_FETCH_FAILED', err.message);
    }
  }
);

/**
 * GET /api/v1/compliance/assessments
 * Retrieves cached compliance assessments for one or all frameworks.
 */
router.get(
  '/assessments',
  requireScope('compliance:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const frameworkId = req.query.frameworkId as ComplianceFrameworkId | undefined;
      const reports = await complianceAssuranceService.evaluateAssessments(orgId, frameworkId, false);
      return sendCollection(res, reports, { hasMore: false, total: reports.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'ASSESSMENTS_FETCH_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/compliance/assessments/evaluate
 * Triggers a fresh compliance evaluation against collected evidence.
 */
router.post(
  '/assessments/evaluate',
  requireScope('compliance:assess'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const frameworkId = req.body?.frameworkId as ComplianceFrameworkId | undefined;
      const forceRefresh = req.body?.forceRefresh === true;

      const reports = await complianceAssuranceService.evaluateAssessments(orgId, frameworkId, forceRefresh);
      return sendSuccess(res, frameworkId ? reports[0] : reports);
    } catch (err: any) {
      return sendCaughtError(res, err, 'ASSESSMENT_EVALUATION_FAILED', err.message);
    }
  }
);

/**
 * GET /api/v1/compliance/evidence
 * Lists sanitized, verifiable evidence artifacts with SHA-256 digests.
 */
router.get(
  '/evidence',
  requireScope('compliance:evidence'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const type = req.query.type as EvidenceType | undefined;
      const freshness = req.query.freshness as any;
      const source = req.query.source as string | undefined;

      const artifacts = await complianceAssuranceService.listEvidence(orgId, { type, freshness, source });
      return sendCollection(res, artifacts, { hasMore: false, total: artifacts.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'EVIDENCE_FETCH_FAILED', err.message);
    }
  }
);

/**
 * GET /api/v1/compliance/gaps
 * Lists identified technical control gaps with remediation guidance.
 */
router.get(
  '/gaps',
  requireScope('compliance:read'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const frameworkId = req.query.frameworkId as ComplianceFrameworkId | undefined;
      const controlId = req.query.controlId as string | undefined;
      const severity = req.query.severity as any;

      const gaps = await complianceAssuranceService.getGaps(orgId, { frameworkId, controlId, severity });
      return sendCollection(res, gaps, { hasMore: false, total: gaps.length });
    } catch (err: any) {
      return sendCaughtError(res, err, 'GAPS_FETCH_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/compliance/exceptions
 * Requests a controlled compliance exception with justification and expiration date.
 */
router.post(
  '/exceptions',
  requireScope('compliance:exceptions'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const actorId = req.apiKey?.id || (req as any).user?.id || 'anonymous';
      const { controlId, justification, compensatingControls, expiresAt } = req.body || {};

      if (!controlId || !justification || !compensatingControls || !expiresAt) {
        return sendError(
          res,
          400,
          'MISSING_EXCEPTION_FIELDS',
          'controlId, justification, compensatingControls, and expiresAt are required.'
        );
      }

      const exception = await complianceAssuranceService.requestException(
        orgId,
        { controlId, justification, compensatingControls, expiresAt },
        actorId
      );

      return sendSuccess(res, exception, 201);
    } catch (err: any) {
      const statusCode = err.message.includes('not exist') ? 404 : 400;
      return sendError(res, statusCode, 'EXCEPTION_REQUEST_FAILED', err.message);
    }
  }
);

/**
 * POST /api/v1/compliance/exceptions/:id/approve
 * Approves a pending compliance exception enforcing the Four-Eyes Principle.
 */
router.post(
  '/exceptions/:id/approve',
  requireScope('compliance:exceptions'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const exceptionId = req.params.id;
      const approverId =
        req.body?.approverId || req.apiKey?.id || (req as any).user?.id || 'anonymous';

      const approved = await complianceAssuranceService.approveException(
        orgId,
        exceptionId,
        approverId
      );

      return sendSuccess(res, approved);
    } catch (err: any) {
      const isFourEyes = err.message.includes('FOUR_EYES_VIOLATION');
      const isNotFound = err.message.includes('not found');
      const statusCode = isFourEyes ? 403 : isNotFound ? 404 : 400;
      return sendError(res, statusCode, 'EXCEPTION_APPROVAL_FAILED', err.message);
    }
  }
);

/**
 * GET /api/v1/compliance/reports/:format
 * Generates an audit-ready report in JSON or CSV format.
 */
router.get(
  '/reports/:format',
  requireScope('compliance:export'),
  async (req: Request, res: Response) => {
    try {
      const orgId = req.organizationId!;
      const format = req.params.format.toLowerCase() as 'json' | 'csv';
      const frameworkId = (req.query.frameworkId as ComplianceFrameworkId) || 'SOC_2_TYPE_II';

      if (format !== 'json' && format !== 'csv') {
        return sendError(res, 400, 'INVALID_REPORT_FORMAT', 'Supported formats are "json" and "csv".');
      }

      const { data, contentType } = await complianceAssuranceService.generateReport(
        orgId,
        frameworkId,
        format
      );

      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="amaracus-compliance-${frameworkId.toLowerCase()}-${Date.now()}.csv"`
        );
        return res.status(200).send(data);
      }

      return sendSuccess(res, data);
    } catch (err: any) {
      return sendCaughtError(res, err, 'REPORT_GENERATION_FAILED', err.message);
    }
  }
);

export default router;
