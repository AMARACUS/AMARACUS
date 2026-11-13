import { Router, Request, Response, NextFunction } from 'express';
import { db } from '../lib/data-store';
import { requireAuth, requireOrgMember } from '../middleware/auth';
import {
  CryptoScanner,
  CryptoRelationshipGraph,
  PolicyEvaluator,
  CryptoMigrationEngine,
  CBOMGenerator,
  SnapshotManager,
  CryptoAssetItem,
  CryptoRelationshipItem,
  CryptoFindingItem,
} from '@amaracus/crypto-core';

const router = Router({ mergeParams: true });

// All routes require authentication and membership in the target organization
router.use(requireAuth);
router.use(requireOrgMember);

/**
 * POST /scan
 * Trigger an end-to-end cryptographic discovery scan across Keys, Certificates,
 * runtime API logs, and optional source-code files.
 */
router.post('/scan', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const userId = (req as any).user?.id || 'system';
    const { sourceFiles = [], policyName = 'DEFAULT_SECURE' } = req.body;

    // Audit event: Scan started
    await db.createAuditEvent({
      organizationId: orgId,
      userId,
      action: 'CRYPTO_SCAN_STARTED',
      resourceType: 'CRYPTO_INTELLIGENCE',
      resourceId: orgId,
      metadata: { initiatedBy: userId, policyName },
    });

    // Fetch live inventory data across Phase 5 and Phase 7 systems
    const keys = await db.listKeys({ organizationId: orgId });
    const customerKeys = await db.listCustomerRegisteredKeys({ organizationId: orgId });
    const certificateAuthorities = await db.listCertificateAuthorities({ organizationId: orgId });
    const certificates = await db.listCertificates({ organizationId: orgId });
    const auditEvents = await db.getAuditEventsByOrg(orgId, 200);

    // 1. Run multi-source scanner
    const scanResult = CryptoScanner.scanAll({
      organizationId: orgId,
      keys,
      customerKeys,
      certificateAuthorities,
      certificates,
      auditEvents,
      sourceFiles,
    });

    // 2. Persist discovered assets
    const persistedAssets: CryptoAssetItem[] = [];
    for (const asset of scanResult.assets) {
      const saved = await db.upsertCryptoAsset({
        id: asset.id,
        organizationId: orgId,
        projectId: asset.projectId,
        environmentId: asset.environmentId,
        assetType: asset.assetType,
        name: asset.name,
        source: asset.source,
        confidence: asset.confidence,
        algorithm: asset.algorithm,
        provider: asset.provider,
        status: asset.status,
        quantumStatus: asset.quantumStatus,
        fingerprint: asset.fingerprint,
        firstSeenAt: asset.firstSeenAt,
        lastSeenAt: asset.lastSeenAt,
        metadata: asset.metadata,
        createdAt: asset.createdAt,
        updatedAt: asset.updatedAt,
      });
      persistedAssets.push(saved as unknown as CryptoAssetItem);
    }

    // 3. Infer and persist explicit relationships
    const inferredRels = CryptoRelationshipGraph.inferRelationships(persistedAssets, orgId);
    await db.deleteCryptoRelationshipsForOrg(orgId);
    const persistedRels: CryptoRelationshipItem[] = [];
    for (const r of inferredRels) {
      const savedRel = await db.createCryptoRelationship({
        id: r.id,
        organizationId: orgId,
        sourceAssetId: r.sourceAssetId,
        targetAssetId: r.targetAssetId,
        relationshipType: r.relationshipType,
        confidence: r.confidence,
        metadata: r.metadata,
        createdAt: r.createdAt,
      });
      persistedRels.push(savedRel as unknown as CryptoRelationshipItem);
    }

    // 4. Policy evaluation & finding generation
    const findings = PolicyEvaluator.evaluateAssets(persistedAssets, policyName);
    const persistedFindings: CryptoFindingItem[] = [];
    for (const f of findings) {
      const savedFinding = await db.upsertCryptoFinding({
        id: f.id,
        organizationId: orgId,
        projectId: f.projectId,
        environmentId: f.environmentId,
        affectedAssetId: f.affectedAssetId,
        severity: f.severity,
        category: f.category,
        title: f.title,
        description: f.description,
        evidence: f.evidence,
        policySource: f.policySource,
        firstDetectedAt: f.firstDetectedAt,
        lastDetectedAt: f.lastDetectedAt,
        status: f.status,
        remediationGuidance: f.remediationGuidance,
        resolvedBy: f.resolvedBy,
        resolvedAt: f.resolvedAt,
        resolutionComment: f.resolutionComment,
        createdAt: f.createdAt,
        updatedAt: f.updatedAt,
      });
      persistedFindings.push(savedFinding as unknown as CryptoFindingItem);
    }

    // 5. Compute snapshot & drift
    const previousSnapshot = await db.getLatestCryptoSnapshot(orgId);
    const snapshotItem = SnapshotManager.createSnapshot({
      organizationId: orgId,
      assets: persistedAssets,
      findings: persistedFindings,
      previousSnapshot: previousSnapshot as any,
    });

    const savedSnapshot = await db.createCryptoSnapshot({
      id: snapshotItem.id,
      organizationId: orgId,
      snapshotDate: snapshotItem.snapshotDate,
      totalAssets: snapshotItem.totalAssets,
      assetsByType: snapshotItem.assetsByType,
      findingsBySeverity: snapshotItem.findingsBySeverity,
      quantumStatusSummary: snapshotItem.quantumStatusSummary,
      assetFingerprints: snapshotItem.assetFingerprints,
      drift: snapshotItem.drift,
      metadata: snapshotItem.metadata,
      createdAt: snapshotItem.createdAt,
    });

    // Audit event: Scan completed
    await db.createAuditEvent({
      organizationId: orgId,
      userId,
      action: 'CRYPTO_SCAN_COMPLETED',
      resourceType: 'CRYPTO_INTELLIGENCE',
      resourceId: savedSnapshot.id,
      metadata: {
        totalAssets: persistedAssets.length,
        totalFindings: persistedFindings.length,
        drift: snapshotItem.drift,
      },
    });

    return res.status(200).json({
      success: true,
      message: 'Cryptographic discovery scan completed successfully.',
      scan: {
        snapshotId: savedSnapshot.id,
        totalAssetsDiscovered: persistedAssets.length,
        relationshipsIdentified: persistedRels.length,
        findingsGenerated: persistedFindings.length,
        sourceUsagesDetected: scanResult.sourceUsages.length,
        quantumStatusSummary: snapshotItem.quantumStatusSummary,
        drift: snapshotItem.drift,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /inventory
 * Summary metrics and telemetry for the organization.
 */
router.get('/inventory', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const assets = await db.listCryptoAssets(orgId);
    const findings = await db.listCryptoFindings(orgId);
    const latestSnapshot = await db.getLatestCryptoSnapshot(orgId);

    const quantumStatusSummary = {
      QUANTUM_VULNERABLE: 0,
      PQC: 0,
      HYBRID: 0,
      CLASSICAL: 0,
      UNKNOWN: 0,
    };
    const assetsByType: Record<string, number> = {};

    for (const a of assets) {
      if (a.quantumStatus in quantumStatusSummary) {
        (quantumStatusSummary as any)[a.quantumStatus]++;
      } else {
        quantumStatusSummary.UNKNOWN++;
      }
      assetsByType[a.assetType] = (assetsByType[a.assetType] || 0) + 1;
    }

    const findingsBySeverity = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const f of findings) {
      if (f.status === 'OPEN' || f.status === 'ACKNOWLEDGED' || f.status === 'IN_PROGRESS') {
        if (f.severity in findingsBySeverity) {
          (findingsBySeverity as any)[f.severity]++;
        }
      }
    }

    return res.status(200).json({
      success: true,
      data: {
        totalAssets: assets.length,
        assetsByType,
        openFindingsCount: findings.filter((f) => f.status === 'OPEN').length,
        totalFindingsCount: findings.length,
        findingsBySeverity,
        quantumStatusSummary,
        latestScanDate: latestSnapshot?.snapshotDate || null,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /assets
 * List discovered cryptographic assets with filtering.
 */
router.get('/assets', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const { assetType, status, algorithm, quantumStatus } = req.query;

    const assets = await db.listCryptoAssets(orgId, {
      assetType: assetType as string,
      status: status as string,
      algorithm: algorithm as string,
      quantumStatus: quantumStatus as string,
    });

    return res.status(200).json({
      success: true,
      data: assets,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /assets/:id
 * Retrieve a specific cryptographic asset.
 */
router.get('/assets/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const assetId = req.params.id;

    const asset = await db.getCryptoAsset(orgId, assetId);
    if (!asset) {
      return res.status(404).json({
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: `Crypto asset '${assetId}' not found.`,
        },
      });
    }

    return res.status(200).json({
      success: true,
      data: asset,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /relationships
 * List all dependency and usage edges for the organization.
 */
router.get('/relationships', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const rels = await db.listCryptoRelationships(orgId);

    return res.status(200).json({
      success: true,
      data: rels,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /impact/:assetId
 * Traverse relationship graph to calculate recursive downstream impact.
 */
router.get('/impact/:assetId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const assetId = req.params.assetId;

    const assets = await db.listCryptoAssets(orgId);
    const rels = await db.listCryptoRelationships(orgId);

    const graph = new CryptoRelationshipGraph(assets as any, rels as any);
    const impact = graph.getDownstreamImpact(assetId);

    return res.status(200).json({
      success: true,
      data: impact,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /findings
 * List security findings.
 */
router.get('/findings', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const { severity, status, category } = req.query;

    const findings = await db.listCryptoFindings(orgId, {
      severity: severity as string,
      status: status as string,
      category: category as string,
    });

    return res.status(200).json({
      success: true,
      data: findings,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /findings/:id
 * Update finding status (e.g. mark FALSE_POSITIVE, RESOLVED, ACKNOWLEDGED).
 */
router.patch('/findings/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const findingId = req.params.id;
    const userId = (req as any).user?.id || 'system';
    const { status, resolutionComment } = req.body;

    const existing = await db.getCryptoFinding(orgId, findingId);
    if (!existing) {
      return res.status(404).json({
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: `Finding '${findingId}' not found.`,
        },
      });
    }

    const updated = await db.updateCryptoFinding(orgId, findingId, {
      status,
      resolutionComment: resolutionComment || existing.resolutionComment,
      resolvedBy: status === 'RESOLVED' || status === 'FALSE_POSITIVE' ? userId : existing.resolvedBy,
      resolvedAt: status === 'RESOLVED' || status === 'FALSE_POSITIVE' ? new Date() : existing.resolvedAt,
    });

    // Record audit event
    const action =
      status === 'RESOLVED'
        ? 'CRYPTO_FINDING_RESOLVED'
        : status === 'SUPPRESSED'
        ? 'CRYPTO_FINDING_SUPPRESSED'
        : 'CRYPTO_FINDING_UPDATED';

    await db.createAuditEvent({
      organizationId: orgId,
      userId,
      action,
      resourceType: 'CRYPTO_FINDING',
      resourceId: findingId,
      metadata: {
        previousStatus: existing.status,
        newStatus: status,
        resolutionComment,
      },
    });

    return res.status(200).json({
      success: true,
      data: updated,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /cbom & POST /cbom/export
 * Export machine-readable Cryptographic Bill of Materials (CBOM) JSON document.
 * Strictly guarantees ZERO SECRET LEAKAGE.
 */
const handleCbomExport = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const userId = (req as any).user?.id || 'system';
    const { environment } = req.query;

    const assets = await db.listCryptoAssets(orgId);
    const rels = await db.listCryptoRelationships(orgId);
    const findings = await db.listCryptoFindings(orgId);

    const cbom = CBOMGenerator.generate({
      organizationId: orgId,
      assets: assets as any,
      relationships: rels as any,
      findings: findings as any,
      environment: (environment as string) || 'PRODUCTION',
    });

    await db.createAuditEvent({
      organizationId: orgId,
      userId,
      action: 'CRYPTO_CBOM_EXPORTED',
      resourceType: 'CBOM',
      resourceId: cbom.serialNumber,
      metadata: {
        totalComponents: cbom.components.length,
        integrityHash: cbom.integrity.hash,
      },
    });

    return res.status(200).json(cbom);
  } catch (error) {
    next(error);
  }
};

router.get('/cbom', handleCbomExport);
router.post('/cbom/export', handleCbomExport);

/**
 * GET /migrations
 * List migration plans.
 */
router.get('/migrations', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const plans = await db.listCryptoMigrationPlans(orgId);

    return res.status(200).json({
      success: true,
      data: plans,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /migrations
 * Create a new crypto-agility migration plan.
 */
router.post('/migrations', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const userId = (req as any).user?.id || 'system';
    const {
      name,
      description,
      affectedAssetIds = [],
      currentAlgorithm,
      targetAlgorithm,
      migrationStrategy,
      environmentId,
    } = req.body;

    if (!name || !currentAlgorithm) {
      return res.status(400).json({
        error: {
          code: 'INVALID_REQUEST',
          message: 'Plan name and currentAlgorithm are required.',
        },
      });
    }

    const planItem = CryptoMigrationEngine.createMigrationPlan({
      organizationId: orgId,
      name,
      description,
      affectedAssetIds,
      currentAlgorithm,
      targetAlgorithm,
      migrationStrategy,
      owner: userId,
      environmentId,
    });

    const savedPlan = await db.createCryptoMigrationPlan({
      id: planItem.id,
      organizationId: orgId,
      name: planItem.name,
      description: planItem.description,
      affectedAssetIds: planItem.affectedAssetIds,
      currentAlgorithm: planItem.currentAlgorithm,
      targetAlgorithm: planItem.targetAlgorithm,
      migrationStrategy: planItem.migrationStrategy,
      dependencies: planItem.dependencies,
      blockers: planItem.blockers,
      owner: planItem.owner,
      environmentId: planItem.environmentId,
      status: planItem.status,
      validationRequirements: planItem.validationRequirements,
      metadata: planItem.metadata,
      createdAt: planItem.createdAt,
      updatedAt: planItem.updatedAt,
    });

    await db.createAuditEvent({
      organizationId: orgId,
      userId,
      action: 'CRYPTO_MIGRATION_CREATED',
      resourceType: 'CRYPTO_MIGRATION_PLAN',
      resourceId: savedPlan.id,
      metadata: {
        currentAlgorithm,
        targetAlgorithm: savedPlan.targetAlgorithm,
        affectedAssetsCount: affectedAssetIds.length,
      },
    });

    return res.status(201).json({
      success: true,
      data: savedPlan,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /migrations/:id
 * Retrieve a specific migration plan.
 */
router.get('/migrations/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const planId = req.params.id;

    const plan = await db.getCryptoMigrationPlan(orgId, planId);
    if (!plan) {
      return res.status(404).json({
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: `Migration plan '${planId}' not found.`,
        },
      });
    }

    return res.status(200).json({
      success: true,
      data: plan,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /migrations/:id
 * Update status or metadata of a migration plan.
 */
router.patch('/migrations/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const planId = req.params.id;
    const userId = (req as any).user?.id || 'system';
    const { status, blockers, validationRequirements, description } = req.body;

    const existing = await db.getCryptoMigrationPlan(orgId, planId);
    if (!existing) {
      return res.status(404).json({
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: `Migration plan '${planId}' not found.`,
        },
      });
    }

    const updated = await db.updateCryptoMigrationPlan(orgId, planId, {
      status: status || existing.status,
      blockers: blockers !== undefined ? blockers : existing.blockers,
      validationRequirements: validationRequirements !== undefined ? validationRequirements : existing.validationRequirements,
      description: description || existing.description,
    });

    await db.createAuditEvent({
      organizationId: orgId,
      userId,
      action: 'CRYPTO_MIGRATION_UPDATED',
      resourceType: 'CRYPTO_MIGRATION_PLAN',
      resourceId: planId,
      metadata: {
        previousStatus: existing.status,
        newStatus: status || existing.status,
      },
    });

    return res.status(200).json({
      success: true,
      data: updated,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /snapshots
 * List inventory snapshots.
 */
router.get('/snapshots', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const snapshots = await db.listCryptoSnapshots(orgId);

    return res.status(200).json({
      success: true,
      data: snapshots,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /snapshots/diff
 * Compare two snapshots or latest vs previous to analyze drift.
 */
router.get('/snapshots/diff', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.organizationId!;
    const snapshots = await db.listCryptoSnapshots(orgId);

    if (snapshots.length < 2) {
      return res.status(200).json({
        success: true,
        message: 'At least two snapshots are required to compute historical drift comparison.',
        drift: snapshots[0]?.drift || null,
      });
    }

    const latest = snapshots[0];
    const previous = snapshots[1];

    return res.status(200).json({
      success: true,
      latestSnapshotId: latest.id,
      previousSnapshotId: previous.id,
      drift: latest.drift,
    });
  } catch (error) {
    next(error);
  }
});

export default router;
