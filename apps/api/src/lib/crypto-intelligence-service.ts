/**
 * @file apps/api/src/lib/crypto-intelligence-service.ts
 * Enterprise Cryptographic Intelligence & Autonomous Optimization Service (Phase 21)
 */

import {
  EvidenceSnapshot,
  OptimizationRecommendation,
  RecommendationCategory,
  RecommendationStatus,
  SeverityLevel,
  ImpactAnalysisResult,
  RecommendationEngine,
  EvidenceAnalyzer,
  ImpactAnalyzer,
  RawKeyTelemetry,
  RawCertTelemetry,
  RawCircuitBreakerTelemetry,
  RawPolicyEvaluationTelemetry,
  RawUsageTelemetry,
} from '@amaracus/crypto-core';
import { db } from './data-store';
import { providerCircuitBreaker } from './provider-circuit-breaker';
import { CryptoOsOrchestrator } from './crypto-os-orchestrator';

export interface RecommendationFilter {
  category?: RecommendationCategory;
  status?: RecommendationStatus;
  severity?: SeverityLevel;
  limit?: number;
  offset?: number;
}

export class CryptoIntelligenceService {
  private static instance: CryptoIntelligenceService;
  private recommendations: Map<string, OptimizationRecommendation[]> = new Map();

  private constructor() {}

  public static getInstance(): CryptoIntelligenceService {
    if (!CryptoIntelligenceService.instance) {
      CryptoIntelligenceService.instance = new CryptoIntelligenceService();
    }
    return CryptoIntelligenceService.instance;
  }

  /**
   * Builds a live, verifiable EvidenceSnapshot for an organization.
   */
  public async buildEvidenceSnapshot(orgId: string): Promise<EvidenceSnapshot> {
    const snapshot: EvidenceSnapshot = {
      orgId,
      keys: [],
      certificates: [],
      circuitBreakers: [],
      policyLogs: [],
      usage: [],
      cbomAssets: [],
    };

    // 1. Gather Keys
    try {
      const keys = await db.listKeys({ organizationId: orgId });
      snapshot.keys = (keys || []).map((k: any) => ({
        id: k.id,
        name: k.name || k.id,
        orgId,
        algorithm: k.algorithm || 'AES-256-GCM',
        provider: k.provider || 'LOCAL',
        status: k.status || 'ACTIVE',
        createdAt: k.createdAt ? new Date(k.createdAt).toISOString() : new Date().toISOString(),
        lastRotatedAt: k.rotatedAt ? new Date(k.rotatedAt).toISOString() : undefined,
        versionCount: k.currentVersion,
        rotationIntervalDays: k.rotationIntervalDays || 90,
      }));
    } catch {
      // Fallback in-memory
    }

    // If no keys in db, check unified inventory from crypto OS
    if (!snapshot.keys || snapshot.keys.length === 0) {
      try {
        const osInventory = await CryptoOsOrchestrator.getInstance().getUnifiedInventory(orgId, { type: 'KEY' });
        snapshot.keys = osInventory.map((r: any) => ({
          id: r.id,
          name: r.name,
          orgId,
          algorithm: r.algorithm || 'AES-256-GCM',
          provider: r.provider || 'LOCAL',
          status: r.status,
          createdAt: r.createdAt,
          lastRotatedAt: r.metadata?.lastRotatedAt,
          rotationIntervalDays: r.metadata?.rotationIntervalDays || 90,
        }));
      } catch {
        // Ignore
      }
    }

    // 2. Gather Certificates
    try {
      const certs = await db.listCertificates({ organizationId: orgId });
      // Certificate records carry subject / authorityId / keyAlgorithm. Reading other field names
      // used to label every certificate 'RSA-2048' with an invented expiry.
      snapshot.certificates = (certs || [])
        .filter((c: any) => c.notBefore && c.notAfter && c.keyAlgorithm)
        .map((c: any) => ({
          id: c.id,
          commonName: /(?:^|,)s*CN=([^,]+)/i.exec(c.subject || '')?.[1]?.trim() || c.name || c.id,
          orgId,
          issuerId: c.authorityId || undefined,
          status: c.status,
          notBefore: new Date(c.notBefore).toISOString(),
          notAfter: new Date(c.notAfter).toISOString(),
          algorithm: c.keyAlgorithm,
        }));
    } catch {
      // Fallback
    }

    // 3. Gather Circuit Breakers Telemetry
    try {
      const breakerStatuses = providerCircuitBreaker.getAllStatuses();
      snapshot.circuitBreakers = breakerStatuses.map((b) => ({
        providerId: b.providerId,
        providerType: 'azure_key_vault',
        state: b.state,
        failuresCount: b.consecutiveFailures,
        lastFailureAt: b.lastFailureTime ? b.lastFailureTime.toISOString() : undefined,
      }));
    } catch {
      // Ignore
    }

    // 4. Gather Policy Telemetry
    try {
      const audits = await db.getAuditEventsByOrg(orgId, 50);
      const policyAudits = (audits || []).filter((a: any) =>
        a.action === 'POLICY_EVALUATION_DENIED' || a.action === 'POLICY_DENIED'
      );
      snapshot.policyLogs = policyAudits.map((a: any) => ({
        id: a.id,
        policyId: a.metadata?.policyId || 'unknown',
        policyName: a.metadata?.policyName || 'unknown',
        orgId,
        operationType: a.metadata?.operation || 'unknown',
        algorithmRequested: a.metadata?.algorithm || 'unknown',
        verdict: 'DENY',
        reason: a.metadata?.reason || 'not recorded',
        timestamp: a.createdAt ? new Date(a.createdAt).toISOString() : new Date().toISOString(),
      }));
    } catch {
      // Ignore
    }

    // 5. Usage in the current billing period, from recorded API requests (5xx counts as a
    // failure; client errors do not) and the metered cost estimate. There is no invoice data,
    // so billedCostUsd stays unset.
    snapshot.usage = [];
    try {
      const { periodStart, periodEnd } = await db.getActiveBillingPeriod(orgId);
      const requests = await db.getApiUsageMetrics(orgId, { from: periodStart, to: periodEnd });
      if (requests.totalRequests > 0) {
        const failedOperations = Object.entries(requests.byStatusCode)
          .filter(([code]) => Number(code) >= 500)
          .reduce((sum, [, count]) => sum + count, 0);
        const billing = await db.getCurrentBillingUsage(orgId);
        snapshot.usage.push({
          orgId,
          periodStart: periodStart.toISOString(),
          periodEnd: periodEnd.toISOString(),
          totalOperations: requests.totalRequests,
          failedOperations,
          activeKeys: (snapshot.keys || []).filter((k) => k.status === 'ACTIVE').length,
          estimatedCostUsd: billing.estimatedCostCents / 100,
        });
      }
    } catch {
      // Usage is optional evidence; the other sections still produce recommendations.
    }

    return snapshot;
  }

  /**
   * Lists recommendations for an organization with optional filtering.
   */
  public async listRecommendations(
    orgId: string,
    filter?: RecommendationFilter
  ): Promise<{ recommendations: OptimizationRecommendation[]; total: number }> {
    let recs = this.recommendations.get(orgId);

    // If no recommendations exist yet, run initial analysis
    if (!recs || recs.length === 0) {
      const snapshot = await this.buildEvidenceSnapshot(orgId);
      recs = RecommendationEngine.generateRecommendations(snapshot);
      this.recommendations.set(orgId, recs);
    }

    let filtered = [...recs];

    if (filter?.category) {
      filtered = filtered.filter((r) => r.category === filter.category);
    }
    if (filter?.status) {
      filtered = filtered.filter((r) => r.status === filter.status);
    }
    if (filter?.severity) {
      filtered = filtered.filter((r) => r.severity === filter.severity);
    }

    const total = filtered.length;
    const offset = filter?.offset || 0;
    const limit = filter?.limit || 50;
    const paginated = filtered.slice(offset, offset + limit);

    return { recommendations: paginated, total };
  }

  /**
   * Retrieves a specific recommendation by ID.
   */
  public async getRecommendation(
    orgId: string,
    id: string
  ): Promise<OptimizationRecommendation | null> {
    const { recommendations } = await this.listRecommendations(orgId);
    const found = recommendations.find((r) => r.id === id);
    if (!found || found.orgId !== orgId) {
      return null;
    }
    return found;
  }


  /**
   * Accepts a recommendation.
   */
  public async acceptRecommendation(
    orgId: string,
    id: string,
    feedback: { reason?: string },
    actorId: string
  ): Promise<OptimizationRecommendation> {
    const rec = await this.getRecommendation(orgId, id);
    if (!rec) {
      throw new Error(`Recommendation "${id}" not found.`);
    }

    const now = new Date().toISOString();
    rec.status = 'ACCEPTED';
    rec.userFeedback = {
      decision: 'ACCEPT',
      reason: feedback?.reason,
      decidedBy: actorId,
      decidedAt: now,
    };
    rec.updatedAt = now;

    // Automatic non-destructive dry-run impact evaluation on acceptance
    rec.dryRunResult = ImpactAnalyzer.analyze(rec);

    // If it is low-risk automated remediation (e.g. refreshing health probe or draft creation), execute safely
    if (rec.proposedAction.isAutomated && !rec.proposedAction.requiresApproval) {
      rec.status = 'COMPLETED';
    }

    await db.createAuditEvent({
      organizationId: orgId,
      userId: actorId,
      action: 'INTELLIGENCE_RECOMMENDATION_ACCEPTED',
      resourceType: 'RECOMMENDATION',
      resourceId: id,
      metadata: { feedback, status: rec.status, isAutomated: rec.proposedAction.isAutomated },
    });

    return rec;
  }

  /**
   * Rejects a recommendation with user rationale.
   */
  public async rejectRecommendation(
    orgId: string,
    id: string,
    feedback: { reason?: string },
    actorId: string
  ): Promise<OptimizationRecommendation> {
    const rec = await this.getRecommendation(orgId, id);
    if (!rec) {
      throw new Error(`Recommendation "${id}" not found.`);
    }

    const now = new Date().toISOString();
    rec.status = 'REJECTED';
    rec.userFeedback = {
      decision: 'REJECT',
      reason: feedback?.reason || 'Rejected by administrator',
      decidedBy: actorId,
      decidedAt: now,
    };
    rec.updatedAt = now;

    await db.createAuditEvent({
      organizationId: orgId,
      userId: actorId,
      action: 'INTELLIGENCE_RECOMMENDATION_REJECTED',
      resourceType: 'RECOMMENDATION',
      resourceId: id,
      metadata: { feedback },
    });

    return rec;
  }

  /**
   * Dismisses a recommendation as irrelevant or duplicate.
   */
  public async dismissRecommendation(
    orgId: string,
    id: string,
    feedback: { reason?: string },
    actorId: string
  ): Promise<OptimizationRecommendation> {
    const rec = await this.getRecommendation(orgId, id);
    if (!rec) {
      throw new Error(`Recommendation "${id}" not found.`);
    }

    const now = new Date().toISOString();
    rec.status = 'DISMISSED';
    rec.userFeedback = {
      decision: 'DISMISS',
      reason: feedback?.reason || 'Dismissed as non-actionable',
      decidedBy: actorId,
      decidedAt: now,
    };
    rec.updatedAt = now;

    await db.createAuditEvent({
      organizationId: orgId,
      userId: actorId,
      action: 'INTELLIGENCE_RECOMMENDATION_DISMISSED',
      resourceType: 'RECOMMENDATION',
      resourceId: id,
      metadata: { feedback },
    });

    return rec;
  }

  /**
   * Executes a non-destructive dry-run impact simulation on the recommendation.
   */
  public async dryRunRecommendation(
    orgId: string,
    id: string
  ): Promise<ImpactAnalysisResult> {
    const rec = await this.getRecommendation(orgId, id);
    if (!rec) {
      throw new Error(`Recommendation "${id}" not found.`);
    }

    const result = ImpactAnalyzer.analyze(rec);
    rec.dryRunResult = result;
    rec.updatedAt = new Date().toISOString();
    return result;
  }

  /**
   * Runs a complete live analysis across the organization's cryptographic infrastructure.
   */
  public async runAnalysis(
    orgId: string,
    options?: { targetResourceIds?: string[]; categories?: RecommendationCategory[] }
  ): Promise<{ newlyDetected: number; total: number; recommendations: OptimizationRecommendation[] }> {
    const snapshot = await this.buildEvidenceSnapshot(orgId);
    const fresh = RecommendationEngine.generateRecommendations(snapshot);

    const existing = this.recommendations.get(orgId) || [];
    const existingMap = new Map(existing.map((r) => [r.deduplicationKey, r]));

    let newlyDetected = 0;
    const merged: OptimizationRecommendation[] = [];

    for (const f of fresh) {
      const prev = existingMap.get(f.deduplicationKey);
      if (prev) {
        // Preserve user decisions
        f.status = prev.status;
        f.userFeedback = prev.userFeedback;
        merged.push(f);
      } else {
        newlyDetected++;
        merged.push(f);
      }
    }

    // Keep rejected/dismissed ones in store for audit history
    for (const e of existing) {
      if (!merged.some((m) => m.deduplicationKey === e.deduplicationKey)) {
        merged.push(e);
      }
    }

    this.recommendations.set(orgId, merged);

    await db.createAuditEvent({
      organizationId: orgId,
      userId: 'system',
      action: 'CRYPTO_INTELLIGENCE_ANALYSIS_COMPLETED',
      resourceType: 'INTELLIGENCE',
      resourceId: orgId,
      metadata: { newlyDetected, total: merged.length, options },
    });

    return { newlyDetected, total: merged.length, recommendations: merged };
  }

  /**
   * Executes an approved recommendation, enforcing the Four-Eyes principle.
   */
  public async executeRecommendation(
    orgId: string,
    id: string,
    actorId: string
  ): Promise<OptimizationRecommendation> {
    const rec = await this.getRecommendation(orgId, id);
    if (!rec) {
      throw new Error(`Recommendation "${id}" not found.`);
    }

    if (rec.status !== 'ACCEPTED' && rec.status !== 'SCHEDULED') {
      throw new Error(`Recommendation "${id}" must be in ACCEPTED or SCHEDULED status before execution (current: ${rec.status}).`);
    }

    // Four-Eyes Principle Enforcement
    if (rec.proposedAction.requiresFourEyes) {
      if (rec.userFeedback?.decidedBy === actorId) {
        throw new Error(
          `Four-eyes separation of duties violation: Approver (${actorId}) cannot execute their own proposed or accepted action. A distinct security officer is required.`
        );
      }
    }

    // AMARACUS does not carry out the proposed action itself. This records that a second
    // party confirmed the change was applied (by them, e.g. a key rotation via /v1/keys).
    rec.status = 'COMPLETED';
    rec.updatedAt = new Date().toISOString();

    await db.createAuditEvent({
      organizationId: orgId,
      userId: actorId,
      action: 'INTELLIGENCE_RECOMMENDATION_EXECUTED',
      resourceType: 'RECOMMENDATION',
      resourceId: id,
      metadata: { actionType: rec.proposedAction.type, executedBy: actorId, executionMode: 'MANUAL_CONFIRMATION' },
    });

    return rec;
  }
}

export const cryptoIntelligenceService = CryptoIntelligenceService.getInstance();
