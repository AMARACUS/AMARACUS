/**
 * @file packages/crypto-core/src/optimization/evidence-analyzer.ts
 * Evidence Normalization and Ingestion for AMARACUS Cryptographic Intelligence (Phase 21)
 */

import {
  EvidenceSnapshot,
  EvidenceReference,
  EvidenceConfidenceLevel,
  RawKeyTelemetry,

  RawCertTelemetry,
  RawCircuitBreakerTelemetry,
  RawPolicyEvaluationTelemetry,
  RawUsageTelemetry,
} from './types';

export class EvidenceAnalyzer {
  /**
   * Normalizes an evidence snapshot into verified and attributed evidence records.
   */
  public static extractEvidence(snapshot: EvidenceSnapshot): EvidenceReference[] {
    const evidenceList: EvidenceReference[] = [];
    const now = new Date().toISOString();

    // 1. Key Telemetry Evidence
    if (snapshot.keys && snapshot.keys.length > 0) {
      for (const key of snapshot.keys) {
        const createdAtTime = new Date(key.createdAt).getTime();
        const lastRotatedTime = key.lastRotatedAt ? new Date(key.lastRotatedAt).getTime() : createdAtTime;
        const ageDays = Math.floor((Date.now() - lastRotatedTime) / (1000 * 60 * 60 * 24));
        const rotationThreshold = key.rotationIntervalDays || 90;

        evidenceList.push({
          source: 'KEY_METADATA',
          resourceId: key.id,
          metricOrFact: 'KEY_AGE_DAYS',
          observedValue: ageDays,
          thresholdOrStandard: rotationThreshold,
          timestamp: now,
          isEstimate: false,
          confidence: 'VERIFIED_FACT',
        });

        if (key.algorithm) {
          evidenceList.push({
            source: 'KEY_METADATA',
            resourceId: key.id,
            metricOrFact: 'ALGORITHM_CONFIGURED',
            observedValue: key.algorithm,
            timestamp: now,
            isEstimate: false,
            confidence: 'VERIFIED_FACT',
          });
        }
      }
    }

    // 2. Certificate Expiry Evidence
    if (snapshot.certificates && snapshot.certificates.length > 0) {
      for (const cert of snapshot.certificates) {
        const expiryTime = new Date(cert.notAfter).getTime();
        const daysUntilExpiry = Math.floor((expiryTime - Date.now()) / (1000 * 60 * 60 * 24));

        evidenceList.push({
          source: 'CERTIFICATE_METADATA',
          resourceId: cert.id,
          metricOrFact: 'DAYS_UNTIL_EXPIRATION',
          observedValue: daysUntilExpiry,
          thresholdOrStandard: 30, // 30-day early warning standard
          timestamp: now,
          isEstimate: false,
          confidence: 'VERIFIED_FACT',
        });
      }
    }

    // 3. Circuit Breaker & Provider Telemetry
    if (snapshot.circuitBreakers && snapshot.circuitBreakers.length > 0) {
      for (const cb of snapshot.circuitBreakers) {
        evidenceList.push({
          source: 'CIRCUIT_BREAKER_TELEMETRY',
          resourceId: cb.providerId,
          metricOrFact: 'CIRCUIT_STATE',
          observedValue: cb.state,
          thresholdOrStandard: 'CLOSED',
          timestamp: now,
          isEstimate: false,
          confidence: 'VERIFIED_FACT',
        });

        if (cb.averageLatencyMs !== undefined) {
          evidenceList.push({
            source: 'CIRCUIT_BREAKER_TELEMETRY',
            resourceId: cb.providerId,
            metricOrFact: 'AVERAGE_LATENCY_MS',
            observedValue: cb.averageLatencyMs,
            thresholdOrStandard: 250, // 250ms SLA baseline
            timestamp: now,
            isEstimate: false,
            confidence: 'HIGH_CONFIDENCE',
          });
        }
      }
    }

    // 4. Policy Denials Telemetry
    if (snapshot.policyLogs && snapshot.policyLogs.length > 0) {
      const denialsByPolicy = new Map<string, { count: number; lastAlgorithm: string }>();

      for (const log of snapshot.policyLogs) {
        if (log.verdict === 'DENY') {
          const current = denialsByPolicy.get(log.policyId) || { count: 0, lastAlgorithm: log.algorithmRequested };
          current.count += 1;
          current.lastAlgorithm = log.algorithmRequested;
          denialsByPolicy.set(log.policyId, current);
        }
      }

      for (const [policyId, stat] of denialsByPolicy.entries()) {
        evidenceList.push({
          source: 'POLICY_EVALUATION_LOG',
          resourceId: policyId,
          metricOrFact: 'REPEATED_POLICY_DENIALS',
          observedValue: stat.count,
          thresholdOrStandard: 5,
          timestamp: now,
          isEstimate: false,
          confidence: 'VERIFIED_FACT',
        });
      }
    }

    // 5. Usage & Billing Telemetry (Distinguishing Actual Billed vs Estimated)
    if (snapshot.usage && snapshot.usage.length > 0) {
      for (const u of snapshot.usage) {
        if (u.billedCostUsd !== undefined) {
          evidenceList.push({
            source: 'BILLING_USAGE',
            resourceId: snapshot.orgId,
            metricOrFact: 'BILLED_COST_USD',
            observedValue: u.billedCostUsd,
            timestamp: now,
            isEstimate: false,
            confidence: 'VERIFIED_FACT',
          });
        }

        if (u.estimatedCostUsd !== undefined) {
          evidenceList.push({
            source: 'BILLING_USAGE',
            resourceId: snapshot.orgId,
            metricOrFact: 'ESTIMATED_COST_USD',
            observedValue: u.estimatedCostUsd,
            timestamp: now,
            isEstimate: true,
            confidence: 'ESTIMATE',
          });
        }

        if (u.failedOperations > 0 && u.totalOperations > 0) {
          const failureRatePct = Number(((u.failedOperations / u.totalOperations) * 100).toFixed(2));
          evidenceList.push({
            source: 'OPERATIONAL_METRICS',
            resourceId: snapshot.orgId,
            metricOrFact: 'OPERATION_FAILURE_RATE_PCT',
            observedValue: failureRatePct,
            thresholdOrStandard: 1.0, // 1% failure rate alert threshold
            timestamp: now,
            isEstimate: false,
            confidence: 'HIGH_CONFIDENCE',
          });
        }
      }
    }

    // 6. CBOM Assets
    if (snapshot.cbomAssets && snapshot.cbomAssets.length > 0) {
      for (const asset of snapshot.cbomAssets) {
        evidenceList.push({
          source: 'CBOM_INVENTORY',
          resourceId: asset.id,
          metricOrFact: 'CBOM_QUANTUM_STATUS',
          observedValue: asset.quantumStatus || 'UNKNOWN',
          thresholdOrStandard: 'QUANTUM_SAFE',
          timestamp: now,
          isEstimate: false,
          confidence: 'VERIFIED_FACT',
        });
      }
    }

    return evidenceList;
  }
}
