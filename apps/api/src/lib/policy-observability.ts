/**
 * AMARACUS Cryptographic Infrastructure — Policy Observability & Telemetry
 *
 * Collects metrics for policy evaluations, decisions, violations,
 * cache efficiency, and latency histograms. Emits operational alerts
 * upon sudden DENY spikes or policy misconfigurations.
 */

import { PolicyDecisionType } from '@amaracus/crypto-core';

export interface PolicyTelemetrySnapshot {
  evaluationsTotal: number;
  decisions: Record<PolicyDecisionType, number>;
  violationsByRule: Record<string, number>;
  latencies: {
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    avgMs: number;
  };
  cache: {
    hits: number;
    misses: number;
    hitRatePercent: number;
  };
  alerts: Array<{ severity: 'WARNING' | 'CRITICAL'; message: string; timestamp: Date }>;
}

export class PolicyObservability {
  private evaluationsTotal = 0;
  private decisionsCount: Record<PolicyDecisionType, number> = {
    ALLOW: 0,
    DENY: 0,
    REQUIRE_CONFIGURATION: 0,
    REQUIRE_STRONGER_ALGORITHM: 0,
    REQUIRE_KEY_ROTATION: 0,
    REQUIRE_APPROVED_PROVIDER: 0,
  };
  private violationsCount: Map<string, number> = new Map();
  private latencySamples: number[] = [];
  private cacheHits = 0;
  private cacheMisses = 0;
  private alerts: Array<{ severity: 'WARNING' | 'CRITICAL'; message: string; timestamp: Date }> = [];

  public recordEvaluation(decision: PolicyDecisionType, durationMs: number, reasons?: string[]): void {
    this.evaluationsTotal++;
    this.decisionsCount[decision] = (this.decisionsCount[decision] || 0) + 1;

    this.latencySamples.push(durationMs);
    if (this.latencySamples.length > 1000) {
      this.latencySamples.shift();
    }

    if (decision !== 'ALLOW' && reasons) {
      for (const r of reasons) {
        const key = r.slice(0, 80);
        this.violationsCount.set(key, (this.violationsCount.get(key) || 0) + 1);
      }
    }

    // Check alerting threshold (e.g. sudden spike in DENY decisions)
    if (decision === 'DENY' && this.evaluationsTotal > 10) {
      const denyRatio = this.decisionsCount.DENY / this.evaluationsTotal;
      if (denyRatio > 0.5 && this.alerts.length === 0) {
        this.alerts.push({
          severity: 'CRITICAL',
          message: `Elevated cryptographic policy rejection rate detected (${Math.round(denyRatio * 100)}% DENY). Review active policies for misconfigurations.`,
          timestamp: new Date(),
        });
      }
    }
  }

  public recordCacheHit(): void {
    this.cacheHits++;
  }

  public recordCacheMiss(): void {
    this.cacheMisses++;
  }

  public getSnapshot(): PolicyTelemetrySnapshot {
    const sorted = [...this.latencySamples].sort((a, b) => a - b);
    const count = sorted.length;
    const p50 = count > 0 ? sorted[Math.floor(count * 0.5)] : 0;
    const p95 = count > 0 ? sorted[Math.floor(count * 0.95)] : 0;
    const p99 = count > 0 ? sorted[Math.floor(count * 0.99)] : 0;
    const avg = count > 0 ? sorted.reduce((a, b) => a + b, 0) / count : 0;

    const totalCache = this.cacheHits + this.cacheMisses;
    const hitRate = totalCache > 0 ? (this.cacheHits / totalCache) * 100 : 100;

    const violationsObj: Record<string, number> = {};
    this.violationsCount.forEach((v, k) => {
      violationsObj[k] = v;
    });

    return {
      evaluationsTotal: this.evaluationsTotal,
      decisions: { ...this.decisionsCount },
      violationsByRule: violationsObj,
      latencies: {
        p50Ms: Math.round(p50 * 100) / 100,
        p95Ms: Math.round(p95 * 100) / 100,
        p99Ms: Math.round(p99 * 100) / 100,
        avgMs: Math.round(avg * 100) / 100,
      },
      cache: {
        hits: this.cacheHits,
        misses: this.cacheMisses,
        hitRatePercent: Math.round(hitRate * 10) / 10,
      },
      alerts: [...this.alerts],
    };
  }

  public reset(): void {
    this.evaluationsTotal = 0;
    this.decisionsCount = {
      ALLOW: 0,
      DENY: 0,
      REQUIRE_CONFIGURATION: 0,
      REQUIRE_STRONGER_ALGORITHM: 0,
      REQUIRE_KEY_ROTATION: 0,
      REQUIRE_APPROVED_PROVIDER: 0,
    };
    this.violationsCount.clear();
    this.latencySamples = [];
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.alerts = [];
  }
}

export const policyObservability = new PolicyObservability();
