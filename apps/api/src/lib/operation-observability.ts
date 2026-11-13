export interface OperationMetricEvent {
  operationId: string;
  organizationId: string;
  operationType: string;
  algorithm?: string | null;
  providerId?: string | null;
  status: string;
  durationMs: number;
  retries: number;
  failoverOccurred: boolean;
  timestamp: Date;
}

export interface LatencyHistogram {
  count: number;
  sumMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  minMs: number;
  maxMs: number;
}

export interface ObservabilityMetricsSummary {
  countsByStatus: Record<string, number>;
  countsByType: Record<string, number>;
  totalOperations: number;
  successRate: number;
  retryDistribution: {
    attempt1: number;
    attempt2: number;
    attempt3Plus: number;
  };
  providerFailovers: number;
  deadLetterCount: number;
  latencies: {
    overall: LatencyHistogram;
    byType: Record<string, LatencyHistogram>;
  };
  activeAlerts: Array<{
    severity: 'INFO' | 'WARNING' | 'CRITICAL';
    type: string;
    message: string;
    timestamp: Date;
  }>;
}

export class OperationObservability {
  private recentEvents: OperationMetricEvent[] = [];
  private maxStoredEvents = 10000;
  private statusCounts: Record<string, number> = {
    REQUESTED: 0,
    VALIDATING: 0,
    AUTHORIZING: 0,
    AUTHORIZED: 0,
    RESOLVING: 0,
    QUEUED: 0,
    EXECUTING: 0,
    COMPLETED: 0,
    FAILED: 0,
    TIMED_OUT: 0,
    CANCELED: 0,
    DEAD_LETTER: 0,
    EXPIRED: 0,
  };
  private typeCounts: Record<string, number> = {};
  private failoverCount = 0;
  private deadLetterCount = 0;
  private durationsOverall: number[] = [];
  private durationsByType: Map<string, number[]> = new Map();
  private retryStats = { attempt1: 0, attempt2: 0, attempt3Plus: 0 };

  recordStatusTransition(status: string): void {
    if (this.statusCounts[status] !== undefined) {
      this.statusCounts[status] += 1;
    } else {
      this.statusCounts[status] = 1;
    }
  }

  recordOperationCompleted(params: {
    operationId: string;
    organizationId: string;
    operationType: string;
    algorithm?: string | null;
    providerId?: string | null;
    durationMs: number;
    retries?: number;
    failoverOccurred?: boolean;
  }): void {
    const retries = params.retries || 0;
    this.recordStatusTransition('COMPLETED');
    this.typeCounts[params.operationType] = (this.typeCounts[params.operationType] || 0) + 1;

    if (retries === 0) {
      this.retryStats.attempt1 += 1;
    } else if (retries === 1) {
      this.retryStats.attempt2 += 1;
    } else {
      this.retryStats.attempt3Plus += 1;
    }

    if (params.failoverOccurred) {
      this.failoverCount += 1;
    }

    this.recordDuration(params.operationType, params.durationMs);

    this.storeEvent({
      operationId: params.operationId,
      organizationId: params.organizationId,
      operationType: params.operationType,
      algorithm: params.algorithm,
      providerId: params.providerId,
      status: 'COMPLETED',
      durationMs: params.durationMs,
      retries,
      failoverOccurred: !!params.failoverOccurred,
      timestamp: new Date(),
    });
  }

  recordOperationFailed(params: {
    operationId: string;
    organizationId: string;
    operationType: string;
    algorithm?: string | null;
    providerId?: string | null;
    durationMs: number;
    retries?: number;
    isDeadLetter?: boolean;
    error?: string;
  }): void {
    const retries = params.retries || 0;
    const status = params.isDeadLetter ? 'DEAD_LETTER' : 'FAILED';
    this.recordStatusTransition(status);

    if (params.isDeadLetter) {
      this.deadLetterCount += 1;
    }

    this.storeEvent({
      operationId: params.operationId,
      organizationId: params.organizationId,
      operationType: params.operationType,
      algorithm: params.algorithm,
      providerId: params.providerId,
      status,
      durationMs: params.durationMs,
      retries,
      failoverOccurred: false,
      timestamp: new Date(),
    });
  }

  recordOperationCanceled(operationId: string, organizationId: string): void {
    this.recordStatusTransition('CANCELED');
  }

  recordOperationTimedOut(operationId: string, organizationId: string): void {
    this.recordStatusTransition('TIMED_OUT');
  }

  private recordDuration(type: string, durationMs: number): void {
    this.durationsOverall.push(durationMs);
    if (this.durationsOverall.length > 5000) {
      this.durationsOverall.shift();
    }

    let byType = this.durationsByType.get(type);
    if (!byType) {
      byType = [];
      this.durationsByType.set(type, byType);
    }
    byType.push(durationMs);
    if (byType.length > 2000) {
      byType.shift();
    }
  }

  private storeEvent(event: OperationMetricEvent): void {
    this.recentEvents.push(event);
    if (this.recentEvents.length > this.maxStoredEvents) {
      this.recentEvents.shift();
    }
  }

  private calculateHistogram(samples: number[]): LatencyHistogram {
    if (samples.length === 0) {
      return { count: 0, sumMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0, minMs: 0, maxMs: 0 };
    }
    const sorted = [...samples].sort((a, b) => a - b);
    const count = sorted.length;
    const sumMs = sorted.reduce((a, b) => a + b, 0);
    const p50Index = Math.floor(count * 0.5);
    const p95Index = Math.min(count - 1, Math.floor(count * 0.95));
    const p99Index = Math.min(count - 1, Math.floor(count * 0.99));

    return {
      count,
      sumMs,
      p50Ms: sorted[p50Index],
      p95Ms: sorted[p95Index],
      p99Ms: sorted[p99Index],
      minMs: sorted[0],
      maxMs: sorted[count - 1],
    };
  }

  getMetricsSummary(organizationId?: string): ObservabilityMetricsSummary {
    const totalOps =
      (this.statusCounts.COMPLETED || 0) +
      (this.statusCounts.FAILED || 0) +
      (this.statusCounts.DEAD_LETTER || 0) +
      (this.statusCounts.TIMED_OUT || 0);

    const successOps = this.statusCounts.COMPLETED || 0;
    const successRate = totalOps > 0 ? (successOps / totalOps) * 100 : 100;

    const byTypeHist: Record<string, LatencyHistogram> = {};
    for (const [type, samples] of this.durationsByType.entries()) {
      byTypeHist[type] = this.calculateHistogram(samples);
    }

    const alerts = this.evaluateAlerts(successRate);

    return {
      countsByStatus: { ...this.statusCounts },
      countsByType: { ...this.typeCounts },
      totalOperations: totalOps,
      successRate: Math.round(successRate * 100) / 100,
      retryDistribution: { ...this.retryStats },
      providerFailovers: this.failoverCount,
      deadLetterCount: this.deadLetterCount,
      latencies: {
        overall: this.calculateHistogram(this.durationsOverall),
        byType: byTypeHist,
      },
      activeAlerts: alerts,
    };
  }

  private evaluateAlerts(successRate: number): ObservabilityMetricsSummary['activeAlerts'] {
    const alerts: ObservabilityMetricsSummary['activeAlerts'] = [];
    const now = new Date();

    if (this.deadLetterCount > 0) {
      alerts.push({
        severity: 'WARNING',
        type: 'DEAD_LETTER_ACCUMULATION',
        message: `${this.deadLetterCount} operation(s) have failed exhausted retries and entered the dead-letter queue.`,
        timestamp: now,
      });
    }

    if (successRate < 95 && this.statusCounts.FAILED > 5) {
      alerts.push({
        severity: 'CRITICAL',
        type: 'HIGH_FAILURE_RATE',
        message: `Cryptographic operation success rate degraded to ${Math.round(successRate)}%.`,
        timestamp: now,
      });
    }

    if (this.failoverCount > 10) {
      alerts.push({
        severity: 'WARNING',
        type: 'FREQUENT_PROVIDER_FAILOVER',
        message: `High frequency of provider failover occurrences (${this.failoverCount} failovers detected). Check upstream provider health.`,
        timestamp: now,
      });
    }

    return alerts;
  }

  reset(): void {
    this.recentEvents = [];
    for (const k of Object.keys(this.statusCounts)) {
      this.statusCounts[k] = 0;
    }
    this.typeCounts = {};
    this.failoverCount = 0;
    this.deadLetterCount = 0;
    this.durationsOverall = [];
    this.durationsByType.clear();
    this.retryStats = { attempt1: 0, attempt2: 0, attempt3Plus: 0 };
  }
}

export const operationObservability = new OperationObservability();
