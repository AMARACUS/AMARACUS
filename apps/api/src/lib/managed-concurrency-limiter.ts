import { OperationType } from '@amaracus/crypto-core';

export interface ConcurrencyLimits {
  maxConcurrentTotal: number;
  maxConcurrentHeavy: number;
}

export interface ConcurrencyAcquireResult {
  allowed: boolean;
  reason?: string;
  currentTotal: number;
  currentHeavy: number;
  limitTotal: number;
  limitHeavy: number;
}

export class ManagedConcurrencyLimiter {
  private activeByOrg = new Map<string, { total: number; heavy: number }>();
  private defaultLimits: ConcurrencyLimits = {
    maxConcurrentTotal: 50,
    maxConcurrentHeavy: 5,
  };
  private globalActiveTotal = 0;
  private maxGlobalLimit = 1000;

  /**
   * Determine whether an operation constitutes a heavy, compute-intensive workload
   * such as Fully Homomorphic Encryption (FHE), Multi-Party Computation (MPC), or ZK Proving.
   */
  isHeavyWorkload(operationType: string | OperationType, algorithm?: string | null): boolean {
    const heavyTypes = new Set([
      'FHE_EXECUTE',
      'FHE_ENCRYPT',
      'FHE_DECRYPT',
      'MPC_COMPUTE',
      'ZK_PROVE',
      'BATCH_ENCRYPT',
      'BATCH_DECRYPT',
      'BATCH_SIGN',
      'KEY_DERIVATION_BULK',
    ]);

    if (heavyTypes.has(operationType)) return true;

    if (algorithm) {
      const upper = algorithm.toUpperCase();
      if (
        upper.startsWith('FHE_') ||
        upper.startsWith('MPC_') ||
        upper.startsWith('ZK_') ||
        upper.includes('TFHE') ||
        upper.includes('BFV') ||
        upper.includes('BGV') ||
        upper.includes('CKKS')
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Attempt to acquire a concurrency slot for a tenant.
   * Atomic within the single-threaded Node.js event loop.
   */
  tryAcquire(
    organizationId: string,
    operationType: string | OperationType,
    algorithm?: string | null,
    customLimits?: Partial<ConcurrencyLimits>
  ): ConcurrencyAcquireResult {
    const limits: ConcurrencyLimits = {
      maxConcurrentTotal: customLimits?.maxConcurrentTotal ?? this.defaultLimits.maxConcurrentTotal,
      maxConcurrentHeavy: customLimits?.maxConcurrentHeavy ?? this.defaultLimits.maxConcurrentHeavy,
    };

    const isHeavy = this.isHeavyWorkload(operationType, algorithm);
    const orgState = this.activeByOrg.get(organizationId) || { total: 0, heavy: 0 };

    // 1. Check global ceiling
    if (this.globalActiveTotal >= this.maxGlobalLimit) {
      return {
        allowed: false,
        reason: 'SYSTEM_CONCURRENCY_LIMIT_EXCEEDED',
        currentTotal: orgState.total,
        currentHeavy: orgState.heavy,
        limitTotal: limits.maxConcurrentTotal,
        limitHeavy: limits.maxConcurrentHeavy,
      };
    }

    // 2. Check tenant total limit
    if (orgState.total >= limits.maxConcurrentTotal) {
      return {
        allowed: false,
        reason: 'TENANT_CONCURRENCY_LIMIT_EXCEEDED',
        currentTotal: orgState.total,
        currentHeavy: orgState.heavy,
        limitTotal: limits.maxConcurrentTotal,
        limitHeavy: limits.maxConcurrentHeavy,
      };
    }

    // 3. Check tenant heavy workload limit
    if (isHeavy && orgState.heavy >= limits.maxConcurrentHeavy) {
      return {
        allowed: false,
        reason: 'HEAVY_WORKLOAD_CONCURRENCY_LIMIT_EXCEEDED',
        currentTotal: orgState.total,
        currentHeavy: orgState.heavy,
        limitTotal: limits.maxConcurrentTotal,
        limitHeavy: limits.maxConcurrentHeavy,
      };
    }

    // Slots available: acquire
    orgState.total += 1;
    if (isHeavy) {
      orgState.heavy += 1;
    }
    this.activeByOrg.set(organizationId, orgState);
    this.globalActiveTotal += 1;

    return {
      allowed: true,
      currentTotal: orgState.total,
      currentHeavy: orgState.heavy,
      limitTotal: limits.maxConcurrentTotal,
      limitHeavy: limits.maxConcurrentHeavy,
    };
  }

  /**
   * Release acquired concurrency slot upon operation completion, failure, or timeout.
   */
  release(
    organizationId: string,
    operationType: string | OperationType,
    algorithm?: string | null
  ): void {
    const orgState = this.activeByOrg.get(organizationId);
    if (!orgState) return;

    const isHeavy = this.isHeavyWorkload(operationType, algorithm);

    orgState.total = Math.max(0, orgState.total - 1);
    if (isHeavy) {
      orgState.heavy = Math.max(0, orgState.heavy - 1);
    }

    this.globalActiveTotal = Math.max(0, this.globalActiveTotal - 1);

    if (orgState.total === 0 && orgState.heavy === 0) {
      this.activeByOrg.delete(organizationId);
    } else {
      this.activeByOrg.set(organizationId, orgState);
    }
  }

  /**
   * Snapshot metrics for observability.
   */
  getMetrics(organizationId?: string): {
    globalActive: number;
    tenantActiveTotal: number;
    tenantActiveHeavy: number;
    allTenantsActiveCount: number;
  } {
    const orgState = organizationId ? this.activeByOrg.get(organizationId) : undefined;
    return {
      globalActive: this.globalActiveTotal,
      tenantActiveTotal: orgState?.total || 0,
      tenantActiveHeavy: orgState?.heavy || 0,
      allTenantsActiveCount: this.activeByOrg.size,
    };
  }

  /**
   * Reset limiter state (primarily for test fixture cleanup).
   */
  reset(): void {
    this.activeByOrg.clear();
    this.globalActiveTotal = 0;
  }
}

export const managedConcurrencyLimiter = new ManagedConcurrencyLimiter();
