import { db } from './data-store';
import { PlanDefinition } from './billing-plans';
import { isSelfHosted } from './edition';

export type CircuitBreakerStatus = 'NORMAL' | 'WARNING' | 'THROTTLED' | 'SUSPENDED';

export interface SafetyEvaluationResult {
  allowed: boolean;
  status: CircuitBreakerStatus;
  opsPerMinute: number;
  opsPerHour: number;
  opsPerDay: number;
  spendingLimitCents: number;
  estimatedCostCents: number;
  reason?: string;
  delayMs?: number;
}

export class BillingSafetyEngine {
  // Velocity limits per organization
  public static readonly WARNING_OPS_PER_MIN = 5000;
  public static readonly THROTTLE_OPS_PER_MIN = 10000;
  public static readonly SUSPEND_OPS_PER_MIN = 100000;

  /**
   * Reset sliding velocity windows if expired.
   */
  private resetWindowsIfNeeded(state: any, now: Date): boolean {
    const elapsedMs = now.getTime() - new Date(state.lastWindowReset).getTime();
    let updated = false;

    // Reset minute window
    if (elapsedMs >= 60000) {
      state.opsPerMinute = 0;
      updated = true;
    }
    // Reset hour window
    if (elapsedMs >= 3600000) {
      state.opsPerHour = 0;
      updated = true;
    }
    // Reset day window
    if (elapsedMs >= 86400000) {
      state.opsPerDay = 0;
      state.lastWindowReset = now;
      updated = true;
    }

    return updated;
  }

  /**
   * Pre-execution safety evaluation.
   * Checks circuit breaker state and PAYG spending caps before operation execution.
   */
  async evaluateSafety(
    organizationId: string,
    requestedQuantity: number = 1,
    plan: PlanDefinition
  ): Promise<SafetyEvaluationResult> {
    // The circuit breaker protects Cloud customers from runaway charges. A self-hosted
    // installation has no metered Cloud bill, so it is never throttled or suspended here.
    if (isSelfHosted()) {
      return { allowed: true, status: 'NORMAL', opsPerMinute: 0, opsPerHour: 0, opsPerDay: 0, spendingLimitCents: 0, estimatedCostCents: 0 };
    }

    const now = new Date();
    const safetyState = await db.getBillingSafetyState(organizationId);
    const usage = await db.getCurrentBillingUsage(organizationId);

    this.resetWindowsIfNeeded(safetyState, now);

    // 1. Check if already SUSPENDED
    if (safetyState.circuitBreakerStatus === 'SUSPENDED') {
      return {
        allowed: false,
        status: 'SUSPENDED',
        opsPerMinute: safetyState.opsPerMinute,
        opsPerHour: safetyState.opsPerHour,
        opsPerDay: safetyState.opsPerDay,
        spendingLimitCents: safetyState.paygSpendingLimitCents,
        estimatedCostCents: usage.estimatedCostCents,
        reason: safetyState.suspensionReason || 'Cryptographic operations suspended by billing safety circuit breaker.',
      };
    }

    // 2. Check Spending Limit Protection (PAYG & Authorized Overage)
    if (plan.id === 'PAYG') {
      const estimatedCostWithOp = usage.estimatedCostCents + Math.round((requestedQuantity / 1000) * plan.costPer1kOpsCents);

      if (safetyState.autoHaltEnabled && estimatedCostWithOp >= safetyState.paygSpendingLimitCents) {
        // Trip circuit breaker to SUSPENDED
        await db.updateBillingSafetyState(organizationId, {
          circuitBreakerStatus: 'SUSPENDED',
          suspensionReason: `Pay As You Go monthly spending limit of $${(safetyState.paygSpendingLimitCents / 100).toFixed(2)} reached. Operation halted for financial protection.`,
        });

        return {
          allowed: false,
          status: 'SUSPENDED',
          opsPerMinute: safetyState.opsPerMinute,
          opsPerHour: safetyState.opsPerHour,
          opsPerDay: safetyState.opsPerDay,
          spendingLimitCents: safetyState.paygSpendingLimitCents,
          estimatedCostCents: usage.estimatedCostCents,
          reason: `Pay As You Go monthly spending limit ($${(safetyState.paygSpendingLimitCents / 100).toFixed(2)}) reached. Increase your spending limit to resume operations.`,
        };
      }

      // Check alert threshold (e.g. 80%)
      const warningCents = (safetyState.paygSpendingLimitCents * safetyState.alertThresholdPercent) / 100;
      if (usage.estimatedCostCents >= warningCents && safetyState.circuitBreakerStatus === 'NORMAL') {
        await db.updateBillingSafetyState(organizationId, {
          circuitBreakerStatus: 'WARNING',
        });
        safetyState.circuitBreakerStatus = 'WARNING';
      }
    } else if (safetyState.overagePolicy === 'AUTHORIZED_OVERAGE' && safetyState.authorizedOverageSpendingLimitCents > 0) {
      // Fixed plan with explicit authorized overage
      const overageLimit = safetyState.authorizedOverageSpendingLimitCents;
      if (safetyState.autoHaltEnabled && usage.estimatedCostCents >= overageLimit) {
        await db.updateBillingSafetyState(organizationId, {
          circuitBreakerStatus: 'SUSPENDED',
          suspensionReason: `Authorized overage spending limit of $${(overageLimit / 100).toFixed(2)} reached. Operation halted for financial protection.`,
        });

        return {
          allowed: false,
          status: 'SUSPENDED',
          opsPerMinute: safetyState.opsPerMinute,
          opsPerHour: safetyState.opsPerHour,
          opsPerDay: safetyState.opsPerDay,
          spendingLimitCents: overageLimit,
          estimatedCostCents: usage.estimatedCostCents,
          reason: `Authorized overage monthly spending limit ($${(overageLimit / 100).toFixed(2)}) reached. Increase your authorized overage limit to resume operations.`,
        };
      }
    }

    // 3. Check Velocity Circuit Breaker
    const projectedPerMin = safetyState.opsPerMinute + requestedQuantity;

    if (projectedPerMin >= BillingSafetyEngine.SUSPEND_OPS_PER_MIN) {
      await db.updateBillingSafetyState(organizationId, {
        circuitBreakerStatus: 'SUSPENDED',
        suspensionReason: `Catastrophic operation flood detected (${projectedPerMin.toLocaleString()} ops/min). Circuit breaker tripped to prevent unbounded financial liability.`,
      });
      return {
        allowed: false,
        status: 'SUSPENDED',
        opsPerMinute: projectedPerMin,
        opsPerHour: safetyState.opsPerHour + requestedQuantity,
        opsPerDay: safetyState.opsPerDay + requestedQuantity,
        spendingLimitCents: safetyState.paygSpendingLimitCents,
        estimatedCostCents: usage.estimatedCostCents,
        reason: 'Emergency circuit breaker tripped: Catastrophic operation flood detected. Contact administrator.',
      };
    }

    if (projectedPerMin >= BillingSafetyEngine.THROTTLE_OPS_PER_MIN) {
      if (safetyState.circuitBreakerStatus !== 'THROTTLED') {
        await db.updateBillingSafetyState(organizationId, { circuitBreakerStatus: 'THROTTLED' });
      }
      return {
        allowed: true,
        status: 'THROTTLED',
        opsPerMinute: projectedPerMin,
        opsPerHour: safetyState.opsPerHour + requestedQuantity,
        opsPerDay: safetyState.opsPerDay + requestedQuantity,
        spendingLimitCents: safetyState.paygSpendingLimitCents,
        estimatedCostCents: usage.estimatedCostCents,
        delayMs: 200, // 200ms throttle backpressure
      };
    }

    if (projectedPerMin >= BillingSafetyEngine.WARNING_OPS_PER_MIN) {
      if (safetyState.circuitBreakerStatus === 'NORMAL') {
        await db.updateBillingSafetyState(organizationId, { circuitBreakerStatus: 'WARNING' });
      }
      return {
        allowed: true,
        status: 'WARNING',
        opsPerMinute: projectedPerMin,
        opsPerHour: safetyState.opsPerHour + requestedQuantity,
        opsPerDay: safetyState.opsPerDay + requestedQuantity,
        spendingLimitCents: safetyState.paygSpendingLimitCents,
        estimatedCostCents: usage.estimatedCostCents,
      };
    }

    return {
      allowed: true,
      status: (safetyState.circuitBreakerStatus as CircuitBreakerStatus) || 'NORMAL',
      opsPerMinute: safetyState.opsPerMinute,
      opsPerHour: safetyState.opsPerHour,
      opsPerDay: safetyState.opsPerDay,
      spendingLimitCents: safetyState.paygSpendingLimitCents,
      estimatedCostCents: usage.estimatedCostCents,
    };
  }

  /**
   * Post-execution velocity record update.
   */
  async recordVelocity(organizationId: string, quantity: number = 1): Promise<void> {
    if (isSelfHosted()) return;
    const safetyState = await db.getBillingSafetyState(organizationId);
    const now = new Date();
    this.resetWindowsIfNeeded(safetyState, now);

    const newOpsPerMinute = safetyState.opsPerMinute + quantity;
    const updates: any = {
      opsPerMinute: newOpsPerMinute,
      opsPerHour: safetyState.opsPerHour + quantity,
      opsPerDay: safetyState.opsPerDay + quantity,
    };

    if (newOpsPerMinute >= BillingSafetyEngine.SUSPEND_OPS_PER_MIN) {
      updates.circuitBreakerStatus = 'SUSPENDED';
      updates.suspensionReason = `Emergency velocity burst exceeded threshold: ${newOpsPerMinute} ops/min (limit: ${BillingSafetyEngine.SUSPEND_OPS_PER_MIN})`;
    }

    await db.updateBillingSafetyState(organizationId, updates);
  }

  /**
   * Update spending limits, overage policies, and circuit breaker thresholds (Admin/Owner only).
   */
  async updateSpendingProtection(
    organizationId: string,
    params: {
      spendingLimitCents?: number;
      alertThresholdPercent?: number;
      autoHaltEnabled?: boolean;
      overagePolicy?: 'HARD_STOP' | 'AUTHORIZED_OVERAGE' | 'ENTERPRISE_CUSTOM';
      authorizedOverageSpendingLimitCents?: number;
    }
  ) {
    const current = await db.getBillingSafetyState(organizationId);
    const updates: any = {};

    if (params.spendingLimitCents !== undefined && params.spendingLimitCents >= 1000) {
      updates.paygSpendingLimitCents = params.spendingLimitCents;
    }
    if (params.alertThresholdPercent !== undefined && params.alertThresholdPercent >= 10 && params.alertThresholdPercent <= 95) {
      updates.alertThresholdPercent = params.alertThresholdPercent;
    }
    if (params.autoHaltEnabled !== undefined) {
      updates.autoHaltEnabled = params.autoHaltEnabled;
    }
    if (params.overagePolicy !== undefined) {
      updates.overagePolicy = params.overagePolicy;
    }
    if (params.authorizedOverageSpendingLimitCents !== undefined && params.authorizedOverageSpendingLimitCents >= 0) {
      updates.authorizedOverageSpendingLimitCents = params.authorizedOverageSpendingLimitCents;
    }

    // If previously suspended for spending limit, and new cap is higher than current usage, restore to NORMAL
    const usage = await db.getCurrentBillingUsage(organizationId);
    const targetCap = updates.paygSpendingLimitCents || current.paygSpendingLimitCents;
    if (current.circuitBreakerStatus === 'SUSPENDED' && usage.estimatedCostCents < targetCap) {
      updates.circuitBreakerStatus = 'NORMAL';
      updates.suspensionReason = null;
    }

    return db.updateBillingSafetyState(organizationId, updates);
  }

  /**
   * Manually reset the circuit breaker back to NORMAL.
   */
  async resetCircuitBreaker(organizationId: string) {
    return db.updateBillingSafetyState(organizationId, {
      circuitBreakerStatus: 'NORMAL',
      opsPerMinute: 0,
      opsPerHour: 0,
      opsPerDay: 0,
      suspensionReason: null,
      lastWindowReset: new Date(),
    });
  }
}

export const billingSafetyEngine = new BillingSafetyEngine();
