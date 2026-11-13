import crypto from 'crypto';
import { db, BillingUsageRecord, BillingUsageEventRecord } from './data-store';
import { entitlementEngine } from './entitlement-engine';
import { billingSafetyEngine } from './billing-safety';
import { isSelfHosted } from './edition';
import { appendLedgerEntry } from './usage-ledger';
import { currentRequestContext } from './request-context';
import { isTestEnv } from './runtime-config';
import { crossedUsageWarning, notifyUsageLimitApproaching } from './usage-limit-warning';

/** Marker stored in polarEventId for events of orgs with no Polar customer (nothing to bill). */
export const NOT_BILLABLE_NO_CUSTOMER = 'not_billable:no_polar_customer';

export interface MeterOperationParams {
  organizationId: string;
  operationType: string; // e.g. "SIGN", "ENCRYPT", "DECRYPT", "VERIFY", "KEY_GEN"
  quantity?: number;
  operationId?: string; // Idempotency key
  keyId?: string;
  projectId?: string;
  metadata?: Record<string, any>;
}

export interface MeterOperationResult {
  success: boolean;
  isDuplicate: boolean;
  operationId: string;
  usage: BillingUsageRecord;
}

/**
 * Delivers one usage event to the Cloud billing provider. Registered by the Cloud module;
 * a self-hosted installation has none, and its usage never leaves the installation.
 * Returns the provider's event ID, or null when delivery should be retried.
 */
export type UsageEventDeliverer = (ev: BillingUsageEventRecord, customerId: string) => Promise<string | null>;

export class UsageMeter {
  private syncTimer: NodeJS.Timeout | null = null;
  private deliverer: UsageEventDeliverer | null = null;

  setDeliverer(deliverer: UsageEventDeliverer | null): void {
    this.deliverer = deliverer;
  }

  /**
   * Self-hosted: append the operation to the local hash-chained ledger. The operation ID is
   * unique there, so an idempotent retry is not counted twice.
   */
  /**
   * The ledger's de-duplication key. The caller's operation ID can come from client headers, so it
   * is never used alone:
   * - a request with an Idempotency-Key is the same entry as an earlier one only when the
   *   organization, operation type, key and request body all match (a genuine retry);
   * - anything else is scoped to this one HTTP request (a server nonce), so a constant
   *   X-Request-Id cannot make later operations disappear, while the route and the runtime
   *   recording the same operation within one request still count once;
   * - background work (no request) uses the server-generated operation ID.
   */
  private ledgerOperationId(params: MeterOperationParams, operationId: string): string {
    const ctx = currentRequestContext();
    let scope: string;
    if (ctx.idempotencyKey) {
      let body = '';
      try {
        body = JSON.stringify(ctx.body ? ctx.body() : null) || '';
      } catch {
        body = String(ctx.nonce || crypto.randomUUID());
      }
      scope = 'idem:' + crypto.createHash('sha256').update(ctx.idempotencyKey + '|' + body).digest('hex');
      operationId = 'idempotent';
    } else if (ctx.nonce) {
      scope = 'req:' + ctx.nonce;
    } else {
      scope = 'bg';
    }
    const digest = crypto
      .createHash('sha256')
      .update([params.organizationId, params.operationType.toUpperCase(), operationId, scope].join('|'))
      .digest('hex');
    return `led_${digest}`;
  }

  private async recordSelfHosted(params: MeterOperationParams, quantity: number, operationId: string): Promise<MeterOperationResult> {
    const { created, entry } = await appendLedgerEntry({
      organizationId: params.organizationId,
      operationId: this.ledgerOperationId(params, operationId),
      operationType: params.operationType,
      quantity,
    });
    const now = new Date();
    return {
      success: true,
      isDuplicate: !created,
      operationId,
      usage: {
        id: 'selfhosted-ledger',
        organizationId: params.organizationId,
        periodStart: new Date(0),
        periodEnd: now,
        operationCount: entry.cumulativeTotal,
        includedAllowance: 0,
        overageCount: 0,
        estimatedCostCents: 0,
        createdAt: now,
        updatedAt: now,
      } as BillingUsageRecord,
    };
  }

  /**
   * Authoritatively record a billable cryptographic operation.
   * The BillingUsageEvent row is the outbox: it is written first, and an event stays
   * pending until Polar accepts it (or the org turns out to have nothing to bill).
   */
  async recordOperation(params: MeterOperationParams): Promise<MeterOperationResult> {
    const quantity = Math.max(1, params.quantity || 1);
    const operationId = params.operationId || `op_${crypto.randomUUID()}`;

    if (isSelfHosted()) return this.recordSelfHosted(params, quantity, operationId);

    // 1. Check idempotency deduplication
    const eventRecord = await db.createBillingUsageEvent({
      id: `bue_${crypto.randomUUID().slice(0, 12)}`,
      organizationId: params.organizationId,
      operationId,
      operationType: params.operationType,
      quantity,
      keyId: params.keyId,
      projectId: params.projectId,
      timestamp: new Date(),
      reportedToPolar: false,
    });

    if (!eventRecord.created) {
      // Duplicate operation submission; do not increment usage a second time
      const currentUsage = await db.getCurrentBillingUsage(params.organizationId);
      return {
        success: true,
        isDuplicate: true,
        operationId,
        usage: currentUsage,
      };
    }

    // 2. Fetch authoritative plan parameters
    const plan = await entitlementEngine.getOrganizationPlan(params.organizationId);
    const includedAllowance = plan.id === 'PAYG' ? 0 : plan.limits.includedMonthlyOperations;
    const costPer1k = plan.costPer1kOpsCents;

    // 3. Atomically increment aggregate usage
    const updatedUsage = await db.incrementBillingUsage(
      params.organizationId,
      quantity,
      includedAllowance,
      costPer1k
    );

    // 4. Update velocity tracking for billing safety circuit breaker
    await billingSafetyEngine.recordVelocity(params.organizationId, quantity);

    // 5. Warn once when this operation crosses the near-limit threshold. Never delays or fails the operation.
    if (crossedUsageWarning(updatedUsage.operationCount - quantity, updatedUsage.operationCount, includedAllowance)) {
      notifyUsageLimitApproaching({
        organizationId: params.organizationId,
        planId: plan.id,
        planName: plan.name,
        includedAllowance,
        usage: updatedUsage,
      }).catch((err) => {
        console.warn(`[UsageMeter] Near-limit email failed for ${params.organizationId}: ${err.message}`);
      });
    }

    // 6. Try to deliver now; on failure the event stays pending for syncPendingUsageEvents.
    this.deliver(eventRecord.event).catch((err) => {
      console.warn(`[UsageMeter] Polar delivery deferred for ${operationId}: ${err.message}`);
    });

    return {
      success: true,
      isDuplicate: false,
      operationId,
      usage: updatedUsage,
    };
  }

  /** Sends one outbox event to Polar. Returns true once the event no longer needs delivery. */
  private async deliver(ev: BillingUsageEventRecord): Promise<boolean> {
    const customer = await db.getBillingCustomer(ev.organizationId);
    if (!customer?.polarCustomerId) {
      await db.markBillingUsageEventReported(ev.operationId, NOT_BILLABLE_NO_CUSTOMER);
      return true;
    }

    if (!this.deliverer) {
      // The Cloud module provides delivery to Polar. Without it there is nowhere to send.
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        this.deliverer = require('../cloud/usage-delivery').deliverUsageEventToPolar;
      } catch {
        return false;
      }
    }
    if (!this.deliverer) return false;
    const eventId = await this.deliverer(ev, customer.polarCustomerId);
    if (eventId === null) return false;
    await db.markBillingUsageEventReported(ev.operationId, eventId || undefined);
    return true;
  }

  /**
   * Retry pending outbox events. Safe to repeat: Polar skips external IDs it already has.
   */
  async syncPendingUsageEvents(organizationId?: string): Promise<{ reportedCount: number; failedCount: number }> {
    const pending = await db.getPendingBillingUsageEvents(organizationId, 100);
    let reportedCount = 0;
    let failedCount = 0;

    for (const ev of pending) {
      try {
        if (await this.deliver(ev)) reportedCount++;
        else failedCount++;
      } catch (err: any) {
        failedCount++;
        console.warn(`[UsageMeter] Failed to sync pending event ${ev.operationId}: ${err.message}`);
      }
    }

    return { reportedCount, failedCount };
  }

  /** Starts the background outbox retry loop (not in tests). */
  startBackgroundSync(intervalMs: number = 60_000): void {
    if (this.syncTimer || isTestEnv() || isSelfHosted()) return;
    this.syncTimer = setInterval(() => {
      this.syncPendingUsageEvents().catch((err) => {
        console.warn(`[UsageMeter] Background sync failed: ${err.message}`);
      });
    }, intervalMs);
    this.syncTimer.unref();
  }

  stopBackgroundSync(): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = null;
  }
}

export const usageMeter = new UsageMeter();
