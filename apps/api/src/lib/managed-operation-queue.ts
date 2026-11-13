import {
  OperationType,
  OperationStatus,
  CryptographicOperationRequest,
  CryptographicOperationResult,
  TenantContext,
  classifyFailure,
} from '@amaracus/crypto-core';
import { db, CryptographicOperationRecord } from './data-store';
import { managedConcurrencyLimiter } from './managed-concurrency-limiter';
import { operationObservability } from './operation-observability';
import { cryptographicRuntime } from './runtime-service';
import { providerCircuitBreaker } from './provider-circuit-breaker';

export interface QueuedOperationItem {
  operationId: string;
  organizationId: string;
  projectId?: string | null;
  environmentId?: string | null;
  operationType: OperationType | string;
  request: CryptographicOperationRequest;
  tenantContext: TenantContext;
  priority: 'HIGH' | 'NORMAL' | 'LOW';
  retryCount: number;
  maxRetries: number;
  enqueuedAt: Date;
  scheduledAt: Date;
  expiresAt?: Date | null;
  timeoutMs?: number;
  failoverAttempts?: number;
}

export class ManagedOperationQueue {
  private queue: QueuedOperationItem[] = [];
  private isProcessing = false;
  private isRunning = true;
  private activeWorkers = 0;
  private maxWorkers = 5;
  private checkInterval: NodeJS.Timeout | null = null;
  private zombieInterval: NodeJS.Timeout | null = null;
  private canceledOpIds = new Set<string>();

  constructor() {
    this.startWorkerLoop();
  }

  /**
   * Enqueue an operation for background execution.
   */
  async enqueue(item: QueuedOperationItem): Promise<void> {
    this.queue.push(item);
    // Sort so HIGH priority comes first, then by scheduledAt
    this.queue.sort((a, b) => {
      const priorityWeight = { HIGH: 3, NORMAL: 2, LOW: 1 };
      const weightDiff = (priorityWeight[b.priority] || 2) - (priorityWeight[a.priority] || 2);
      if (weightDiff !== 0) return weightDiff;
      return a.scheduledAt.getTime() - b.scheduledAt.getTime();
    });

    operationObservability.recordStatusTransition('QUEUED');
    await db.updateCryptographicOperation(item.operationId, {
      status: 'QUEUED',
      retryCount: item.retryCount,
    });
  }

  /**
   * Cancel an enqueued or in-flight operation.
   */
  async cancel(operationId: string, organizationId: string): Promise<boolean> {
    this.canceledOpIds.add(operationId);

    // Remove from in-memory queue if still waiting
    const idx = this.queue.findIndex(
      (item) => item.operationId === operationId && item.organizationId === organizationId
    );
    if (idx !== -1) {
      this.queue.splice(idx, 1);
    }

    const op = await db.getCryptographicOperation(operationId);
    if (!op || op.organizationId !== organizationId) return false;

    if (['COMPLETED', 'FAILED', 'TIMED_OUT', 'DEAD_LETTER', 'EXPIRED'].includes(op.status)) {
      return false; // Already reached terminal state
    }

    await db.updateCryptographicOperation(operationId, {
      status: 'CANCELED',
    });
    operationObservability.recordOperationCanceled(operationId, organizationId);
    return true;
  }

  /**
   * Get queue status and depth.
   */
  getQueueMetrics(): {
    depth: number;
    activeWorkers: number;
    maxWorkers: number;
    isProcessing: boolean;
  } {
    return {
      depth: this.queue.length,
      activeWorkers: this.activeWorkers,
      maxWorkers: this.maxWorkers,
      isProcessing: this.isProcessing,
    };
  }

  private startWorkerLoop(): void {
    if (!this.checkInterval) {
      this.checkInterval = setInterval(() => {
        this.processNextItems().catch((err) => {
          console.error('[ManagedOperationQueue Worker Error]', err);
        });
      }, 50);
    }

    if (!this.zombieInterval && process.env.NODE_ENV !== 'test') {
      this.zombieInterval = setInterval(() => {
        this.recoverZombieJobs().catch((err) => {
          console.error('[ManagedOperationQueue Zombie Recovery Error]', err);
        });
      }, 60000);
    }
  }

  /**
   * Recovers operations stuck in EXECUTING state due to process crashes or worker restarts.
   */
  async recoverZombieJobs(staleThresholdMs = 120000): Promise<number> {
    const olderThan = new Date(Date.now() - staleThresholdMs);
    const staleOps = await db.listStaleCryptographicOperations(['EXECUTING'], olderThan);
    let recoveredCount = 0;

    for (const op of staleOps) {
      const currentRetries = op.retryCount || 0;
      const maxRetries = 3;

      if (currentRetries < maxRetries) {
        const nextRetries = currentRetries + 1;
        await db.updateCryptographicOperation(op.id, {
          status: 'QUEUED',
          retryCount: nextRetries,
          error: {
            message: 'Recovered from unexpected worker termination or timeout',
            code: 'ZOMBIE_WORKER_RECOVERED',
            retryAttempt: nextRetries,
          },
        });

        if (op.request && this.isRunning) {
          this.queue.push({
            operationId: op.id,
            organizationId: op.organizationId,
            projectId: op.projectId,
            environmentId: op.environmentId,
            operationType: op.operationType,
            request: op.request,
            tenantContext: {
              organizationId: op.organizationId,
              projectId: op.projectId || undefined,
              environmentId: op.environmentId || undefined,
            },
            priority: (op.priority as any) || 'NORMAL',
            retryCount: nextRetries,
            maxRetries,
            enqueuedAt: new Date(),
            scheduledAt: new Date(Date.now() + 500),
          });
        }
        operationObservability.recordStatusTransition('QUEUED');
        recoveredCount++;
      } else {
        await db.updateCryptographicOperation(op.id, {
          status: 'DEAD_LETTER',
          error: {
            message: 'Job abandoned after repeated worker timeouts / failure to complete',
            code: 'ZOMBIE_RECOVERY_EXHAUSTED',
          },
        });
        operationObservability.recordOperationFailed({
          operationId: op.id,
          organizationId: op.organizationId,
          operationType: op.operationType,
          durationMs: 0,
          retries: currentRetries,
          isDeadLetter: true,
          error: 'ZOMBIE_RECOVERY_EXHAUSTED',
        });
        recoveredCount++;
      }
    }

    return recoveredCount;
  }


  /**
   * Process items from the queue up to maximum worker concurrency.
   */
  private async processNextItems(): Promise<void> {
    if (!this.isRunning) return;
    const now = Date.now();

    while (this.activeWorkers < this.maxWorkers && this.queue.length > 0) {
      const nextIndex = this.queue.findIndex((item) => item.scheduledAt.getTime() <= now);
      if (nextIndex === -1) break;

      const item = this.queue.splice(nextIndex, 1)[0];
      this.activeWorkers += 1;

      this.executeItem(item).finally(() => {
        this.activeWorkers = Math.max(0, this.activeWorkers - 1);
      });
    }
  }

  /**
   * Execute an individual queued operation.
   */
  private async executeItem(item: QueuedOperationItem): Promise<void> {
    const startTime = Date.now();

    // 1. Check if canceled
    if (this.canceledOpIds.has(item.operationId)) {
      this.canceledOpIds.delete(item.operationId);
      await db.updateCryptographicOperation(item.operationId, { status: 'CANCELED' });
      operationObservability.recordOperationCanceled(item.operationId, item.organizationId);
      return;
    }

    // 2. Check expiration / TTL
    if (item.expiresAt && Date.now() > item.expiresAt.getTime()) {
      await db.updateCryptographicOperation(item.operationId, { status: 'EXPIRED' });
      operationObservability.recordStatusTransition('EXPIRED');
      return;
    }

    // 3. Acquire concurrency slot
    const acquireResult = managedConcurrencyLimiter.tryAcquire(
      item.organizationId,
      item.operationType,
      item.request.algorithm
    );

    if (!acquireResult.allowed) {
      // Re-enqueue with small delay (200ms) to allow in-flight tasks to clear
      item.scheduledAt = new Date(Date.now() + 200);
      this.queue.push(item);
      return;
    }

    await db.updateCryptographicOperation(item.operationId, { status: 'EXECUTING' });
    operationObservability.recordStatusTransition('EXECUTING');

    try {
      const timeoutMs = item.timeoutMs || 30000;
      let timeoutHandle: NodeJS.Timeout;

      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          const timeoutErr: any = new Error(`Operation timed out after ${timeoutMs}ms`);
          timeoutErr.code = 'OPERATION_TIMEOUT';
          reject(timeoutErr);
        }, timeoutMs);
      });

      const providerId = (item.request as any)?.providerId || 'azure-keyvault';
      const execPromise = providerCircuitBreaker.execute(
        providerId,
        () =>
          cryptographicRuntime.execute(
            { ...item.request, operationId: item.operationId },
            item.tenantContext
          )
      );

      const result = await Promise.race([execPromise, timeoutPromise]).finally(() => {
        clearTimeout(timeoutHandle);
      });

      const durationMs = Date.now() - startTime;

      if (!result.success) {
        const failureErr: any = new Error(result.error?.message || 'Execution failed');
        failureErr.code = result.error?.code || 'OPERATION_FAILED';
        failureErr.statusCode = result.error?.statusCode || 500;
        failureErr.retryable = result.error?.retryable;
        await this.handleExecutionFailure(item, failureErr, durationMs);
        return;
      }

      // Sanitize result for persistence (no sensitive keys leaked)
      const sanitizedResult = this.sanitizeResult(result);

      await db.updateCryptographicOperation(item.operationId, {
        status: 'COMPLETED',
        durationMs,
        result: sanitizedResult,
        providerId: result.metadata?.providerId,
        algorithm: result.metadata?.algorithm,
      });

      operationObservability.recordOperationCompleted({
        operationId: item.operationId,
        organizationId: item.organizationId,
        operationType: item.operationType,
        algorithm: result.metadata?.algorithm,
        providerId: result.metadata?.providerId,
        durationMs,
        retries: item.retryCount,
      });
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      await this.handleExecutionFailure(item, err, durationMs);
    } finally {
      managedConcurrencyLimiter.release(
        item.organizationId,
        item.operationType,
        item.request.algorithm
      );
    }
  }

  /**
   * Handle failure with safe retry, jitter backoff, or dead-letter storage.
   */
  private async handleExecutionFailure(
    item: QueuedOperationItem,
    err: any,
    durationMs: number
  ): Promise<void> {
    const isTimeout = err?.code === 'OPERATION_TIMEOUT' || err?.message?.includes('timed out');
    if (isTimeout) {
      await db.updateCryptographicOperation(item.operationId, {
        status: 'TIMED_OUT',
        durationMs,
        error: { message: 'Operation timed out', code: 'OPERATION_TIMEOUT' },
      });
      operationObservability.recordOperationTimedOut(item.operationId, item.organizationId);
      return;
    }

    const failure = classifyFailure(err);
    const sanitizedErrorMsg = this.sanitizeErrorMessage(err?.message || 'Operation failed');

    if (failure.retryable && item.retryCount < item.maxRetries) {
      // Bounded retry with exponential backoff and jitter
      const nextAttempt = item.retryCount + 1;
      const baseDelay = Math.min(5000, Math.pow(2, nextAttempt) * 100);
      const jitter = Math.floor(Math.random() * 50);
      const delayMs = baseDelay + jitter;

      item.retryCount = nextAttempt;
      item.scheduledAt = new Date(Date.now() + delayMs);

      await db.updateCryptographicOperation(item.operationId, {
        status: 'QUEUED',
        retryCount: nextAttempt,
        error: { message: sanitizedErrorMsg, code: failure.code, retryAttempt: nextAttempt },
      });

      this.queue.push(item);
    } else if (item.retryCount >= item.maxRetries) {
      // Retries exhausted: transfer to Dead-Letter Queue
      await db.updateCryptographicOperation(item.operationId, {
        status: 'DEAD_LETTER',
        durationMs,
        retryCount: item.retryCount,
        error: {
          message: sanitizedErrorMsg,
          code: 'EXHAUSTED_RETRIES',
          retries: item.retryCount,
        },
      });

      operationObservability.recordOperationFailed({
        operationId: item.operationId,
        organizationId: item.organizationId,
        operationType: item.operationType,
        algorithm: item.request.algorithm,
        durationMs,
        retries: item.retryCount,
        isDeadLetter: true,
        error: sanitizedErrorMsg,
      });
    } else {
      // Non-retryable failure (validation error, policy violation, key not found)
      await db.updateCryptographicOperation(item.operationId, {
        status: 'FAILED',
        durationMs,
        retryCount: item.retryCount,
        error: { message: sanitizedErrorMsg, code: failure.code },
      });

      operationObservability.recordOperationFailed({
        operationId: item.operationId,
        organizationId: item.organizationId,
        operationType: item.operationType,
        algorithm: item.request.algorithm,
        durationMs,
        retries: item.retryCount,
        isDeadLetter: false,
        error: sanitizedErrorMsg,
      });
    }
  }

  /**
   * Strict Zero Secret Leakage sanitizer for results.
   */
  private sanitizeResult(result: CryptographicOperationResult): any {
    const sanitized: any = {
      operationId: result.operationId,
      status: result.status,
      algorithm: result.metadata?.algorithm,
      providerId: result.metadata?.providerId,
      durationMs: result.metadata?.durationMs,
      executedAt: result.metadata?.timestamp,
      ...(result.data && typeof result.data === 'object' ? result.data : { data: result.data }),
    };

    if (result.metadata) {
      sanitized.metadata = {
        keyId: result.metadata.keyId,
        keyVersion: result.metadata.keyVersion,
        isHardwareBacked: result.metadata.isHardwareBacked,
        isCustomerManaged: result.metadata.isCustomerManaged,
        failoverOccurred: result.metadata.failoverOccurred,
      };
    }

    return sanitized;
  }

  /**
   * Sanitizes error message strings to prevent accidental leakage of hex or base64 keys.
   */
  private sanitizeErrorMessage(msg: string): string {
    // Redact long hex / base64 strings that look like raw keys
    return msg.replace(/[0-9a-fA-F]{32,}/g, '[REDACTED]').replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[REDACTED]');
  }

  /**
   * Graceful shutdown: clear timer and drain queue.
   */
  async shutdown(): Promise<void> {
    this.isRunning = false;
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
    if (this.zombieInterval) {
      clearInterval(this.zombieInterval);
      this.zombieInterval = null;
    }
  }

  /**
   * Test fixture helper: clear queue.
   */
  reset(): void {
    this.queue = [];
    this.canceledOpIds.clear();
    this.activeWorkers = 0;
  }
}

export const managedOperationQueue = new ManagedOperationQueue();
