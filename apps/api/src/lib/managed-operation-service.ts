import crypto from 'crypto';
import {
  CryptographicOperationRequest,
  CryptographicOperationResult,
  TenantContext,
  OperationType,
  OperationStatus,
  classifyFailure,
  providerRouter,
} from '@amaracus/crypto-core';
import { db, CryptographicOperationRecord } from './data-store';
import { managedConcurrencyLimiter } from './managed-concurrency-limiter';
import { managedOperationQueue } from './managed-operation-queue';
import { operationObservability } from './operation-observability';
import { billingSafetyEngine } from './billing-safety';
import { entitlementEngine } from './entitlement-engine';
import { cryptographicRuntime, keyResolver } from './runtime-service';
import { policyService } from './policy-service';

export interface SubmitOperationOptions {
  mode?: 'sync' | 'async';
  priority?: 'HIGH' | 'NORMAL' | 'LOW';
  timeoutMs?: number;
  maxRetries?: number;
  ttlSeconds?: number;
  allowQueueFallback?: boolean;
}

export interface SubmitOperationResponse {
  operationId: string;
  status: OperationStatus | string;
  mode: 'sync' | 'async';
  pollUrl?: string;
  result?: any;
  durationMs?: number;
  error?: any;
  expiresAt?: Date | null;
}

export class ManagedOperationService {
  /**
   * Universal entry point for managed cryptographic operations (Sync and Async).
   */
  async submitOperation(
    request: CryptographicOperationRequest,
    context: TenantContext,
    options?: SubmitOperationOptions
  ): Promise<SubmitOperationResponse> {
    const orgId = context.organizationId;

    // 1. Idempotency Check
    if (request.idempotencyKey) {
      const existing = await db.getCryptographicOperationByIdempotencyKey(
        orgId,
        request.idempotencyKey
      );
      if (existing) {
        if (existing.status === 'COMPLETED') {
          return {
            operationId: existing.id,
            status: existing.status,
            mode: 'sync',
            result: existing.result,
            durationMs: existing.durationMs || undefined,
            expiresAt: existing.expiresAt,
          };
        }
        if (['FAILED', 'TIMED_OUT', 'CANCELED', 'DEAD_LETTER', 'EXPIRED'].includes(existing.status)) {
          return {
            operationId: existing.id,
            status: existing.status,
            mode: 'sync',
            error: existing.error,
            durationMs: existing.durationMs || undefined,
            expiresAt: existing.expiresAt,
          };
        }
        // In-flight operation
        return {
          operationId: existing.id,
          status: existing.status,
          mode: 'async',
          pollUrl: `/v1/operations/${existing.id}`,
          expiresAt: existing.expiresAt,
        };
      }
    }

    // 2. Commercial / Billing Safety Check
    const plan = await entitlementEngine.getOrganizationPlan(orgId);
    const safetyResult = await billingSafetyEngine.evaluateSafety(orgId, 1, plan);
    if (!safetyResult.allowed) {
      const errorObj = {
        code: safetyResult.status === 'SUSPENDED' ? 'CIRCUIT_BREAKER_SUSPENDED' : 'BILLING_SAFETY_HALT',
        message: safetyResult.reason || 'Cryptographic operation halted due to billing safety limits.',
      };
      throw Object.assign(new Error(errorObj.message), { statusCode: 429, details: errorObj });
    }

    // 2.5 Phase 15 Cryptographic Policy Evaluation (Fail Closed)
    let resolvedKeyRef: any = undefined;
    let keyAgeDays: number | undefined = undefined;
    let keyCreatedAt: Date | undefined = undefined;
    if (request.keyId) {
      const dbKey = (await db.getKey(orgId, request.keyId)) || (keyResolver ? await keyResolver.resolveKey(request.keyId, orgId, context.projectId, context.environmentId) : null);
      if (dbKey) {
        resolvedKeyRef = dbKey;
        const createdRaw = (dbKey as any).createdAt || (dbKey as any).metadata?.createdAt;
        if (createdRaw) {
          keyCreatedAt = new Date(createdRaw);
          keyAgeDays = Math.floor((Date.now() - keyCreatedAt.getTime()) / (1000 * 60 * 60 * 24));
        }
      }
    }

    const policyDecision = await policyService.evaluate({
      organizationId: orgId,
      projectId: context.projectId,
      environmentId: context.environmentId,
      operationType: request.type as any,
      algorithm: (request.algorithm || resolvedKeyRef?.algorithm)?.toString(),
      keyId: request.keyId || resolvedKeyRef?.id,
      keyReference: resolvedKeyRef,
      keyCreatedAt,
      keyAgeDays,
      complianceProfile: request.policy as any,
    }, request.policy);

    if (policyDecision.decision !== 'ALLOW') {
      const errCode =
        policyDecision.decision === 'REQUIRE_KEY_ROTATION' ? 'KEY_ROTATION_REQUIRED' :
        policyDecision.decision === 'REQUIRE_STRONGER_ALGORITHM' ? 'INSUFFICIENT_SECURITY' :
        policyDecision.decision === 'REQUIRE_APPROVED_PROVIDER' ? 'PROVIDER_NOT_APPROVED' :
        'POLICY_VIOLATION';
      const errorObj = {
        code: errCode,
        message: `Cryptographic policy denied operation: ${policyDecision.reasons.join('; ')}`,
        decision: policyDecision.decision,
        reasons: policyDecision.reasons,
        requirements: policyDecision.requirements,
        warnings: policyDecision.warnings,
        recommendations: policyDecision.recommendations,
      };
      throw Object.assign(new Error(errorObj.message), { code: errCode, statusCode: 403, details: errorObj });
    }

    // 3. Determine Execution Mode
    const isHeavy = managedConcurrencyLimiter.isHeavyWorkload(request.type, request.algorithm);
    const mode: 'sync' | 'async' = options?.mode === 'async' || isHeavy ? 'async' : 'sync';

    const operationId = request.operationId || `op_${crypto.randomUUID()}`;
    const ttlSeconds = options?.ttlSeconds || (mode === 'async' ? 86400 : 3600);
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

    // 4. Create authoritative operation record
    await db.createCryptographicOperation({
      id: operationId,
      requestId: request.requestId || `req_${crypto.randomUUID()}`,
      idempotencyKey: request.idempotencyKey || null,
      organizationId: orgId,
      projectId: context.projectId || null,
      environmentId: context.environmentId || null,
      operationType: request.type,
      algorithm: request.algorithm || null,
      keyId: request.keyId || null,
      status: 'REQUESTED',
      retryCount: 0,
      expiresAt,
    });
    operationObservability.recordStatusTransition('REQUESTED');

    // 5. Asynchronous Path: Enqueue and return 202 Accepted handle
    if (mode === 'async') {
      await managedOperationQueue.enqueue({
        operationId,
        organizationId: orgId,
        projectId: context.projectId,
        environmentId: context.environmentId,
        operationType: request.type,
        request,
        tenantContext: context,
        priority: options?.priority || 'NORMAL',
        retryCount: 0,
        maxRetries: options?.maxRetries ?? 3,
        enqueuedAt: new Date(),
        scheduledAt: new Date(),
        expiresAt,
        timeoutMs: options?.timeoutMs || 60000,
      });

      return {
        operationId,
        status: 'QUEUED',
        mode: 'async',
        pollUrl: `/v1/operations/${operationId}`,
        expiresAt,
      };
    }

    // 6. Synchronous Path: Execute with concurrency lock, timeout, and failover
    const acquireResult = managedConcurrencyLimiter.tryAcquire(
      orgId,
      request.type,
      request.algorithm
    );

    if (!acquireResult.allowed) {
      if (options?.allowQueueFallback) {
        // Degrade gracefully to async queue
        await managedOperationQueue.enqueue({
          operationId,
          organizationId: orgId,
          projectId: context.projectId,
          environmentId: context.environmentId,
          operationType: request.type,
          request,
          tenantContext: context,
          priority: options?.priority || 'NORMAL',
          retryCount: 0,
          maxRetries: options?.maxRetries ?? 3,
          enqueuedAt: new Date(),
          scheduledAt: new Date(),
          expiresAt,
          timeoutMs: options?.timeoutMs || 30000,
        });

        return {
          operationId,
          status: 'QUEUED',
          mode: 'async',
          pollUrl: `/v1/operations/${operationId}`,
          expiresAt,
        };
      }

      // Reject synchronous request with 429
      const limitErr = new Error(`Concurrency limit exceeded: ${acquireResult.reason}`);
      (limitErr as any).statusCode = 429;
      (limitErr as any).code = 'CONCURRENCY_LIMIT_EXCEEDED';
      throw limitErr;
    }

    const startTime = Date.now();
    await db.updateCryptographicOperation(operationId, { status: 'EXECUTING' });
    operationObservability.recordStatusTransition('EXECUTING');

    try {
      const timeoutMs = options?.timeoutMs || 30000;
      let timeoutHandle: NodeJS.Timeout;

      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          const timeoutErr: any = new Error(`Operation timed out after ${timeoutMs}ms`);
          timeoutErr.code = 'OPERATION_TIMEOUT';
          reject(timeoutErr);
        }, timeoutMs);
      });

      let failoverOccurred = false;
      let result: CryptographicOperationResult;

      result = await Promise.race([
        cryptographicRuntime.execute({ ...request, operationId }, context),
        timeoutPromise,
      ]).finally(() => {
        clearTimeout(timeoutHandle);
      });

      if (!result.success) {
        // Evaluate Safe Provider Failover
        const failure = classifyFailure(result.error);
        if (failure.retryable) {
          const keyRef = request.keyId ? await keyResolver.resolveKey(request.keyId, orgId) : null;
          const primaryProvider = providerRouter.getProvider(
            result.metadata?.providerId || keyRef?.provider || 'LOCAL_DEV'
          );
          const fallbackProvider = primaryProvider
            ? providerRouter.resolveFailoverProvider(primaryProvider, request, keyRef, context)
            : null;

          if (fallbackProvider) {
            failoverOccurred = true;
            const fallbackResult = await cryptographicRuntime.execute(
              {
                ...request,
                operationId,
                metadata: { ...(request.metadata || {}), forcedProviderId: fallbackProvider.id },
              },
              context
            );

            if (fallbackResult.success) {
              result = fallbackResult;
            } else {
              const execErr: any = new Error(fallbackResult.error?.message || 'Failover execution failed');
              execErr.code = fallbackResult.error?.code || 'OPERATION_FAILED';
              execErr.statusCode = fallbackResult.error?.statusCode || 500;
              throw execErr;
            }
          } else {
            const execErr: any = new Error(result.error?.message || 'Operation failed');
            execErr.code = result.error?.code || 'OPERATION_FAILED';
            execErr.statusCode = result.error?.statusCode || 500;
            throw execErr;
          }
        } else {
          const execErr: any = new Error(result.error?.message || 'Operation failed');
          execErr.code = result.error?.code || 'OPERATION_FAILED';
          execErr.statusCode = result.error?.statusCode || 500;
          throw execErr;
        }
      }

      const durationMs = Date.now() - startTime;
      const sanitized = this.sanitizeResult(result);

      await db.updateCryptographicOperation(operationId, {
        status: 'COMPLETED',
        durationMs,
        result: sanitized,
        providerId: result.metadata?.providerId,
        algorithm: result.metadata?.algorithm,
      });

      operationObservability.recordOperationCompleted({
        operationId,
        organizationId: orgId,
        operationType: request.type,
        algorithm: result.metadata?.algorithm,
        providerId: result.metadata?.providerId,
        durationMs,
        retries: 0,
        failoverOccurred,
      });

      return {
        operationId,
        status: 'COMPLETED',
        mode: 'sync',
        result: sanitized,
        durationMs,
        expiresAt,
      };
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      const isTimeout = err?.code === 'OPERATION_TIMEOUT' || err?.message?.includes('timed out');
      const finalStatus = isTimeout ? 'TIMED_OUT' : 'FAILED';
      const sanitizedMsg = this.sanitizeErrorMessage(err?.message || 'Operation failed');

      await db.updateCryptographicOperation(operationId, {
        status: finalStatus,
        durationMs,
        error: { message: sanitizedMsg, code: err?.code || 'OPERATION_FAILED' },
      });

      if (isTimeout) {
        operationObservability.recordOperationTimedOut(operationId, orgId);
      } else {
        operationObservability.recordOperationFailed({
          operationId,
          organizationId: orgId,
          operationType: request.type,
          algorithm: request.algorithm,
          durationMs,
          retries: 0,
          isDeadLetter: false,
          error: sanitizedMsg,
        });
      }

      throw err;
    } finally {
      managedConcurrencyLimiter.release(orgId, request.type, request.algorithm);
    }
  }

  /**
   * Retrieve an operation record by ID with strict tenant isolation (IDOR protection).
   */
  async getOperation(
    operationId: string,
    organizationId: string
  ): Promise<CryptographicOperationRecord | null> {
    const op = await db.getCryptographicOperation(operationId);
    if (!op || op.organizationId !== organizationId) {
      return null;
    }
    return op;
  }

  /**
   * Retrieve the execution result or status polling details of an operation.
   */
  async getOperationResult(
    operationId: string,
    organizationId: string
  ): Promise<{
    operationId: string;
    status: string;
    result?: any;
    error?: any;
    retryAfterMs?: number;
    durationMs?: number;
  }> {
    const op = await this.getOperation(operationId, organizationId);
    if (!op) {
      const notFoundErr: any = new Error('Cryptographic operation not found');
      notFoundErr.statusCode = 404;
      notFoundErr.code = 'NOT_FOUND';
      throw notFoundErr;
    }

    if (op.status === 'COMPLETED') {
      return {
        operationId: op.id,
        status: op.status,
        result: op.result,
        durationMs: op.durationMs || undefined,
      };
    }

    if (['FAILED', 'TIMED_OUT', 'CANCELED', 'DEAD_LETTER', 'EXPIRED'].includes(op.status)) {
      return {
        operationId: op.id,
        status: op.status,
        error: op.error,
        durationMs: op.durationMs || undefined,
      };
    }

    // In-flight or queued
    return {
      operationId: op.id,
      status: op.status,
      retryAfterMs: 500,
    };
  }

  /**
   * Cancel an enqueued or active operation.
   */
  async cancelOperation(
    operationId: string,
    organizationId: string
  ): Promise<{ success: boolean; status: string }> {
    const op = await this.getOperation(operationId, organizationId);
    if (!op) {
      const notFoundErr: any = new Error('Cryptographic operation not found');
      notFoundErr.statusCode = 404;
      throw notFoundErr;
    }

    if (['COMPLETED', 'FAILED', 'TIMED_OUT', 'DEAD_LETTER', 'EXPIRED'].includes(op.status)) {
      return { success: false, status: op.status };
    }

    const success = await managedOperationQueue.cancel(operationId, organizationId);
    return { success, status: 'CANCELED' };
  }

  /**
   * List operations for an organization with optional status and type filters.
   */
  async listOperations(
    organizationId: string,
    options?: { limit?: number; offset?: number; status?: string; operationType?: string }
  ): Promise<CryptographicOperationRecord[]> {
    return db.listCryptographicOperations(organizationId, options);
  }

  /**
   * Aggregated operational metrics across concurrency, queue, and telemetry.
   */
  async getMetrics(organizationId?: string): Promise<any> {
    const queueMetrics = managedOperationQueue.getQueueMetrics();
    const concurrencyMetrics = managedConcurrencyLimiter.getMetrics(organizationId);
    const telemetry = operationObservability.getMetricsSummary(organizationId);

    return {
      queue: queueMetrics,
      concurrency: concurrencyMetrics,
      telemetry,
      timestamp: new Date().toISOString(),
    };
  }

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

  private sanitizeErrorMessage(msg: string): string {
    return msg.replace(/[0-9a-fA-F]{32,}/g, '[REDACTED]').replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[REDACTED]');
  }
}

export const managedOperationService = new ManagedOperationService();
