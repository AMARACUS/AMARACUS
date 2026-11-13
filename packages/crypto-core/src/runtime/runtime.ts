/**
 * AMARACUS Cryptographic Infrastructure — Cryptographic Runtime
 *
 * Central execution engine coordinating:
 * Application/API
 *      ↓
 * Authentication / Tenant Context
 *      ↓
 * Operation Lifecycle (REQUESTED → VALIDATING → AUTHORIZING → RESOLVING → EXECUTING → COMPLETED)
 *      ↓
 * Policy Evaluation
 *      ↓
 * Key Resolution (Logical KeyReference decoupling)
 *      ↓
 * Provider Routing & Capability Check
 *      ↓
 * Provider Execution (Local, Azure KV, Azure HSM, BYOK, PQC, Advanced)
 *      ↓
 * Standardized Envelope Result
 *      ↓
 * Structured Audit & Observability (Zero Secret Exposure)
 */

import crypto from 'crypto';
import {
  CryptographicOperationRequest,
  CryptographicOperationResult,
  OperationStatus,
  OperationType,
  CryptographicOperationError,
} from './operation-model';
import { TenantContext, ContextValidator } from './context';
import { KeyReference, KeyResolver } from './key-reference';
import { selectKeyVersion } from './key-version';
import { CryptographicProviderRouter, providerRouter } from './provider-router';
import { CryptographicPolicyEvaluator, CryptographicPolicy } from './policy-abstraction';
import { CryptographicPolicyEngine } from '../policy-engine';
import { CryptoEngineError } from '../errors';

export interface AuditSink {
  logOperation(event: {
    operationId: string;
    requestId: string;
    action: string;
    organizationId: string;
    projectId?: string | null;
    environmentId?: string | null;
    actorId?: string | null;
    providerId: string;
    algorithm?: string | null;
    keyId?: string | null;
    status: 'SUCCESS' | 'FAILED';
    durationMs: number;
    error?: string;
  }): Promise<void>;
}

export interface IdempotencyStore {
  get(key: string): Promise<CryptographicOperationResult | null>;
  set(key: string, result: CryptographicOperationResult, ttlSeconds?: number): Promise<void>;
}

// Results of these operations contain plaintext, shared secrets or private keys,
// so they are never stored in the idempotency cache.
const NON_CACHEABLE_OPERATIONS = new Set<OperationType>([
  'DECRYPT',
  'UNWRAP_KEY',
  'KEY_AGREEMENT',
  'KEM_KEYGEN',
  'KEM_ENCAPSULATE',
  'KEM_DECAPSULATE',
]);

function scopedIdempotencyKey(context: TenantContext, request: CryptographicOperationRequest): string | null {
  if (!request.idempotencyKey || NON_CACHEABLE_OPERATIONS.has(request.type)) return null;
  return [
    context.organizationId,
    context.projectId || '-',
    context.environmentId || '-',
    request.type,
    request.idempotencyKey,
  ].join('\u0000');
}

export interface OperationStateObserver {
  onTransition(operationId: string, status: OperationStatus, metadata?: Record<string, any>): void | Promise<void>;
}

export class CryptographicRuntime {
  private keyResolver?: KeyResolver;
  private auditSink?: AuditSink;
  private idempotencyStore?: IdempotencyStore;
  private stateObserver?: OperationStateObserver;

  constructor(
    private readonly router: CryptographicProviderRouter = providerRouter,
    options?: {
      keyResolver?: KeyResolver;
      auditSink?: AuditSink;
      idempotencyStore?: IdempotencyStore;
      stateObserver?: OperationStateObserver;
    }
  ) {
    if (options) {
      this.keyResolver = options.keyResolver;
      this.auditSink = options.auditSink;
      this.idempotencyStore = options.idempotencyStore;
      this.stateObserver = options.stateObserver;
    }
  }

  public setKeyResolver(resolver: KeyResolver): void {
    this.keyResolver = resolver;
  }

  public setAuditSink(sink: AuditSink): void {
    this.auditSink = sink;
  }

  public setIdempotencyStore(store: IdempotencyStore): void {
    this.idempotencyStore = store;
  }

  public setStateObserver(observer: OperationStateObserver): void {
    this.stateObserver = observer;
  }

  /**
   * Universal Execution Pipeline
   */
  public async execute<TData = any>(
    request: CryptographicOperationRequest,
    context: TenantContext
  ): Promise<CryptographicOperationResult<TData>> {
    const startTime = Date.now();
    let currentStatus: OperationStatus = 'REQUESTED';

    const operationId = request.operationId || `op_${crypto.randomUUID()}`;
    const requestId = request.requestId || `req_${crypto.randomUUID()}`;

    const notifyTransition = async (status: OperationStatus, meta?: Record<string, any>) => {
      currentStatus = status;
      if (this.stateObserver) {
        try {
          await this.stateObserver.onTransition(operationId, status, {
            organizationId: context.organizationId,
            projectId: context.projectId,
            environmentId: context.environmentId,
            type: request.type,
            algorithm: request.algorithm,
            keyId: request.keyId,
            ...meta,
          });
        } catch {}
      }
    };

    await notifyTransition('REQUESTED');

    try {
      // 1. Validate Tenant Context (VALIDATING) before any cache lookup
      await notifyTransition('VALIDATING');
      ContextValidator.validate(context);

      // 2. Idempotency Check, scoped to the tenant and operation
      const idempotencyCacheKey = scopedIdempotencyKey(context, request);
      if (idempotencyCacheKey && this.idempotencyStore) {
        const cached = await this.idempotencyStore.get(idempotencyCacheKey);
        if (cached) {
          return {
            ...cached,
            operationId,
            requestId,
          } as CryptographicOperationResult<TData>;
        }
      }

      if (!request.type || typeof request.type !== 'string') {
        throw new CryptoEngineError('INVALID_REQUEST', 'Operation type is required.', 400);
      }
      if (request.params == null) {
        request = { ...request, params: {} };
      }

      // 3. Resolve Key Reference (RESOLVING)
      await notifyTransition('RESOLVING');
      let resolvedKeyRef: KeyReference | null = request.keyReference || null;
      if (!resolvedKeyRef && request.keyId && this.keyResolver) {
        resolvedKeyRef = await this.keyResolver.resolveKey(
          request.keyId,
          context.organizationId,
          context.projectId,
          context.environmentId
        );
        if (!resolvedKeyRef) {
          throw new CryptoEngineError('KEY_NOT_FOUND', `Key '${request.keyId}' not found within organization.`, 404);
        }
      }
      if (resolvedKeyRef) {
        resolvedKeyRef = selectKeyVersion(resolvedKeyRef, request.type, request.params?.version);
      }

      const effectiveAlgorithm = (
        request.algorithm ||
        resolvedKeyRef?.algorithm ||
        (request.params && request.params.algorithm) ||
        'AES-256-GCM'
      ).toString();

      // 4. Policy Evaluation (AUTHORIZING)
      await notifyTransition('AUTHORIZING');

      // Authoritative Phase 15 Cryptographic Policy Engine Evaluation
      const keyCreatedDate = resolvedKeyRef?.metadata?.createdAt
        ? new Date(resolvedKeyRef.metadata.createdAt)
        : undefined;
      const keyAgeDays = keyCreatedDate
        ? Math.floor((Date.now() - keyCreatedDate.getTime()) / (1000 * 60 * 60 * 24))
        : undefined;

      const policyDecision = CryptographicPolicyEngine.evaluate({
        organizationId: context.organizationId,
        projectId: context.projectId,
        environmentId: context.environmentId,
        operationType: request.type as any,
        algorithm: effectiveAlgorithm,
        keyId: request.keyId || resolvedKeyRef?.id,
        keyReference: resolvedKeyRef,
        keyCreatedAt: keyCreatedDate,
        keyAgeDays,
        complianceProfile: request.policy as any,
      });

      if (policyDecision.decision !== 'ALLOW') {
        const errorMsg = `Policy enforcement denied operation: ${policyDecision.reasons.join('; ')}`;
        const errorCode =
          policyDecision.decision === 'REQUIRE_KEY_ROTATION' ? 'KEY_ROTATION_REQUIRED' :
          policyDecision.decision === 'REQUIRE_STRONGER_ALGORITHM' ? 'INSUFFICIENT_SECURITY' :
          policyDecision.decision === 'REQUIRE_APPROVED_PROVIDER' ? 'PROVIDER_NOT_APPROVED' :
          'POLICY_DENIED';
        throw new CryptoEngineError(
          errorCode,
          errorMsg,
          403,
          {
            decision: policyDecision.decision,
            reasons: policyDecision.reasons,
            requirements: policyDecision.requirements,
            warnings: policyDecision.warnings,
            recommendations: policyDecision.recommendations,
          }
        );
      }

      // Legacy compatibility check if request.policy is specified
      if (request.policy) {
        const policy: CryptographicPolicy = request.policy === 'FIPS_COMPLIANT'
          ? CryptographicPolicyEvaluator.FIPS_COMPLIANT_POLICY
          : request.policy === 'PQC_PREFERRED'
          ? CryptographicPolicyEvaluator.PQC_PREFERRED_POLICY
          : CryptographicPolicyEvaluator.DEFAULT_SECURE_POLICY;

        CryptographicPolicyEvaluator.assertAllowed(policy, request.type, effectiveAlgorithm, resolvedKeyRef);
      }

      // 5. Provider Routing & Capability Check
      const provider = await this.router.route(request, resolvedKeyRef, context);
      if (!provider.supportsOperation(request.type, effectiveAlgorithm)) {
        throw new CryptoEngineError(
          'PROVIDER_CAPABILITY_MISSING',
          `Provider '${provider.name}' does not support operation '${request.type}' with algorithm '${effectiveAlgorithm}'.`,
          400
        );
      }

      // 6. Execution (EXECUTING)
      await notifyTransition('EXECUTING', { providerId: provider.id });
      let executionData: any;

      switch (request.type) {
        case 'ENCRYPT': {
          const pt = Buffer.isBuffer(request.params.plaintext)
            ? request.params.plaintext
            : Buffer.from(request.params.plaintext || '', request.params.plaintextEncoding || 'utf8');
          const aad = request.params.aad
            ? Buffer.isBuffer(request.params.aad)
              ? request.params.aad
              : Buffer.from(request.params.aad, request.params.aadEncoding || 'utf8')
            : undefined;

          executionData = await provider.encrypt({
            keyReference: resolvedKeyRef,
            key: request.params.key,
            keyEncoding: request.params.keyEncoding,
            plaintext: pt,
            algorithm: effectiveAlgorithm,
            aad,
            version: request.params.version,
          });
          break;
        }

        case 'DECRYPT': {
          executionData = await provider.decrypt({
            keyReference: resolvedKeyRef,
            key: request.params.key,
            keyEncoding: request.params.keyEncoding,
            envelope: request.params.envelope,
            algorithm: effectiveAlgorithm,
            version: request.params.version,
          });
          // Return as utf8 string if requested or buffer
          if (Buffer.isBuffer(executionData) && request.params.outputEncoding !== 'buffer') {
            executionData = executionData.toString(request.params.outputEncoding || 'utf8');
          }
          break;
        }

        case 'SIGN':
        case 'PQC_SIGN': {
          const dataBuf = Buffer.isBuffer(request.params.data)
            ? request.params.data
            : Buffer.from(request.params.data || '', 'utf8');

          const sigBuf = await provider.sign({
            keyReference: resolvedKeyRef,
            privateKey: request.params.privateKey,
            data: dataBuf,
            algorithm: effectiveAlgorithm,
            version: request.params.version,
          });
          executionData = {
            signature: sigBuf.toString(request.params.encoding || 'hex'),
            encoding: request.params.encoding || 'hex',
            algorithm: effectiveAlgorithm,
          };
          break;
        }

        case 'VERIFY':
        case 'PQC_VERIFY': {
          const dataBuf = Buffer.isBuffer(request.params.data)
            ? request.params.data
            : Buffer.from(request.params.data || '', 'utf8');
          const sigBuf = Buffer.isBuffer(request.params.signature)
            ? request.params.signature
            : Buffer.from(request.params.signature || '', request.params.encoding || 'hex');

          executionData = await provider.verify({
            keyReference: resolvedKeyRef,
            publicKey: request.params.publicKey,
            data: dataBuf,
            signature: sigBuf,
            algorithm: effectiveAlgorithm,
            version: request.params.version,
          });
          break;
        }

        case 'HASH': {
          if (!provider.hash) {
            throw new CryptoEngineError('UNSUPPORTED_OPERATION', `Provider '${provider.name}' does not implement hashing.`);
          }
          const dataBuf = Buffer.isBuffer(request.params.data)
            ? request.params.data
            : Buffer.from(request.params.data || '', 'utf8');
          const digestBuf = await provider.hash(dataBuf, effectiveAlgorithm);
          executionData = {
            digest: digestBuf.toString(request.params.outputEncoding || 'hex'),
            algorithm: effectiveAlgorithm,
          };
          break;
        }

        case 'HMAC': {
          if (!provider.hmac) {
            throw new CryptoEngineError('UNSUPPORTED_OPERATION', `Provider '${provider.name}' does not implement HMAC.`);
          }
          const keyBuf = Buffer.isBuffer(request.params.key)
            ? request.params.key
            : Buffer.from(request.params.key || '', request.params.keyEncoding || 'base64');
          const dataBuf = Buffer.isBuffer(request.params.data)
            ? request.params.data
            : Buffer.from(request.params.data || '', 'utf8');
          const macBuf = await provider.hmac(keyBuf, dataBuf, effectiveAlgorithm);
          executionData = {
            mac: macBuf.toString(request.params.macEncoding || 'hex'),
            algorithm: effectiveAlgorithm,
          };
          break;
        }

        case 'KEY_GEN':
        case 'KEM_KEYGEN': {
          if (!provider.generateKey) {
            throw new CryptoEngineError('UNSUPPORTED_OPERATION', `Provider '${provider.name}' does not implement key generation.`);
          }
          executionData = await provider.generateKey({
            name: request.params.name || `key_${Date.now()}`,
            algorithm: effectiveAlgorithm,
            purpose: request.params.purpose || 'ENCRYPTION',
            isHsm: request.params.isHsm,
            metadata: request.params.metadata,
          });
          break;
        }

        case 'KEY_ROTATION': {
          if (!provider.rotateKey || !resolvedKeyRef) {
            throw new CryptoEngineError('UNSUPPORTED_OPERATION', `Key rotation requires a managed KeyReference and supporting provider.`);
          }
          executionData = await provider.rotateKey(resolvedKeyRef);
          break;
        }

        default:
          throw new CryptoEngineError('UNSUPPORTED_OPERATION', `Operation type '${request.type}' is not supported by runtime.`);
      }

      // 7. Completed State & Result Construction (COMPLETED)
      const durationMs = Date.now() - startTime;
      await notifyTransition('COMPLETED', { durationMs });

      const finalResult: CryptographicOperationResult<TData> = {
        success: true,
        operationId,
        requestId,
        status: 'COMPLETED',
        type: request.type,
        data: executionData,
        metadata: {
          durationMs,
          providerId: provider.id,
          providerName: provider.name,
          algorithm: effectiveAlgorithm,
          keyId: resolvedKeyRef?.id || request.keyId || null,
          keyVersion: resolvedKeyRef ? Number(resolvedKeyRef.currentVersion) || null : null,
          isHardwareBacked: resolvedKeyRef?.isHsmBacked || provider.capabilities.hardwareBacked === true,
          isCustomerManaged: resolvedKeyRef?.isCustomerManaged || false,
          isPqc: provider.capabilities.pqc === true,
          timestamp: new Date().toISOString(),
        },
      };

      // 8. Audit Logging (Zero Secrets Exchanged)
      if (this.auditSink) {
        this.auditSink.logOperation({
          operationId,
          requestId,
          action: `crypto.${request.type.toLowerCase()}`,
          organizationId: context.organizationId,
          projectId: context.projectId,
          environmentId: context.environmentId,
          actorId: context.actorId,
          providerId: provider.id,
          algorithm: effectiveAlgorithm,
          keyId: resolvedKeyRef?.id || request.keyId || null,
          status: 'SUCCESS',
          durationMs,
        }).catch(() => {});
      }

      // 9. Cache Idempotent Result
      if (idempotencyCacheKey && this.idempotencyStore) {
        await this.idempotencyStore.set(idempotencyCacheKey, finalResult);
      }

      return finalResult;
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      await notifyTransition('FAILED', { error: err.message, durationMs });

      const isCryptoError = err instanceof CryptoEngineError;
      // Node rejects malformed caller input (wrong types, unknown encodings) with
      // ERR_INVALID_ARG_* / ERR_UNKNOWN_ENCODING; that is a client error, not a server fault.
      const isInputError =
        !isCryptoError &&
        typeof err?.code === 'string' &&
        (err.code.startsWith('ERR_INVALID_ARG') || err.code === 'ERR_UNKNOWN_ENCODING');
      const errorPayload: CryptographicOperationError = {
        code: isCryptoError ? err.code : isInputError ? 'INVALID_REQUEST' : 'OPERATION_FAILED',
        message: isInputError
          ? 'Invalid operation parameters.'
          : err.message || 'An error occurred during cryptographic execution.',
        retryable: isCryptoError ? err.code === 'TIMEOUT' || err.code === 'PROVIDER_UNAVAILABLE' : false,
        statusCode: isCryptoError ? err.status : isInputError ? 400 : 500,
        details: isCryptoError ? err.details : undefined,
      };

      if (this.auditSink) {
        this.auditSink.logOperation({
          operationId,
          requestId,
          action: `crypto.${String(request.type).toLowerCase()}`,
          organizationId: context.organizationId,
          projectId: context.projectId,
          environmentId: context.environmentId,
          actorId: context.actorId,
          providerId: 'unknown',
          algorithm: request.algorithm ? String(request.algorithm) : null,
          keyId: request.keyId || null,
          status: 'FAILED',
          durationMs,
          error: errorPayload.message,
        }).catch(() => {});
      }

      return {
        success: false,
        operationId,
        requestId,
        status: 'FAILED',
        type: request.type,
        metadata: {
          durationMs,
          providerId: 'none',
          providerName: 'none',
          timestamp: new Date().toISOString(),
        },
        error: errorPayload,
      };
    }
  }

  // --- Ergonomic Developer Helpers ---

  public async encrypt(
    params: {
      data: Buffer | string;
      key?: Buffer | string;
      keyId?: string;
      algorithm?: string;
      aad?: Buffer | string;
      policy?: string;
      idempotencyKey?: string;
    },
    context: TenantContext
  ) {
    return this.execute(
      {
        operationId: `op_enc_${Date.now()}`,
        requestId: `req_${Date.now()}`,
        idempotencyKey: params.idempotencyKey,
        type: 'ENCRYPT',
        algorithm: params.algorithm,
        keyId: params.keyId,
        policy: params.policy,
        params: {
          plaintext: params.data,
          key: params.key,
          aad: params.aad,
        },
      },
      context
    );
  }

  public async decrypt(
    params: {
      envelope: any;
      key?: Buffer | string;
      keyId?: string;
      algorithm?: string;
      policy?: string;
      idempotencyKey?: string;
    },
    context: TenantContext
  ) {
    return this.execute(
      {
        operationId: `op_dec_${Date.now()}`,
        requestId: `req_${Date.now()}`,
        idempotencyKey: params.idempotencyKey,
        type: 'DECRYPT',
        algorithm: params.algorithm,
        keyId: params.keyId,
        policy: params.policy,
        params: {
          envelope: params.envelope,
          key: params.key,
        },
      },
      context
    );
  }

  public async sign(
    params: {
      data: Buffer | string;
      keyId?: string;
      privateKey?: Buffer | string;
      algorithm?: string;
      policy?: string;
      idempotencyKey?: string;
    },
    context: TenantContext
  ) {
    return this.execute(
      {
        operationId: `op_sig_${Date.now()}`,
        requestId: `req_${Date.now()}`,
        idempotencyKey: params.idempotencyKey,
        type: 'SIGN',
        algorithm: params.algorithm,
        keyId: params.keyId,
        policy: params.policy,
        params: {
          data: params.data,
          privateKey: params.privateKey,
        },
      },
      context
    );
  }

  public async verify(
    params: {
      data: Buffer | string;
      signature: Buffer | string;
      keyId?: string;
      publicKey?: Buffer | string;
      algorithm?: string;
      policy?: string;
      idempotencyKey?: string;
    },
    context: TenantContext
  ) {
    return this.execute(
      {
        operationId: `op_ver_${Date.now()}`,
        requestId: `req_${Date.now()}`,
        idempotencyKey: params.idempotencyKey,
        type: 'VERIFY',
        algorithm: params.algorithm,
        keyId: params.keyId,
        policy: params.policy,
        params: {
          data: params.data,
          signature: params.signature,
          publicKey: params.publicKey,
        },
      },
      context
    );
  }
}

export const cryptographicRuntime = new CryptographicRuntime();
