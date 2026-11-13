import { HttpClient } from './http';
import {
  AmaracusClientOptions,
  RequestOptions,
  BinaryLike,
  EncryptRequest,
  EncryptResponse,
  DecryptRequest,
  DecryptResponse,
  HashRequest,
  HashResponse,
  SignRequest,
  SignResponse,
  VerifyRequest,
  VerifyResponse,
  LogicalKey,
  CreateKeyRequest,
  UpdateKeyRequest,
  ListKeysOptions,
  KmsProviderHealth,
  PlatformCapabilities,
  AlgorithmMetadata,
  OperationRecord,
  CreateOperationRequest,
  CreateOperationResponse,
  ListOperationsOptions,
  OperationResultResponse,
  CancelOperationResponse,
  PollOperationOptions,
  ApiCredential,
  CreateCredentialParams,
  CreateCredentialResult,
  WebhookEndpoint,
  CreateWebhookParams,
  CreateWebhookResult,
  WebhookDelivery,
  AsyncJob,
  SubmitJobParams,
  UsageMetrics,
  EncryptParams,
  EncryptResult,
  DecryptParams,
  DecryptResult,
  SignParams,
  SignResult,
  VerifyParams,
  VerifyResult,
  PqcKeyPairParams,
  PqcKeyPairResult,
  PqcEncapsulateParams,
  PqcEncapsulateResult,
  PqcDecapsulateParams,
  PqcDecapsulateResult,
  PqcSignParams,
  PqcSignResult,
  PqcVerifyParams,
  PqcVerifyResult,
  CryptographicKey,
  CreateKeyParams,
  CertificateRecord,
  IssueCertificateParams,
  CertificateValidationResult,
  PolicyDocument,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  PolicySimulationRequest,
  PolicySimulationResponse,
  PolicyDryRunRequest,
  PolicyDryRunResponse,
  PolicyMetricsResponse,
  ControlProject,
  ControlEnvironment,
  ControlTeam,
  ControlServiceIdentity,
  ControlServiceIdentityCreated,
  CryptographicPosture,
  ConfigurationDrift,
  ControlAuditEvent,
  OptimizationRecommendation,
  RecommendationListOptions,
  ImpactAnalysisResult,
  ComplianceFrameworkId,
  ComplianceFrameworkDefinition,
  FrameworkAssessmentReport,
  EvidenceArtifact,
  ControlGap,
  ComplianceException,
  EvaluateAssessmentsParams,
  RequestExceptionParams,
  EvidenceListFilter,
  GapListFilter,
} from './types';

import { verifyWebhookSignature, constructWebhookEvent } from './webhooks';

function isBinaryObject(input: any): boolean {
  return Buffer.isBuffer(input) || input instanceof Uint8Array || input instanceof ArrayBuffer;
}

function toBase64(input: BinaryLike): string {
  if (typeof input === 'string') {
    return input;
  }
  if (Buffer.isBuffer(input)) {
    return input.toString('base64');
  }
  if (input instanceof Uint8Array || input instanceof ArrayBuffer) {
    return Buffer.from(input as any).toString('base64');
  }
  return String(input);
}

/**
 * Official AMARACUS Client.
 *
 * Provides a thin, secure, ergonomic developer experience over the AMARACUS
 * Universal Cryptographic API. Contains zero client-side cryptographic primitives.
 */
export class Amaracus {
  private readonly http: HttpClient;

  // ==========================================================================
  // DISCOVERY & OBSERVABILITY NAMESPACES
  // ==========================================================================

  public readonly capabilities: {
    /**
     * Retrieve platform cryptographic capabilities, supported operations, and compliance profiles.
     */
    get: (options?: RequestOptions) => Promise<PlatformCapabilities>;
  };

  public readonly algorithms: {
    /**
     * List all algorithms in the AMARACUS cryptographic catalog with security and FIPS metadata.
     */
    list: (options?: RequestOptions) => Promise<AlgorithmMetadata[]>;
  };

  public readonly operations: {
    /**
     * Submit a managed cryptographic operation (synchronous or asynchronous).
     */
    create: (params: CreateOperationRequest, options?: RequestOptions) => Promise<CreateOperationResponse>;

    /**
     * Inspect execution status and audit metadata for any cryptographic operation by ID.
     */
    get: (operationId: string, options?: RequestOptions) => Promise<OperationRecord>;

    /**
     * List operations for current tenant with status and type filters.
     */
    list: (options?: ListOperationsOptions) => Promise<OperationRecord[]>;

    /**
     * Retrieve the execution result or polling status for an operation.
     */
    result: (operationId: string, options?: RequestOptions) => Promise<OperationResultResponse>;

    /**
     * Cancel an enqueued or active cryptographic operation.
     */
    cancel: (operationId: string, options?: RequestOptions) => Promise<CancelOperationResponse>;

    /**
     * Poll an asynchronous operation until terminal state (COMPLETED, FAILED, etc.).
     */
    pollUntilComplete: (
      operationId: string,
      pollOptions?: PollOperationOptions,
      options?: RequestOptions
    ) => Promise<OperationResultResponse>;

    /**
     * Retrieve operational telemetry, queue depth, and active concurrency metrics.
     */
    metrics: (options?: RequestOptions) => Promise<any>;
  };

  // ==========================================================================
  // LOGICAL KEY MANAGEMENT NAMESPACE
  // ==========================================================================

  public readonly keys: {
    /**
     * Create a new managed logical key backed by local dev KMS or Cloud HSM.
     */
    create: (params: CreateKeyRequest, options?: RequestOptions) => Promise<LogicalKey>;

    /**
     * List logical keys in the current tenant environment.
     */
    list: (options?: ListKeysOptions) => Promise<LogicalKey[]>;

    /**
     * Retrieve sanitized metadata for a logical key by ID or name.
     */
    get: (id: string, options?: RequestOptions) => Promise<LogicalKey>;

    /**
     * Rotate a logical key, provisioning a new active version and deprecating previous versions.
     */
    rotate: (id: string, options?: RequestOptions) => Promise<LogicalKey>;

    /**
     * Update metadata, description, or active status of a logical key.
     */
    update: (id: string, params: UpdateKeyRequest, options?: RequestOptions) => Promise<LogicalKey>;

    /**
     * Permanently destroy or soft-delete a logical key.
     */
    delete: (id: string, options?: RequestOptions) => Promise<{ id: string; status: string; message: string }>;

    /**
     * Alias for delete.
     */
    destroy: (id: string, options?: RequestOptions) => Promise<{ id: string; status: string; message: string }>;

    /**
     * Retrieve health status and latency metrics for KMS and Cloud HSM providers.
     */
    providers: (options?: RequestOptions) => Promise<KmsProviderHealth[]>;

    /**
     * Disable a key: it can still decrypt and verify existing data, but not encrypt or sign.
     * Reversible with update(id, { status: 'ACTIVE' }).
     */
    archive: (id: string, options?: RequestOptions) => Promise<CryptographicKey>;

    /**
     * Revoke a key: from then on it can only verify. Irreversible.
     */
    revoke: (id: string, options?: RequestOptions) => Promise<CryptographicKey>;
  };

  // ==========================================================================
  // POLICY & INTELLIGENCE NAMESPACE (PHASE 15)
  // ==========================================================================

  public readonly policies: {
    /**
     * List cryptographic policies with optional scope, status, and pagination filters.
     */
    list: (options?: RequestOptions & { scope?: string; status?: string; limit?: number; cursor?: string }) => Promise<{ items: PolicyDocument[]; pagination?: any }>;

    /**
     * Retrieve a specific cryptographic policy by ID.
     */
    get: (id: string, options?: RequestOptions) => Promise<PolicyDocument>;

    /**
     * Create a new cryptographic policy.
     */
    create: (params: CreatePolicyRequest, options?: RequestOptions) => Promise<PolicyDocument>;

    /**
     * Update an existing cryptographic policy and create a new version record.
     */
    update: (id: string, params: UpdatePolicyRequest, options?: RequestOptions) => Promise<PolicyDocument>;

    /**
     * Delete or archive a cryptographic policy.
     */
    delete: (id: string, options?: RequestOptions) => Promise<{ success: boolean }>;

    /**
     * Simulate policy impact against registered inventory, keys, and operations without applying changes.
     */
    simulate: (id: string, params?: PolicySimulationRequest, options?: RequestOptions) => Promise<PolicySimulationResponse>;

    /**
     * Evaluate a prospective cryptographic operation against active policies without execution (dry-run).
     */
    dryRun: (params: PolicyDryRunRequest, options?: RequestOptions) => Promise<PolicyDryRunResponse>;

    /**
     * Retrieve policy evaluation telemetry, decision distributions, latencies, and anomaly alerts.
     */
    metrics: (options?: RequestOptions) => Promise<PolicyMetricsResponse>;
  };

  // ==========================================================================
  // PHASE 16: CONTROL PLANE SUBCLIENTS
  // ==========================================================================

  public readonly projects: {
    list: (options?: RequestOptions) => Promise<ControlProject[]>;
    get: (projectId: string, options?: RequestOptions) => Promise<ControlProject>;
    create: (data: { name: string; slug: string; description?: string }, options?: RequestOptions) => Promise<ControlProject>;
    update: (projectId: string, data: { name?: string; description?: string }, options?: RequestOptions) => Promise<ControlProject>;
    delete: (projectId: string, options?: RequestOptions) => Promise<{ success: boolean }>;
    listEnvironments: (projectId: string, options?: RequestOptions) => Promise<ControlEnvironment[]>;
    createEnvironment: (projectId: string, data: { name: string; slug: string; type?: string }, options?: RequestOptions) => Promise<ControlEnvironment>;
  };

  public readonly posture: {
    get: (options?: RequestOptions) => Promise<CryptographicPosture>;
    drifts: (options?: RequestOptions) => Promise<ConfigurationDrift[]>;
    resolveDrift: (driftId: string, options?: RequestOptions) => Promise<{ success: boolean }>;
  };

  public readonly control: {
    projects: Amaracus['projects'];
    posture: Amaracus['posture'];
    teams: {
      list: (options?: RequestOptions) => Promise<ControlTeam[]>;
      create: (data: { name: string; description?: string }, options?: RequestOptions) => Promise<ControlTeam>;
      get: (teamId: string, options?: RequestOptions) => Promise<ControlTeam>;
      addMember: (teamId: string, data: { userId: string; role?: string }, options?: RequestOptions) => Promise<any>;
    };
    serviceIdentities: {
      list: (options?: RequestOptions) => Promise<ControlServiceIdentity[]>;
      create: (data: { name: string; description?: string; scopes?: string[] }, options?: RequestOptions) => Promise<ControlServiceIdentityCreated>;
      revoke: (id: string, options?: RequestOptions) => Promise<{ success: boolean }>;
    };
    audit: {
      list: (params?: { actorId?: string; action?: string; limit?: number; offset?: number }, options?: RequestOptions) => Promise<{ auditEvents: ControlAuditEvent[]; total: number }>;
    };
    usage: {
      get: (options?: RequestOptions) => Promise<any>;
    };
  };

  // ==========================================================================
  // BACKWARD-COMPATIBLE SUBCLIENTS
  // ==========================================================================

  public readonly credentials: {
    list: (options?: RequestOptions & { limit?: number; cursor?: string }) => Promise<{ items: ApiCredential[]; pagination?: any }>;
    create: (params: CreateCredentialParams, options?: RequestOptions) => Promise<CreateCredentialResult>;
    get: (id: string, options?: RequestOptions) => Promise<ApiCredential>;
    update: (id: string, params: { status?: string; name?: string }, options?: RequestOptions) => Promise<ApiCredential>;
    rotate: (id: string, options?: RequestOptions) => Promise<{ credential: ApiCredential; rawApiKey: string }>;
    revoke: (id: string, options?: RequestOptions) => Promise<{ success: boolean }>;
  };

  /**
   * Raw-key operations (the caller supplies key material). For managed keys use the
   * top-level encrypt/decrypt/hash/sign/verify methods instead.
   * @deprecated Use the top-level methods; this namespace stays for existing integrations.
   */
  public readonly crypto: {
    algorithms: (options?: RequestOptions) => Promise<any[]>;
    policies: (options?: RequestOptions) => Promise<any[]>;
    encrypt: (params: EncryptParams, options?: RequestOptions) => Promise<EncryptResult>;
    decrypt: (params: DecryptParams, options?: RequestOptions) => Promise<DecryptResult>;
    sign: (params: SignParams, options?: RequestOptions) => Promise<SignResult>;
    verify: (params: VerifyParams, options?: RequestOptions) => Promise<VerifyResult>;
    /** HMAC with a caller-supplied key (POST /crypto/hmac). */
    mac: (params: { algorithm: string; data: string; key: string; keyEncoding?: string; dataEncoding?: string }, options?: RequestOptions) => Promise<any>;
    /** Hash (POST /crypto/hash). Prefer the top-level hash(). */
    digest: (params: { algorithm: string; data: string; encoding?: string }, options?: RequestOptions) => Promise<any>;
    random: (params: { lengthBytes: number }, options?: RequestOptions) => Promise<{ randomBytes: string }>;
  };

  public readonly cryptography: typeof this.crypto;

  public readonly pqc: {
    algorithms: (options?: RequestOptions) => Promise<string[]>;
    keypair: (params: PqcKeyPairParams, options?: RequestOptions) => Promise<PqcKeyPairResult>;
    encapsulate: (params: PqcEncapsulateParams, options?: RequestOptions) => Promise<PqcEncapsulateResult>;
    decapsulate: (params: PqcDecapsulateParams, options?: RequestOptions) => Promise<PqcDecapsulateResult>;
    sign: (params: PqcSignParams, options?: RequestOptions) => Promise<PqcSignResult>;
    verify: (params: PqcVerifyParams, options?: RequestOptions) => Promise<PqcVerifyResult>;
  };

  public readonly certificates: {
    list: (options?: RequestOptions) => Promise<CertificateRecord[]>;
    get: (id: string, options?: RequestOptions) => Promise<CertificateRecord>;
    issue: (params: IssueCertificateParams, options?: RequestOptions) => Promise<CertificateRecord>;
    revoke: (id: string, reason?: string, options?: RequestOptions) => Promise<CertificateRecord>;
    /** Chain, expiry and revocation check of an issued certificate (by ID). */
    validate: (id: string, options?: RequestOptions) => Promise<CertificateValidationResult>;
    getCas: (options?: RequestOptions) => Promise<any[]>;
  };

  public readonly intelligence: {
    getAssets: (options?: RequestOptions) => Promise<any[]>;
    getFindings: (options?: RequestOptions) => Promise<any[]>;
    scan: (params?: any, options?: RequestOptions) => Promise<any>;
    exportCbom: (format?: 'json' | 'cyclonedx', options?: RequestOptions) => Promise<any>;
    getMigrations: (options?: RequestOptions) => Promise<any[]>;
    planMigration: (params: any, options?: RequestOptions) => Promise<any>;
    getRecommendations: (params?: RecommendationListOptions, options?: RequestOptions) => Promise<OptimizationRecommendation[]>;
    getRecommendation: (id: string, options?: RequestOptions) => Promise<OptimizationRecommendation>;
    acceptRecommendation: (id: string, params?: { reason?: string }, options?: RequestOptions) => Promise<OptimizationRecommendation>;
    rejectRecommendation: (id: string, params?: { reason?: string }, options?: RequestOptions) => Promise<OptimizationRecommendation>;
    dismissRecommendation: (id: string, params?: { reason?: string }, options?: RequestOptions) => Promise<OptimizationRecommendation>;
    dryRunRecommendation: (id: string, options?: RequestOptions) => Promise<ImpactAnalysisResult>;
    executeRecommendation: (id: string, options?: RequestOptions) => Promise<OptimizationRecommendation>;
    runAnalysis: (params?: { targetResourceIds?: string[]; categories?: string[] }, options?: RequestOptions) => Promise<any>;
  };
  public readonly optimization: typeof this.intelligence;

  public readonly compliance: {
    getFrameworks: (options?: RequestOptions) => Promise<ComplianceFrameworkDefinition[]>;
    getFramework: (id: ComplianceFrameworkId, options?: RequestOptions) => Promise<ComplianceFrameworkDefinition>;
    getAssessments: (frameworkId?: ComplianceFrameworkId, options?: RequestOptions) => Promise<FrameworkAssessmentReport[]>;
    evaluate: (params?: EvaluateAssessmentsParams, options?: RequestOptions) => Promise<FrameworkAssessmentReport | FrameworkAssessmentReport[]>;
    getEvidence: (filter?: EvidenceListFilter, options?: RequestOptions) => Promise<EvidenceArtifact[]>;
    getGaps: (filter?: GapListFilter, options?: RequestOptions) => Promise<ControlGap[]>;
    requestException: (params: RequestExceptionParams, options?: RequestOptions) => Promise<ComplianceException>;
    approveException: (id: string, approverId?: string, options?: RequestOptions) => Promise<ComplianceException>;
    generateReport: (frameworkId: ComplianceFrameworkId, format?: 'json' | 'csv', options?: RequestOptions) => Promise<any>;
  };
  public readonly assurance: typeof this.compliance;


  public readonly advanced: {
    /** Preview: Schnorr proofs only; not for production. */
    zk: {
      circuits: (options?: RequestOptions) => Promise<any[]>;
      /** Registers a circuit (POST /advanced/zk/circuits). */
      setup: (params: any, options?: RequestOptions) => Promise<any>;
      prove: (params: any, options?: RequestOptions) => Promise<any>;
      verify: (params: any, options?: RequestOptions) => Promise<any>;
    };
    /** Preview: the server holds the FHE secret key; not for production. */
    fhe: {
      limits: (options?: RequestOptions) => Promise<any>;
      /** Generates an FHE key set (POST /advanced/fhe/keygen). */
      context: (params: any, options?: RequestOptions) => Promise<any>;
      encrypt: (params: any, options?: RequestOptions) => Promise<any>;
      evaluate: (params: any, options?: RequestOptions) => Promise<any>;
      decrypt: (params: any, options?: RequestOptions) => Promise<any>;
    };
    /** Disabled on the server (501 preview) until a real protocol exists. */
    mpc: {
      createSession: (params: any, options?: RequestOptions) => Promise<any>;
      submitInput: (sessionId: string, params: any, options?: RequestOptions) => Promise<any>;
      compute: (sessionId: string, params?: any, options?: RequestOptions) => Promise<any>;
    };
    /** Disabled on the server (501 preview) until a vetted FROST implementation exists. */
    threshold: {
      generateKeys: (params: any, options?: RequestOptions) => Promise<any>;
      /** Opens a signing session (POST /advanced/threshold/sessions). */
      sign: (params: any, options?: RequestOptions) => Promise<any>;
      /** Executes an approved signing session. */
      combine: (sessionId: string, params?: any, options?: RequestOptions) => Promise<any>;
    };
  };

  public readonly webhooks: {
    list: (options?: RequestOptions) => Promise<WebhookEndpoint[]>;
    create: (params: CreateWebhookParams, options?: RequestOptions) => Promise<CreateWebhookResult>;
    get: (id: string, options?: RequestOptions) => Promise<WebhookEndpoint>;
    update: (id: string, params: Partial<CreateWebhookParams> & { status?: string }, options?: RequestOptions) => Promise<WebhookEndpoint>;
    delete: (id: string, options?: RequestOptions) => Promise<{ success: boolean }>;
    rotateSecret: (id: string, options?: RequestOptions) => Promise<{ endpoint: Partial<WebhookEndpoint>; signingSecret: string; warning: string }>;
    getDeliveries: (id: string, options?: RequestOptions) => Promise<WebhookDelivery[]>;
    testPing: (id: string, options?: RequestOptions) => Promise<{ success: boolean; delivery: WebhookDelivery }>;
    verifySignature: (rawPayload: string | Buffer, headerValue: string, secret: string, toleranceSeconds?: number) => boolean;
    constructEvent: <T = any>(rawPayload: string | Buffer, headerValue: string, secret: string, toleranceSeconds?: number) => T;
  };

  public readonly jobs: {
    list: (options?: RequestOptions) => Promise<AsyncJob[]>;
    submit: <T = any>(params: SubmitJobParams, options?: RequestOptions) => Promise<AsyncJob<T>>;
    get: <T = any>(id: string, options?: RequestOptions) => Promise<AsyncJob<T>>;
    cancel: (id: string, options?: RequestOptions) => Promise<{ success: boolean }>;
    pollUntilComplete: <T = any>(id: string, pollIntervalMs?: number, maxWaitMs?: number) => Promise<AsyncJob<T>>;
  };

  public readonly usage: {
    get: (options?: RequestOptions & { from?: string; to?: string }) => Promise<UsageMetrics>;
  };

  constructor(options: AmaracusClientOptions = {}) {
    this.http = new HttpClient(options);

    // Capabilities Subclient
    this.capabilities = {
      get: async (opts) => {
        const res = await this.http.request<PlatformCapabilities>('GET', '/capabilities', undefined, opts);
        return res.data;
      },
    };

    // Algorithms Subclient
    this.algorithms = {
      list: async (opts) => {
        const res = await this.http.request<AlgorithmMetadata[]>('GET', '/algorithms', undefined, opts);
        return res.data;
      },
    };

    // Managed Operations Subclient
    this.operations = {
      create: async (params, opts) => {
        const res = await this.http.request<any>(
          'POST',
          '/operations',
          params,
          opts
        );
        return {
          operationId: res.operationId || res.data?.operationId,
          requestId: res.requestId || res.data?.requestId,
          status: res.status || res.data?.status,
          mode: (res as any).mode || res.data?.mode,
          pollUrl: (res as any).pollUrl || res.data?.pollUrl,
          data: res.data !== undefined ? res.data : (res as any).data,
          durationMs: (res as any).durationMs || res.data?.durationMs,
          expiresAt: (res as any).expiresAt || res.data?.expiresAt,
        };
      },
      get: async (operationId, opts) => {
        const res = await this.http.request<OperationRecord>(
          'GET',
          `/operations/${encodeURIComponent(operationId)}`,
          undefined,
          opts
        );
        return res.data;
      },
      list: async (opts) => {
        const queryParams = new URLSearchParams();
        if (opts?.limit) queryParams.set('limit', String(opts.limit));
        if (opts?.offset) queryParams.set('offset', String(opts.offset));
        if (opts?.status) queryParams.set('status', opts.status);
        if (opts?.type) queryParams.set('type', opts.type);
        const qs = queryParams.toString();
        const endpoint = qs ? `/operations?${qs}` : '/operations';

        const res = await this.http.request<OperationRecord[]>(
          'GET',
          endpoint,
          undefined,
          opts
        );
        return res.data;
      },
      result: async (operationId, opts) => {
        const res = await this.http.request<any>(
          'GET',
          `/operations/${encodeURIComponent(operationId)}/result`,
          undefined,
          opts
        );
        const dataPayload = res.data;
        return {
          operationId: res.operationId || dataPayload?.operationId || operationId,
          status: res.status || dataPayload?.status || 'COMPLETED',
          data: dataPayload,
          error: (res as any).error || dataPayload?.error,
          durationMs: res.durationMs || dataPayload?.durationMs,
          retryAfterMs: (res as any).retryAfterMs || dataPayload?.retryAfterMs,
        };
      },
      cancel: async (operationId, opts) => {
        const res = await this.http.request<any>(
          'POST',
          `/operations/${encodeURIComponent(operationId)}/cancel`,
          undefined,
          opts
        );
        const dataPayload = res.data;
        return {
          operationId: res.operationId || dataPayload?.operationId || operationId,
          status: res.status || dataPayload?.status || 'CANCELED',
          canceled: (res as any).canceled ?? dataPayload?.canceled ?? true,
        };
      },
      pollUntilComplete: async (operationId, pollOpts, opts) => {
        const intervalMs = pollOpts?.intervalMs || 200;
        const timeoutMs = pollOpts?.timeoutMs || 30000;
        const startTime = Date.now();

        while (Date.now() - startTime < timeoutMs) {
          const res = await this.operations.result(operationId, opts);
          if (pollOpts?.onProgress) {
            pollOpts.onProgress(res.status);
          }
          if (
            ['COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELED', 'DEAD_LETTER', 'EXPIRED'].includes(
              res.status
            )
          ) {
            return res;
          }
          const sleepMs = res.retryAfterMs || intervalMs;
          await new Promise((resolve) => setTimeout(resolve, sleepMs));
        }

        throw new Error(`Polling operation '${operationId}' timed out after ${timeoutMs}ms`);
      },
      metrics: async (opts) => {
        const res = await this.http.request<any>(
          'GET',
          '/operations/metrics',
          undefined,
          opts
        );
        return res.data;
      },
    };

    // Keys Subclient
    this.keys = {
      create: async (params, opts) => {
        const res = await this.http.request<LogicalKey>('POST', '/keys', params, opts);
        return res.data;
      },
      list: async (opts) => {
        const queryParams = new URLSearchParams();
        if (opts?.limit !== undefined) queryParams.set('limit', String(opts.limit));
        if (opts?.offset !== undefined) queryParams.set('offset', String(opts.offset));
        if (opts?.purpose) queryParams.set('purpose', opts.purpose);
        if (opts?.status) queryParams.set('status', opts.status);
        if (opts?.algorithm) queryParams.set('algorithm', opts.algorithm);

        const qs = queryParams.toString();
        const path = qs ? `/keys?${qs}` : '/keys';
        const res = await this.http.request<LogicalKey[]>('GET', path, undefined, opts);
        return res.data;
      },
      get: async (id, opts) => {
        const res = await this.http.request<LogicalKey>('GET', `/keys/${encodeURIComponent(id)}`, undefined, opts);
        return res.data;
      },
      rotate: async (id, opts) => {
        const res = await this.http.request<LogicalKey>('POST', `/keys/${encodeURIComponent(id)}/rotate`, {}, opts);
        return res.data;
      },
      update: async (id, params, opts) => {
        const res = await this.http.request<LogicalKey>('PATCH', `/keys/${encodeURIComponent(id)}`, params, opts);
        return res.data;
      },
      delete: async (id, opts) => {
        const res = await this.http.request<{ id: string; status: string; message: string }>(
          'DELETE',
          `/keys/${encodeURIComponent(id)}`,
          undefined,
          opts
        );
        return res.data;
      },
      destroy: async (id, opts) => {
        return this.keys.delete(id, opts);
      },
      providers: async (opts) => {
        const res = await this.http.request<KmsProviderHealth[]>('GET', '/keys/providers', undefined, opts);
        return res.data;
      },
      archive: async (id, opts) => {
        const res = await this.http.request<CryptographicKey>('PATCH', `/keys/${encodeURIComponent(id)}`, { status: 'DISABLED' }, opts);
        return res.data;
      },
      revoke: async (id, opts) => {
        const res = await this.http.request<CryptographicKey>('PATCH', `/keys/${encodeURIComponent(id)}`, { status: 'REVOKED' }, opts);
        return res.data;
      },
    };

    // Policies Subclient (Phase 15)
    this.policies = {
      list: async (opts) => {
        const queryParams = new URLSearchParams();
        if (opts?.scope) queryParams.set('scope', opts.scope);
        if (opts?.status) queryParams.set('status', opts.status);
        if (opts?.limit) queryParams.set('limit', String(opts.limit));
        if (opts?.cursor) queryParams.set('cursor', opts.cursor);
        const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';
        const res = await this.http.request<PolicyDocument[]>('GET', `/policies${qs}`, undefined, opts);
        return { items: res.data, pagination: res.pagination };
      },
      get: async (id, opts) => {
        const res = await this.http.request<PolicyDocument>('GET', `/policies/${encodeURIComponent(id)}`, undefined, opts);
        return res.data;
      },
      create: async (params, opts) => {
        const res = await this.http.request<PolicyDocument>('POST', '/policies', params, opts);
        return res.data;
      },
      update: async (id, params, opts) => {
        const res = await this.http.request<PolicyDocument>('PATCH', `/policies/${encodeURIComponent(id)}`, params, opts);
        return res.data;
      },
      delete: async (id, opts) => {
        const res = await this.http.request<{ id: string; deleted?: boolean; success?: boolean }>('DELETE', `/policies/${encodeURIComponent(id)}`, undefined, opts);
        return { success: res.data?.success ?? res.data?.deleted ?? true };
      },
      simulate: async (id, params, opts) => {
        const res = await this.http.request<PolicySimulationResponse>('POST', `/policies/${encodeURIComponent(id)}/simulate`, params || {}, opts);
        return res.data;
      },
      dryRun: async (params, opts) => {
        const res = await this.http.request<PolicyDryRunResponse>('POST', '/policies/dry-run', params, opts);
        return res.data;
      },
      metrics: async (opts) => {
        const res = await this.http.request<PolicyMetricsResponse>('GET', '/policies/metrics', undefined, opts);
        return res.data;
      },
    };

    // Projects Control Subclient
    this.projects = {
      list: async (opts) => {
        const res = await this.http.request<{ projects: ControlProject[] }>('GET', '/control/projects', undefined, opts);
        return res.data.projects;
      },
      get: async (projectId, opts) => {
        const res = await this.http.request<{ project: ControlProject }>('GET', `/control/projects/${encodeURIComponent(projectId)}`, undefined, opts);
        return res.data.project;
      },
      create: async (data, opts) => {
        const res = await this.http.request<{ project: ControlProject }>('POST', '/control/projects', data, opts);
        return res.data.project;
      },
      update: async (projectId, data, opts) => {
        const res = await this.http.request<{ project: ControlProject }>('PATCH', `/control/projects/${encodeURIComponent(projectId)}`, data, opts);
        return res.data.project;
      },
      delete: async (projectId, opts) => {
        const res = await this.http.request<{ success: boolean }>('DELETE', `/control/projects/${encodeURIComponent(projectId)}`, undefined, opts);
        return { success: res.data?.success ?? true };
      },
      listEnvironments: async (projectId, opts) => {
        const res = await this.http.request<{ environments: ControlEnvironment[] }>('GET', `/control/projects/${encodeURIComponent(projectId)}/environments`, undefined, opts);
        return res.data.environments;
      },
      createEnvironment: async (projectId, data, opts) => {
        const res = await this.http.request<{ environment: ControlEnvironment }>('POST', `/control/projects/${encodeURIComponent(projectId)}/environments`, data, opts);
        return res.data.environment;
      },
    };

    // Posture Control Subclient
    this.posture = {
      get: async (opts) => {
        const res = await this.http.request<{ posture: CryptographicPosture }>('GET', '/control/posture', undefined, opts);
        return res.data.posture;
      },
      drifts: async (opts) => {
        const res = await this.http.request<{ drifts: ConfigurationDrift[] }>('GET', '/control/drifts', undefined, opts);
        return res.data.drifts;
      },
      resolveDrift: async (driftId, opts) => {
        const res = await this.http.request<{ success: boolean }>('POST', `/control/drifts/${encodeURIComponent(driftId)}/resolve`, undefined, opts);
        return { success: res.data?.success ?? true };
      },
    };

    // Control Plane Comprehensive Subclient
    this.control = {
      projects: this.projects,
      posture: this.posture,
      teams: {
        list: async (opts) => {
          const res = await this.http.request<{ teams: ControlTeam[] }>('GET', '/control/teams', undefined, opts);
          return res.data.teams;
        },
        create: async (data, opts) => {
          const res = await this.http.request<{ team: ControlTeam }>('POST', '/control/teams', data, opts);
          return res.data.team;
        },
        get: async (teamId, opts) => {
          const res = await this.http.request<{ team: ControlTeam }>('GET', `/control/teams/${encodeURIComponent(teamId)}`, undefined, opts);
          return res.data.team;
        },
        addMember: async (teamId, data, opts) => {
          const res = await this.http.request<{ member: any }>('POST', `/control/teams/${encodeURIComponent(teamId)}/members`, data, opts);
          return res.data.member;
        },
      },
      serviceIdentities: {
        list: async (opts) => {
          const res = await this.http.request<{ serviceIdentities: ControlServiceIdentity[] }>('GET', '/control/service-identities', undefined, opts);
          return res.data.serviceIdentities;
        },
        create: async (data, opts) => {
          const res = await this.http.request<ControlServiceIdentityCreated>('POST', '/control/service-identities', data, opts);
          return res.data;
        },
        revoke: async (id, opts) => {
          const res = await this.http.request<{ success: boolean }>('DELETE', `/control/service-identities/${encodeURIComponent(id)}`, undefined, opts);
          return { success: res.data?.success ?? true };
        },
      },
      audit: {
        list: async (params, opts) => {
          const queryParams = new URLSearchParams();
          if (params?.actorId) queryParams.set('actorId', params.actorId);
          if (params?.action) queryParams.set('action', params.action);
          if (params?.limit) queryParams.set('limit', String(params.limit));
          if (params?.offset) queryParams.set('offset', String(params.offset));
          const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';
          const res = await this.http.request<{ auditEvents: ControlAuditEvent[]; total: number }>('GET', `/control/audit${qs}`, undefined, opts);
          return res.data;
        },
      },
      usage: {
        get: async (opts) => {
          const res = await this.http.request<{ usage: any }>('GET', '/control/usage', undefined, opts);
          return res.data.usage;
        },
      },
    };

    // Credentials Subclient
    this.credentials = {
      list: async (opts) => {
        const query = opts?.limit ? `?limit=${opts.limit}${opts.cursor ? `&cursor=${opts.cursor}` : ''}` : '';
        const res = await this.http.request<ApiCredential[]>('GET', `/credentials${query}`, undefined, opts);
        return { items: res.data, pagination: res.pagination };
      },
      create: async (params, opts) => {
        const res = await this.http.request<CreateCredentialResult>('POST', '/credentials', params, opts);
        return res.data;
      },
      get: async (id, opts) => {
        const res = await this.http.request<ApiCredential>('GET', `/credentials/${encodeURIComponent(id)}`, undefined, opts);
        return res.data;
      },
      update: async (id, params, opts) => {
        const res = await this.http.request<ApiCredential>('PATCH', `/credentials/${encodeURIComponent(id)}`, params, opts);
        return res.data;
      },
      rotate: async (id, opts) => {
        const res = await this.http.request<{ credential: ApiCredential; rawApiKey: string }>(
          'POST',
          `/credentials/${encodeURIComponent(id)}/rotate`,
          {},
          opts
        );
        return res.data;
      },
      revoke: async (id, opts) => {
        const res = await this.http.request<{ success: boolean }>(
          'DELETE',
          `/credentials/${encodeURIComponent(id)}`,
          undefined,
          opts
        );
        return res.data;
      },
    };

    // Legacy Crypto Subclient
    this.crypto = {
      algorithms: async (opts) => {
        const res = await this.http.request<any[]>('GET', '/crypto/algorithms', undefined, opts);
        return res.data;
      },
      policies: async (opts) => {
        const res = await this.http.request<any[]>('GET', '/crypto/policies', undefined, opts);
        return res.data;
      },
      // These take the universal request types (key / rawKey / data), which only the
      // top-level endpoints understand, so they delegate there.
      encrypt: (params, opts) => this.encrypt(params, opts),
      decrypt: (params, opts) => this.decrypt(params, opts),
      sign: (params, opts) => this.sign(params, opts),
      verify: (params, opts) => this.verify(params, opts),
      mac: async (params, opts) => {
        const res = await this.http.request<any>('POST', '/crypto/hmac', params, opts);
        return res.data;
      },
      digest: async (params, opts) => {
        const res = await this.http.request<any>('POST', '/crypto/hash', params, opts);
        return res.data;
      },
      random: async (params, opts) => {
        const res = await this.http.request<{ randomBytes: string }>('POST', '/crypto/random', params, opts);
        return res.data;
      },
    };
    this.cryptography = this.crypto;

    // PQC Subclient
    this.pqc = {
      algorithms: async (opts) => {
        const res = await this.http.request<string[]>('GET', '/pqc/algorithms', undefined, opts);
        return res.data;
      },
      keypair: async (params, opts) => {
        const res = await this.http.request<PqcKeyPairResult>('POST', '/pqc/keypair', params, opts);
        return res.data;
      },
      encapsulate: async (params, opts) => {
        const res = await this.http.request<PqcEncapsulateResult>('POST', '/pqc/encapsulate', params, opts);
        return res.data;
      },
      decapsulate: async (params, opts) => {
        const res = await this.http.request<PqcDecapsulateResult>('POST', '/pqc/decapsulate', params, opts);
        return res.data;
      },
      sign: async (params, opts) => {
        const res = await this.http.request<PqcSignResult>('POST', '/pqc/sign', params, opts);
        return res.data;
      },
      verify: async (params, opts) => {
        const res = await this.http.request<PqcVerifyResult>('POST', '/pqc/verify', params, opts);
        return res.data;
      },
    };

    // Certificates Subclient
    this.certificates = {
      list: async (opts) => {
        const res = await this.http.request<CertificateRecord[]>('GET', '/pki/certificates', undefined, opts);
        return res.data;
      },
      get: async (id, opts) => {
        const res = await this.http.request<CertificateRecord>('GET', `/pki/certificates/${encodeURIComponent(id)}`, undefined, opts);
        return res.data;
      },
      issue: async (params, opts) => {
        const res = await this.http.request<CertificateRecord>('POST', '/pki/certificates', params, opts);
        return res.data;
      },
      revoke: async (id, reason, opts) => {
        const res = await this.http.request<CertificateRecord>(
          'POST',
          `/pki/certificates/${encodeURIComponent(id)}/revoke`,
          { reason },
          opts
        );
        return res.data;
      },
      validate: async (id, opts) => {
        const res = await this.http.request<CertificateValidationResult>('POST', `/pki/certificates/${encodeURIComponent(id)}/validate`, {}, opts);
        return res.data;
      },
      getCas: async (opts) => {
        const res = await this.http.request<any[]>('GET', '/pki/certificate-authorities', undefined, opts);
        return res.data;
      },
    };

    // Intelligence Subclient
    this.intelligence = {
      getAssets: async (opts) => {
        const res = await this.http.request<any[]>('GET', '/intelligence/assets', undefined, opts);
        return res.data;
      },
      getFindings: async (opts) => {
        const res = await this.http.request<any[]>('GET', '/intelligence/findings', undefined, opts);
        return res.data;
      },
      scan: async (params, opts) => {
        const res = await this.http.request<any>('POST', '/intelligence/scan', params || {}, opts);
        return res.data;
      },
      exportCbom: async (format = 'cyclonedx', opts) => {
        const res = await this.http.request<any>('GET', `/intelligence/cbom?format=${encodeURIComponent(format)}`, undefined, opts);
        return res.data;
      },
      getMigrations: async (opts) => {
        const res = await this.http.request<any[]>('GET', '/intelligence/migrations', undefined, opts);
        return res.data;
      },
      planMigration: async (params, opts) => {
        const res = await this.http.request<any>('POST', '/intelligence/migrations', params, opts);
        return res.data;
      },
      getRecommendations: async (filter, opts) => {
        const queryParams = new URLSearchParams();
        if (filter?.category) queryParams.set('category', filter.category);
        if (filter?.status) queryParams.set('status', filter.status);
        if (filter?.severity) queryParams.set('severity', filter.severity);
        if (filter?.limit) queryParams.set('limit', String(filter.limit));
        if (filter?.offset) queryParams.set('offset', String(filter.offset));
        const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';
        const res = await this.http.request<OptimizationRecommendation[]>('GET', `/intelligence/recommendations${qs}`, undefined, opts);
        return res.data;
      },
      getRecommendation: async (id, opts) => {
        const res = await this.http.request<OptimizationRecommendation>('GET', `/intelligence/recommendations/${encodeURIComponent(id)}`, undefined, opts);
        return res.data;
      },
      acceptRecommendation: async (id, params, opts) => {
        const res = await this.http.request<OptimizationRecommendation>('POST', `/intelligence/recommendations/${encodeURIComponent(id)}/accept`, params || {}, opts);
        return res.data;
      },
      rejectRecommendation: async (id, params, opts) => {
        const res = await this.http.request<OptimizationRecommendation>('POST', `/intelligence/recommendations/${encodeURIComponent(id)}/reject`, params || {}, opts);
        return res.data;
      },
      dismissRecommendation: async (id, params, opts) => {
        const res = await this.http.request<OptimizationRecommendation>('POST', `/intelligence/recommendations/${encodeURIComponent(id)}/dismiss`, params || {}, opts);
        return res.data;
      },
      dryRunRecommendation: async (id, opts) => {
        const res = await this.http.request<ImpactAnalysisResult>('POST', `/intelligence/recommendations/${encodeURIComponent(id)}/dry-run`, {}, opts);
        return res.data;
      },
      executeRecommendation: async (id, opts) => {
        const res = await this.http.request<OptimizationRecommendation>('POST', `/intelligence/recommendations/${encodeURIComponent(id)}/execute`, {}, opts);
        return res.data;
      },
      runAnalysis: async (params, opts) => {
        const res = await this.http.request<any>('POST', '/intelligence/analyze', params || {}, opts);
        return res.data;
      },
    };
    this.optimization = this.intelligence;

    // Compliance & Assurance Subclient (Phase 22)
    this.compliance = {
      getFrameworks: async (opts) => {
        const res = await this.http.request<ComplianceFrameworkDefinition[]>('GET', '/compliance/frameworks', undefined, opts);
        return res.data || [];
      },
      getFramework: async (id, opts) => {
        const res = await this.http.request<ComplianceFrameworkDefinition>('GET', `/compliance/frameworks/${encodeURIComponent(id)}`, undefined, opts);
        return res.data;
      },
      getAssessments: async (frameworkId, opts) => {
        const q = frameworkId ? `?frameworkId=${encodeURIComponent(frameworkId)}` : '';
        const res = await this.http.request<FrameworkAssessmentReport[]>('GET', `/compliance/assessments${q}`, undefined, opts);
        return res.data || [];
      },
      evaluate: async (params, opts) => {
        const res = await this.http.request<any>('POST', '/compliance/assessments/evaluate', params || {}, opts);
        return res.data;
      },
      getEvidence: async (filter, opts) => {
        const queryParams = new URLSearchParams();
        if (filter?.type) queryParams.set('type', filter.type);
        if (filter?.freshness) queryParams.set('freshness', filter.freshness);
        if (filter?.source) queryParams.set('source', filter.source);
        const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';
        const res = await this.http.request<EvidenceArtifact[]>('GET', `/compliance/evidence${qs}`, undefined, opts);
        return res.data || [];
      },
      getGaps: async (filter, opts) => {
        const queryParams = new URLSearchParams();
        if (filter?.frameworkId) queryParams.set('frameworkId', filter.frameworkId);
        if (filter?.controlId) queryParams.set('controlId', filter.controlId);
        if (filter?.severity) queryParams.set('severity', filter.severity);
        const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';
        const res = await this.http.request<ControlGap[]>('GET', `/compliance/gaps${qs}`, undefined, opts);
        return res.data || [];
      },
      requestException: async (params, opts) => {
        const res = await this.http.request<ComplianceException>('POST', '/compliance/exceptions', params, opts);
        return res.data;
      },
      approveException: async (id, approverId, opts) => {
        const res = await this.http.request<ComplianceException>('POST', `/compliance/exceptions/${encodeURIComponent(id)}/approve`, { approverId }, opts);
        return res.data;
      },
      generateReport: async (frameworkId, format = 'json', opts) => {
        const q = `?frameworkId=${encodeURIComponent(frameworkId)}`;
        const res = await this.http.request<any>('GET', `/compliance/reports/${encodeURIComponent(format)}${q}`, undefined, opts);
        return res.data;
      },
    };
    this.assurance = this.compliance;


    // Advanced Cryptography Subclient
    this.advanced = {
      zk: {
        circuits: async (opts) => (await this.http.request<any[]>('GET', '/advanced/zk/circuits', undefined, opts)).data,
        setup: async (params, opts) => (await this.http.request('POST', '/advanced/zk/circuits', params, opts)).data,
        prove: async (params, opts) => (await this.http.request('POST', '/advanced/zk/prove', params, opts)).data,
        verify: async (params, opts) => (await this.http.request('POST', '/advanced/zk/verify', params, opts)).data,
      },
      fhe: {
        limits: async (opts) => (await this.http.request('GET', '/advanced/fhe/limits', undefined, opts)).data,
        context: async (params, opts) => (await this.http.request('POST', '/advanced/fhe/keygen', params, opts)).data,
        encrypt: async (params, opts) => (await this.http.request('POST', '/advanced/fhe/encrypt', params, opts)).data,
        evaluate: async (params, opts) => (await this.http.request('POST', '/advanced/fhe/evaluate', params, opts)).data,
        decrypt: async (params, opts) => (await this.http.request('POST', '/advanced/fhe/decrypt', params, opts)).data,
      },
      mpc: {
        createSession: async (params, opts) => (await this.http.request('POST', '/advanced/mpc/sessions', params, opts)).data,
        submitInput: async (sessionId, params, opts) => (await this.http.request('POST', `/advanced/mpc/sessions/${encodeURIComponent(sessionId)}/input`, params, opts)).data,
        compute: async (sessionId, params, opts) => (await this.http.request('POST', `/advanced/mpc/sessions/${encodeURIComponent(sessionId)}/execute`, params || {}, opts)).data,
      },
      threshold: {
        generateKeys: async (params, opts) => (await this.http.request('POST', '/advanced/threshold/keys', params, opts)).data,
        sign: async (params, opts) => (await this.http.request('POST', '/advanced/threshold/sessions', params, opts)).data,
        combine: async (sessionId, params, opts) => (await this.http.request('POST', `/advanced/threshold/sessions/${encodeURIComponent(sessionId)}/execute`, params || {}, opts)).data,
      },
    };

    // Webhooks Subclient
    this.webhooks = {
      list: async (opts) => (await this.http.request<WebhookEndpoint[]>('GET', '/webhooks', undefined, opts)).data,
      create: async (params, opts) => (await this.http.request<CreateWebhookResult>('POST', '/webhooks', params, opts)).data,
      get: async (id, opts) => (await this.http.request<WebhookEndpoint>('GET', `/webhooks/${encodeURIComponent(id)}`, undefined, opts)).data,
      update: async (id, params, opts) => (await this.http.request<WebhookEndpoint>('PATCH', `/webhooks/${encodeURIComponent(id)}`, params, opts)).data,
      delete: async (id, opts) => (await this.http.request<{ success: boolean }>('DELETE', `/webhooks/${encodeURIComponent(id)}`, undefined, opts)).data,
      rotateSecret: async (id, opts) => (await this.http.request<{ endpoint: Partial<WebhookEndpoint>; signingSecret: string; warning: string }>('POST', `/webhooks/${encodeURIComponent(id)}/rotate-secret`, {}, opts)).data,
      getDeliveries: async (id, opts) => (await this.http.request<WebhookDelivery[]>('GET', `/webhooks/${encodeURIComponent(id)}/deliveries`, undefined, opts)).data,
      testPing: async (id, opts) => (await this.http.request<any>('POST', `/webhooks/${encodeURIComponent(id)}/test`, {}, opts)).data,
      verifySignature: verifyWebhookSignature,
      constructEvent: constructWebhookEvent,
    };

    // Jobs Subclient
    this.jobs = {
      list: async (opts) => (await this.http.request<AsyncJob[]>('GET', '/jobs', undefined, opts)).data,
      submit: async (params, opts) => (await this.http.request<AsyncJob>('POST', '/jobs', params, opts)).data,
      get: async (id, opts) => (await this.http.request<AsyncJob>('GET', `/jobs/${encodeURIComponent(id)}`, undefined, opts)).data,
      cancel: async (id, opts) => (await this.http.request<{ success: boolean }>('POST', `/jobs/${encodeURIComponent(id)}/cancel`, {}, opts)).data,
      pollUntilComplete: async (id, pollIntervalMs = 2000, maxWaitMs = 120000) => {
        const startTime = Date.now();
        while (Date.now() - startTime < maxWaitMs) {
          const job = (await this.http.request<AsyncJob>('GET', `/jobs/${encodeURIComponent(id)}`)).data;
          if (job.status === 'COMPLETED') return job;
          if (job.status === 'FAILED') throw new Error(`Async job failed: ${job.error || 'Unknown error'}`);
          if (job.status === 'CANCELLED') throw new Error('Async job was cancelled');
          await new Promise((r) => setTimeout(r, pollIntervalMs));
        }
        throw new Error(`Polling timed out after ${maxWaitMs}ms`);
      },
    };

    // Usage Subclient
    this.usage = {
      get: async (opts) => {
        const q = opts?.from ? `?from=${encodeURIComponent(opts.from)}&to=${encodeURIComponent(opts.to || '')}` : '';
        const res = await this.http.request<UsageMetrics>('GET', `/usage${q}`, undefined, opts);
        return res.data;
      },
    };
  }

  // ==========================================================================
  // TOP-LEVEL ERGONOMIC UNIVERSAL CRYPTOGRAPHIC METHODS
  // ==========================================================================

  /**
   * Encrypts plaintext data using a managed logical key or a caller-supplied symmetric key.
   *
   * Automatically handles string or binary Buffer/Uint8Array inputs with zero client-side crypto overhead.
   */
  public async encrypt(params: EncryptRequest, options?: RequestOptions): Promise<EncryptResponse> {
    const payload: any = { ...params };

    if (isBinaryObject(params.data)) {
      payload.data = toBase64(params.data);
      payload.encoding = 'base64';
    }

    if (params.aad && isBinaryObject(params.aad)) {
      payload.aad = toBase64(params.aad);
    }

    const res = await this.http.request<EncryptResponse>('POST', '/encrypt', payload, options);
    return {
      ...res.data,
      operationId: res.operationId || res.data?.operationId || '',
      status: res.status || res.data?.status || 'COMPLETED',
      requestId: res.requestId || res.data?.requestId || '',
    };
  }

  /**
   * Decrypts ciphertext envelope using a managed logical key or caller-supplied symmetric key.
   *
   * Accepts individual ciphertext/iv/tag fields or the entire envelope object returned by encrypt().
   */
  public async decrypt(params: DecryptRequest, options?: RequestOptions): Promise<DecryptResponse> {
    const payload: any = { ...params };

    if (params.envelope && typeof params.envelope === 'object') {
      payload.envelope = { ...params.envelope };
    }

    const res = await this.http.request<DecryptResponse>('POST', '/decrypt', payload, options);
    return {
      ...res.data,
      data: res.data?.plaintext,
      operationId: res.operationId || res.data?.operationId || '',
      status: res.status || res.data?.status || 'COMPLETED',
      requestId: res.requestId || res.data?.requestId || '',
    };
  }

  /**
   * Phase 19 Cryptographic Migration Platform client methods.
   * Assess inventory, plan, simulate, approve, execute, and rollback migrations.
   */
  public get migrations() {
    return {
      assess: async (options?: RequestOptions): Promise<any[]> => {
        const res = await this.http.request<any>('GET', '/migrations/assess', undefined, options);
        return res.data || [];
      },
      createPlan: async (params: any, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', '/migrations/plans', params, options);
        return res.data;
      },
      listPlans: async (options?: RequestOptions): Promise<any[]> => {
        const res = await this.http.request<any>('GET', '/migrations/plans', undefined, options);
        return res.data || [];
      },
      getPlan: async (id: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('GET', `/migrations/plans/${id}`, undefined, options);
        return res.data;
      },
      simulatePlan: async (id: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/migrations/plans/${id}/simulate`, {}, options);
        return res.data;
      },
      approvePlan: async (id: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/migrations/plans/${id}/approve`, {}, options);
        return res.data;
      },
      executePlan: async (id: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/migrations/plans/${id}/execute`, {}, options);
        return res.data;
      },
      rollbackPlan: async (id: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/migrations/plans/${id}/rollback`, {}, options);
        return res.data;
      },
      reEncrypt: async (params: { sourceKeyId: string; targetKeyId: string; envelopes: any[] }, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', '/migrations/re-encrypt', params, options);
        return res.data;
      },
    };
  }

  /**
   * Phase 20 Enterprise Cryptographic Operating System client methods.
   * Unified inventory discovery, posture scoring, workflow orchestration, templates, and automations.
   */
  public get os() {
    return {
      getInventory: async (filter?: { type?: string; verifiedOnly?: boolean }, options?: RequestOptions): Promise<any[]> => {
        const queryParams = new URLSearchParams();
        if (filter?.type) queryParams.set('type', filter.type);
        if (filter?.verifiedOnly) queryParams.set('verifiedOnly', 'true');
        const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';
        const res = await this.http.request<any>('GET', `/os/inventory${qs}`, undefined, options);
        return res.data || [];
      },
      registerResource: async (params: any, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', '/os/resources', params, options);
        return res.data;
      },
      getPosture: async (options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('GET', '/os/posture', undefined, options);
        return res.data;
      },
      listTemplates: async (options?: RequestOptions): Promise<any[]> => {
        const res = await this.http.request<any>('GET', '/os/templates', undefined, options);
        return res.data || [];
      },
      instantiateTemplate: async (templateId: string, params?: any, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/os/templates/${templateId}/instantiate`, params || {}, options);
        return res.data;
      },
      listWorkflows: async (options?: RequestOptions): Promise<any[]> => {
        const res = await this.http.request<any>('GET', '/os/workflows', undefined, options);
        return res.data || [];
      },
      createWorkflow: async (params: any, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', '/os/workflows', params, options);
        return res.data;
      },
      getWorkflow: async (id: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('GET', `/os/workflows/${id}`, undefined, options);
        return res.data;
      },
      approveWorkflow: async (id: string, approverId: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/os/workflows/${id}/approve`, { approverId }, options);
        return res.data;
      },
      executeWorkflow: async (id: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/os/workflows/${id}/execute`, {}, options);
        return res.data;
      },
      cancelWorkflow: async (id: string, reason?: string, options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', `/os/workflows/${id}/cancel`, { reason }, options);
        return res.data;
      },
      evaluateAutomations: async (options?: RequestOptions): Promise<any> => {
        const res = await this.http.request<any>('POST', '/os/automations/evaluate', {}, options);
        return res.data;
      },
    };
  }

  /**
   * Computes a cryptographic digest over input data using FIPS-approved hashing algorithms.
   */
  public async hash(params: HashRequest, options?: RequestOptions): Promise<HashResponse> {
    const payload: any = {
      algorithm: 'SHA-256',
      ...params,
    };

    if (isBinaryObject(params.data)) {
      payload.data = toBase64(params.data);
      payload.encoding = 'base64';
    }

    const res = await this.http.request<HashResponse>('POST', '/hash', payload, options);
    return {
      ...res.data,
      operationId: res.operationId || res.data?.operationId || '',
      status: res.status || res.data?.status || 'COMPLETED',
      requestId: res.requestId || res.data?.requestId || '',
    };
  }

  /**
   * Generates a digital signature using an asymmetric or post-quantum signing key.
   */
  public async sign(params: SignRequest, options?: RequestOptions): Promise<SignResponse> {
    const payload: any = { ...params };

    if (isBinaryObject(params.data)) {
      payload.data = toBase64(params.data);
      payload.encoding = 'base64';
    }

    const res = await this.http.request<SignResponse>('POST', '/sign', payload, options);
    return {
      ...res.data,
      operationId: res.operationId || res.data?.operationId || '',
      status: res.status || res.data?.status || 'COMPLETED',
      requestId: res.requestId || res.data?.requestId || '',
    };
  }

  /**
   * Verifies the authenticity and integrity of a digital signature.
   */
  public async verify(params: VerifyRequest, options?: RequestOptions): Promise<VerifyResponse> {
    const payload: any = { ...params };

    if (isBinaryObject(params.data)) {
      payload.data = toBase64(params.data);
      payload.encoding = 'base64';
    }

    if (isBinaryObject(params.signature)) {
      payload.signature = toBase64(params.signature);
      payload.signatureEncoding = 'base64';
    }

    const res = await this.http.request<VerifyResponse>('POST', '/verify', payload, options);
    return {
      ...res.data,
      operationId: res.operationId || res.data?.operationId || '',
      status: res.status || res.data?.status || 'COMPLETED',
      requestId: res.requestId || res.data?.requestId || '',
    };
  }

  public static verifyWebhookSignature = verifyWebhookSignature;
  public static constructWebhookEvent = constructWebhookEvent;
}
