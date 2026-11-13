import {
  AmaracusError,
  AmaracusAuthenticationError,
  AmaracusAuthorizationError,
  AmaracusValidationError,
  AmaracusNotFoundError,
  AmaracusConflictError,
  AmaracusRateLimitError,
  AmaracusTimeoutError,
  AmaracusProviderError,
  AmaracusServerError,
} from './errors';
import { ApiResponseEnvelope, RequestOptions } from './types';

export class HttpClient {
  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly defaultHeaders: Record<string, string>;

  constructor(options: {
    apiKey?: string;
    baseUrl?: string;
    timeout?: number;
    maxRetries?: number;
    defaultHeaders?: Record<string, string>;
  } = {}) {
    this.apiKey = options.apiKey || process.env.AMARACUS_API_KEY;

    let base = (options.baseUrl || process.env.AMARACUS_BASE_URL || 'https://api.amaracus.tech').replace(/\/+$/, '');
    if (!base.endsWith('/v1') && !base.endsWith('/api/v1')) {
      base = `${base}/v1`;
    }
    this.baseUrl = base;

    this.timeout = options.timeout ?? 30000;
    this.maxRetries = options.maxRetries ?? 2;
    this.defaultHeaders = options.defaultHeaders ?? {};
  }

  public async request<T = any>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    path: string,
    body?: any,
    options?: RequestOptions
  ): Promise<ApiResponseEnvelope<T>> {
    let cleanPath = path.startsWith('/') ? path : `/${path}`;
    if (cleanPath.startsWith('/v1/') && (this.baseUrl.endsWith('/v1') || this.baseUrl.endsWith('/api/v1'))) {
      cleanPath = cleanPath.slice(3);
    } else if (cleanPath === '/v1' && (this.baseUrl.endsWith('/v1') || this.baseUrl.endsWith('/api/v1'))) {
      cleanPath = '';
    }

    const url = `${this.baseUrl}${cleanPath}`;
    let attempt = 0;
    const isIdempotentMethod = method === 'GET';
    const hasIdempotencyKey = Boolean(options?.idempotencyKey);
    const isSafeToRetry = isIdempotentMethod || hasIdempotencyKey;

    const headers: Record<string, string> = {
      'User-Agent': '@amaracus/sdk/1.0.0',
      Accept: 'application/json',
      ...this.defaultHeaders,
      ...options?.headers,
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    if (body !== undefined && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    if (options?.idempotencyKey) {
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    while (true) {
      attempt++;
      let timer: NodeJS.Timeout | undefined;

      try {
        const controller = new AbortController();
        const timeoutDuration = options?.timeout ?? this.timeout;
        timer = setTimeout(() => controller.abort(), timeoutDuration);

        const response = await fetch(url, {
          method,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });

        clearTimeout(timer);

        const requestId = response.headers.get('x-request-id') || undefined;
        let responseJson: any = null;

        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          responseJson = await response.json();
        } else {
          const text = await response.text();
          responseJson = { data: text };
        }

        if (!response.ok) {
          const errCode = responseJson?.error?.code || 'API_ERROR';
          const errMsg = responseJson?.error?.message || `HTTP request failed with status ${response.status}`;
          const details = responseJson?.error?.details;
          const operationId = responseJson?.operationId || undefined;
          const retryAfterSec = parseInt(response.headers.get('retry-after') || '0', 10);

          // Check if retryable
          const isRateLimit = response.status === 429;
          const isServerError = response.status >= 500;
          const canRetry = (isRateLimit || (isServerError && isSafeToRetry)) && attempt <= this.maxRetries;

          if (canRetry) {
            const jitter = Math.floor(Math.random() * 100);
            const waitTime = retryAfterSec > 0
              ? retryAfterSec * 1000 + jitter
              : Math.min(5000, 300 * Math.pow(2, attempt - 1)) + jitter;

            await new Promise((resolve) => setTimeout(resolve, waitTime));
            continue;
          }

          const errorOptions = {
            code: errCode,
            status: response.status,
            requestId: responseJson?.requestId || requestId,
            operationId,
            retryable: responseJson?.error?.retryable ?? (isRateLimit || isServerError),
            details,
          };

          switch (response.status) {
            case 400:
              throw new AmaracusValidationError(errMsg, errorOptions);
            case 401:
              throw new AmaracusAuthenticationError(errMsg, errorOptions);
            case 403:
              throw new AmaracusAuthorizationError(errMsg, errorOptions);
            case 404:
              throw new AmaracusNotFoundError(errMsg, errorOptions);
            case 409:
              throw new AmaracusConflictError(errMsg, errorOptions);
            case 429:
              throw new AmaracusRateLimitError(errMsg, retryAfterSec || undefined, errorOptions);
            case 502:
            case 504:
              throw new AmaracusProviderError(errMsg, errorOptions);
            case 500:
            case 503:
            default:
              if (response.status >= 500) {
                throw new AmaracusServerError(errMsg, errorOptions);
              }
              throw new AmaracusError(errMsg, errorOptions);
          }
        }

        // Standard envelope return
        if (responseJson && typeof responseJson === 'object' && 'data' in responseJson) {
          return {
            data: responseJson.data,
            requestId: responseJson.requestId || requestId || '',
            operationId: responseJson.operationId,
            status: responseJson.status,
            mode: responseJson.mode,
            pollUrl: responseJson.pollUrl,
            durationMs: responseJson.durationMs,
            expiresAt: responseJson.expiresAt,
            pagination: responseJson.pagination,
            meta: responseJson.meta,
          };
        }

        return {
          data: responseJson as T,
          requestId: requestId || '',
        };
      } catch (err: any) {
        if (timer) {
          clearTimeout(timer);
        }

        if (err instanceof AmaracusError) {
          throw err;
        }

        // If request timed out via AbortController
        if (err.name === 'AbortError') {
          if (isSafeToRetry && attempt <= this.maxRetries) {
            const jitter = Math.floor(Math.random() * 100);
            await new Promise((resolve) => setTimeout(resolve, 300 * Math.pow(2, attempt - 1) + jitter));
            continue;
          }
          throw new AmaracusTimeoutError(`Request timed out after ${options?.timeout ?? this.timeout}ms`, {
            retryable: isSafeToRetry,
            cause: err,
          });
        }

        // Network drops or connection refused
        if (isSafeToRetry && attempt <= this.maxRetries) {
          const jitter = Math.floor(Math.random() * 100);
          await new Promise((resolve) => setTimeout(resolve, 300 * Math.pow(2, attempt - 1) + jitter));
          continue;
        }

        throw new AmaracusError(err.message || 'Network request failed', {
          code: 'NETWORK_ERROR',
          status: 0,
          retryable: isSafeToRetry,
          cause: err,
        });
      }
    }
  }
}
