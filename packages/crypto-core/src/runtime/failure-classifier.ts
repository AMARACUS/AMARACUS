/**
 * AMARACUS Cryptographic Infrastructure — Failure Classifier
 *
 * Authoritatively classifies cryptographic operation errors into retryable vs non-retryable.
 * Guarantees that permanent client errors or security violations are never retried,
 * while transient network and provider outages can be safely retried with backoff.
 */

export type FailureCategory =
  | 'CLIENT_VALIDATION'
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'RESOURCE_NOT_FOUND'
  | 'INTEGRITY_CHECK_FAILED'
  | 'POLICY_DENIED'
  | 'ALGORITHM_UNSUPPORTED'
  | 'TRANSIENT_PROVIDER_OUTAGE'
  | 'PROVIDER_TIMEOUT'
  | 'RATE_LIMIT_EXCEEDED'
  | 'INTERNAL_ERROR';

export interface ClassifiedFailure {
  retryable: boolean;
  category: FailureCategory;
  code: string;
  message: string;
  statusCode: number;
}

export class FailureClassifier {
  /**
   * Evaluates any thrown error and returns its classification.
   */
  public static classify(err: any): ClassifiedFailure {
    if (!err) {
      return {
        retryable: false,
        category: 'INTERNAL_ERROR',
        code: 'UNKNOWN_ERROR',
        message: 'An unknown error occurred.',
        statusCode: 500,
      };
    }

    const code = String(err.code || err.name || 'INTERNAL_ERROR').toUpperCase();
    const msg = String(err.message || '');
    const status = Number(err.statusCode || err.status || 500);

    // 1. Client Validation Errors (NEVER RETRY)
    if (
      status === 400 ||
      code === 'INVALID_REQUEST' ||
      code === 'INVALID_PARAMS' ||
      code === 'INVALID_NONCE' ||
      code === 'VALIDATION_ERROR'
    ) {
      return {
        retryable: false,
        category: 'CLIENT_VALIDATION',
        code: code || 'INVALID_REQUEST',
        message: msg || 'Invalid request parameters.',
        statusCode: 400,
      };
    }

    // 2. Authentication Errors (NEVER RETRY)
    if (status === 401 || code === 'UNAUTHENTICATED' || code === 'INVALID_API_KEY') {
      return {
        retryable: false,
        category: 'AUTHENTICATION',
        code: 'UNAUTHENTICATED',
        message: msg || 'Authentication failed.',
        statusCode: 401,
      };
    }

    // 3. Authorization / Scope / Policy Errors (NEVER RETRY)
    if (
      status === 403 ||
      code === 'INSUFFICIENT_SCOPE' ||
      code === 'FORBIDDEN' ||
      code === 'POLICY_DENIED' ||
      code === 'KEY_LIMIT_REACHED'
    ) {
      return {
        retryable: false,
        category: code === 'POLICY_DENIED' ? 'POLICY_DENIED' : 'AUTHORIZATION',
        code,
        message: msg || 'Action forbidden.',
        statusCode: 403,
      };
    }

    // 4. Resource Not Found / Key Not Found (NEVER RETRY)
    if (status === 404 || code === 'KEY_NOT_FOUND' || code === 'NOT_FOUND') {
      return {
        retryable: false,
        category: 'RESOURCE_NOT_FOUND',
        code: 'KEY_NOT_FOUND',
        message: msg || 'Key or resource not found.',
        statusCode: 404,
      };
    }

    // 5. Integrity / Auth Tag Failure (Tampered Ciphertext - NEVER RETRY)
    if (
      code === 'AUTHENTICATION_FAILED' ||
      code === 'DECRYPTION_FAILED' ||
      msg.includes('tampered') ||
      msg.includes('authentication failed')
    ) {
      return {
        retryable: false,
        category: 'INTEGRITY_CHECK_FAILED',
        code: 'AUTHENTICATION_FAILED',
        message: 'Decryption authenticity check failed: data or tag was tampered.',
        statusCode: 400,
      };
    }

    // 6. Unsupported Algorithm (NEVER RETRY)
    if (
      code === 'UNSUPPORTED_ALGORITHM' ||
      code === 'ALGORITHM_UNSUPPORTED' ||
      code === 'PROVIDER_CAPABILITY_MISSING'
    ) {
      return {
        retryable: false,
        category: 'ALGORITHM_UNSUPPORTED',
        code,
        message: msg || 'Cryptographic algorithm or capability not supported.',
        statusCode: 400,
      };
    }

    // 7. Rate Limits (RETRYABLE with Backoff)
    if (status === 429 || code === 'RATE_LIMIT_EXCEEDED' || code === 'TOO_MANY_REQUESTS') {
      return {
        retryable: true,
        category: 'RATE_LIMIT_EXCEEDED',
        code: 'RATE_LIMIT_EXCEEDED',
        message: msg || 'Rate limit exceeded.',
        statusCode: 429,
      };
    }

    // 8. Timeouts (RETRYABLE on safe/idempotent contexts)
    if (
      status === 408 ||
      code === 'TIMEOUT' ||
      code === 'ETIMEDOUT' ||
      code === 'REQUEST_TIMEOUT' ||
      err.name === 'AbortError' ||
      msg.includes('timed out')
    ) {
      return {
        retryable: true,
        category: 'PROVIDER_TIMEOUT',
        code: 'TIMEOUT',
        message: 'Operation or provider request timed out.',
        statusCode: 504,
      };
    }

    // 9. Transient Provider / Infrastructure Outages (RETRYABLE)
    if (
      status === 502 ||
      status === 503 ||
      status === 504 ||
      code === 'PROVIDER_UNAVAILABLE' ||
      code === 'ECONNRESET' ||
      code === 'ECONNREFUSED' ||
      code === 'ENOTFOUND'
    ) {
      return {
        retryable: true,
        category: 'TRANSIENT_PROVIDER_OUTAGE',
        code: code === 'PROVIDER_UNAVAILABLE' ? 'PROVIDER_UNAVAILABLE' : 'SERVICE_UNAVAILABLE',
        message: msg || 'Cryptographic provider temporarily unavailable.',
        statusCode: status >= 500 ? status : 503,
      };
    }

    // Default: internal server error
    return {
      retryable: err.retryable === true,
      category: 'INTERNAL_ERROR',
      code: code || 'INTERNAL_ERROR',
      message: msg || 'An internal error occurred.',
      statusCode: status >= 400 && status < 600 ? status : 500,
    };
  }
}

export const classifyFailure = FailureClassifier.classify;

