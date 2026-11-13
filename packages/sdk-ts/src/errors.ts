export interface AmaracusErrorDetails {
  code?: string;
  status?: number;
  requestId?: string;
  operationId?: string;
  retryable?: boolean;
  details?: Record<string, any>;
  cause?: unknown;
}

/**
 * Base error class for all AMARACUS SDK and API errors.
 * Guarantees zero leakage of private keys, plaintexts, or API keys in error strings.
 */
export class AmaracusError extends Error {
  public readonly code: string;
  public readonly status: number;
  public readonly statusCode: number;
  public readonly requestId?: string;
  public readonly operationId?: string;
  public readonly retryable: boolean;
  public readonly details?: Record<string, any>;

  constructor(
    message: string,
    options: AmaracusErrorDetails = {}
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = options.code || 'INTERNAL_ERROR';
    this.status = options.status || 500;
    this.statusCode = this.status;
    this.requestId = options.requestId;
    this.operationId = options.operationId;
    this.retryable = options.retryable ?? false;
    this.details = options.details;

    if (options.cause) {
      (this as any).cause = options.cause;
    }

    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when authentication fails (HTTP 401) due to missing, invalid, or revoked API key.
 */
export class AmaracusAuthenticationError extends AmaracusError {
  constructor(message = 'Authentication failed: Invalid, missing, or revoked API key.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'UNAUTHENTICATED',
      status: 401,
      retryable: false,
      ...options,
    });
  }
}

/**
 * Thrown when authorization fails (HTTP 403) due to missing required scope or policy denial.
 */
export class AmaracusAuthorizationError extends AmaracusError {
  constructor(message = 'Access denied: Insufficient scope or permissions.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'INSUFFICIENT_SCOPE',
      status: 403,
      retryable: false,
      ...options,
    });
  }
}

/**
 * Legacy alias for AmaracusAuthorizationError
 */
export const AmaracusPermissionError = AmaracusAuthorizationError;

/**
 * Thrown when request payload fails validation (HTTP 400).
 * Examples: missing parameters, unsupported algorithm, authenticity check failure.
 */
export class AmaracusValidationError extends AmaracusError {
  constructor(message = 'Invalid request parameters or payload.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'INVALID_REQUEST',
      status: 400,
      retryable: false,
      ...options,
    });
  }
}

/**
 * Thrown when requested resource or key does not exist or belongs to another tenant (HTTP 404).
 */
export class AmaracusNotFoundError extends AmaracusError {
  constructor(message = 'Requested resource or key not found.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'RESOURCE_NOT_FOUND',
      status: 404,
      retryable: false,
      ...options,
    });
  }
}

/**
 * Thrown when state conflict occurs (HTTP 409).
 */
export class AmaracusConflictError extends AmaracusError {
  constructor(message = 'Resource state conflict occurred.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'CONFLICT',
      status: 409,
      retryable: false,
      ...options,
    });
  }
}

/**
 * Thrown when rate limit or quota is exceeded (HTTP 429).
 */
export class AmaracusRateLimitError extends AmaracusError {
  public readonly retryAfter?: number;

  constructor(message = 'Rate limit exceeded.', retryAfter?: number, options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'RATE_LIMIT_EXCEEDED',
      status: 429,
      retryable: true,
      ...options,
    });
    this.retryAfter = retryAfter;
  }
}

/**
 * Thrown when request exceeds configured timeout duration.
 * Safe retry is NOT automatic for mutations to prevent double execution.
 */
export class AmaracusTimeoutError extends AmaracusError {
  constructor(message = 'The request timed out before receiving a response from AMARACUS.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: 'REQUEST_TIMEOUT',
      status: 408,
      retryable: false,
      ...options,
    });
  }
}

/**
 * Thrown when a backend KMS, Cloud HSM, or provider fails (HTTP 502 / 504).
 */
export class AmaracusProviderError extends AmaracusError {
  constructor(message = 'Cryptographic provider error occurred.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'PROVIDER_ERROR',
      status: 502,
      retryable: true,
      ...options,
    });
  }
}

/**
 * Thrown when AMARACUS server encounters an unhandled internal error (HTTP 500 / 503).
 */
export class AmaracusServerError extends AmaracusError {
  constructor(message = 'AMARACUS service error occurred.', options: AmaracusErrorDetails = {}) {
    super(message, {
      code: options.code || 'INTERNAL_ERROR',
      status: options.status || 500,
      retryable: true,
      ...options,
    });
  }
}
