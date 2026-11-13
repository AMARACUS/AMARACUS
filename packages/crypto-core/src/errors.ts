export type CryptoErrorCode =
  // Standard 22 Canonical BYOK/API Error Codes
  | 'INVALID_REQUEST'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'TENANT_ACCESS_DENIED'
  | 'PROVIDER_NOT_FOUND'
  | 'PROVIDER_NOT_CONFIGURED'
  | 'PROVIDER_UNAVAILABLE'
  | 'AUTHORIZATION_FAILED'
  | 'RESOURCE_NOT_FOUND'
  | 'KEY_NOT_FOUND'
  | 'KEY_DISABLED'
  | 'KEY_REVOKED'
  | 'KEY_EXPIRED'
  | 'OPERATION_NOT_SUPPORTED'
  | 'ALGORITHM_NOT_SUPPORTED'
  | 'CAPABILITY_UNKNOWN'
  | 'PURPOSE_NOT_ALLOWED'
  | 'CRYPTO_OPERATION_FAILED'
  | 'ENTITLEMENT_REQUIRED'
  | 'RATE_LIMITED'
  | 'CONFLICT'
  | 'INTERNAL_ERROR'
  | 'POLICY_DENIED'
  | 'KEY_ROTATION_REQUIRED'
  | 'INSUFFICIENT_SECURITY'
  | 'PROVIDER_NOT_APPROVED'
  | 'PROVIDER_CAPABILITY_MISSING'
  | 'TIMEOUT'
  | 'OPERATION_FAILED'
  // Existing Core Engine Codes
  | 'INVALID_INPUT'
  | 'UNSUPPORTED_ALGORITHM'
  | 'POLICY_VIOLATION'
  | 'INVALID_KEY'
  | 'INVALID_NONCE'
  | 'AUTHENTICATION_FAILED'
  | 'SIGNATURE_INVALID'
  | 'UNAUTHORIZED'
  | 'INTERNAL_CRYPTO_ERROR'
  | 'PROVIDER_UNCONFIGURED'
  | 'UNSUPPORTED_OPERATION'
  | 'UNSUPPORTED_PROVIDER'
  | 'INVALID_STATE_TRANSITION'
  | 'KEY_DESTROYED'
  | 'INVALID_PURPOSE'
  | 'CONNECTION_ERROR'
  | 'UNSUPPORTED_PQC_X509';

export class CryptoEngineError extends Error {
  public readonly code: CryptoErrorCode;
  public readonly status: number;
  public readonly details?: Record<string, any>;

  constructor(code: CryptoErrorCode, message: string, status = 400, details?: Record<string, any>) {
    super(message);
    this.name = 'CryptoEngineError';
    this.code = code;
    this.status = status;
    this.details = details;
    Object.setPrototypeOf(this, CryptoEngineError.prototype);
  }
}
