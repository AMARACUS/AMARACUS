from typing import Optional, Dict, Any


class AmaracusError(Exception):
    """Base exception for all AMARACUS SDK errors."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.request_id = request_id
        self.details = details or {}

    def __str__(self) -> str:
        req_str = f" [request_id={self.request_id}]" if self.request_id else ""
        return f"[{self.code} {self.status_code}]{req_str}: {self.message}"


class AmaracusAuthenticationError(AmaracusError):
    """Raised when authentication fails or an API key is invalid/expired."""

    def __init__(self, message: str = "Authentication failed", request_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "UNAUTHENTICATED", 401, request_id, details)


class AmaracusPermissionError(AmaracusError):
    """Raised when the API key lacks the required scope for the operation."""

    def __init__(self, message: str = "Insufficient scope", request_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "INSUFFICIENT_SCOPE", 403, request_id, details)


class AmaracusNotFoundError(AmaracusError):
    """Raised when the requested resource does not exist."""

    def __init__(self, message: str = "Resource not found", request_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "RESOURCE_NOT_FOUND", 404, request_id, details)


class AmaracusConflictError(AmaracusError):
    """Raised when an idempotency conflict or resource state conflict occurs."""

    def __init__(self, message: str = "Conflict or concurrent mutation in progress", request_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFLICT", 409, request_id, details)


class AmaracusRateLimitError(AmaracusError):
    """Raised when rate limits are exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, "RATE_LIMIT_EXCEEDED", 429, request_id, details)
        self.retry_after = retry_after


class AmaracusValidationError(AmaracusError):
    """Raised when input parameters fail validation."""

    def __init__(self, message: str = "Invalid input parameters", request_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "INVALID_INPUT", 400, request_id, details)


class WebhookVerificationError(AmaracusError):
    """Raised when webhook signature verification fails."""

    def __init__(self, message: str = "Webhook signature verification failed"):
        super().__init__(message, "WEBHOOK_SIGNATURE_VERIFICATION_FAILED", 400)
