"""
AMARACUS Cryptographic Developer Platform Python SDK.
"""

from .client import Amaracus
from .exceptions import (
    AmaracusError,
    AmaracusAuthenticationError,
    AmaracusPermissionError,
    AmaracusNotFoundError,
    AmaracusConflictError,
    AmaracusRateLimitError,
    AmaracusValidationError,
    WebhookVerificationError,
)
from .webhooks import verify_signature, construct_event

__all__ = [
    "Amaracus",
    "AmaracusError",
    "AmaracusAuthenticationError",
    "AmaracusPermissionError",
    "AmaracusNotFoundError",
    "AmaracusConflictError",
    "AmaracusRateLimitError",
    "AmaracusValidationError",
    "WebhookVerificationError",
    "verify_signature",
    "construct_event",
]
__version__ = "1.0.0"
