import hmac
import hashlib
import time
import json
from typing import Union, Dict, Any, Tuple
from .exceptions import WebhookVerificationError


def parse_webhook_header(header_value: str) -> Tuple[int, str]:
    if not header_value or not isinstance(header_value, str):
        raise WebhookVerificationError("Missing or invalid X-AMARACUS-Signature header.")

    parts = header_value.split(",")
    timestamp = None
    signature = None

    for part in parts:
        if "=" in part:
            k, v = part.strip().split("=", 1)
            if k == "t":
                try:
                    timestamp = int(v)
                except ValueError:
                    pass
            elif k == "v1":
                signature = v

    if timestamp is None or signature is None:
        raise WebhookVerificationError("Malformed X-AMARACUS-Signature header format. Expected 't=...,v1=...'")

    return timestamp, signature


def verify_signature(
    raw_payload: Union[str, bytes],
    header_value: str,
    secret: str,
    tolerance_seconds: int = 300,
) -> bool:
    """
    Verifies that a webhook payload was genuinely signed by AMARACUS using HMAC-SHA256,
    and protects against replay attacks by verifying the timestamp.
    """
    if not secret:
        raise WebhookVerificationError("Webhook signing secret is required.")

    timestamp, signature = parse_webhook_header(header_value)

    current_time = int(time.time())
    if abs(current_time - timestamp) > tolerance_seconds:
        raise WebhookVerificationError(
            f"Webhook timestamp outside tolerance window. Request: {timestamp}, Current: {current_time}, Tolerance: {tolerance_seconds}s"
        )

    payload_bytes = raw_payload.encode("utf-8") if isinstance(raw_payload, str) else raw_payload
    signed_payload = f"{timestamp}.".encode("utf-8") + payload_bytes

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature)


def construct_event(
    raw_payload: Union[str, bytes],
    header_value: str,
    secret: str,
    tolerance_seconds: int = 300,
) -> Dict[str, Any]:
    """
    Verifies webhook signature and decodes JSON payload into a Python dictionary.
    """
    if not verify_signature(raw_payload, header_value, secret, tolerance_seconds):
        raise WebhookVerificationError("HMAC-SHA256 signature mismatch.")

    payload_str = raw_payload.decode("utf-8") if isinstance(raw_payload, bytes) else raw_payload
    try:
        return json.loads(payload_str)
    except Exception as e:
        raise WebhookVerificationError(f"Malformed webhook JSON payload: {str(e)}")
