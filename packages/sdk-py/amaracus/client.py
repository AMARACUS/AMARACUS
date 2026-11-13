import os
import json
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List, Union
from .exceptions import (
    AmaracusError,
    AmaracusAuthenticationError,
    AmaracusPermissionError,
    AmaracusNotFoundError,
    AmaracusConflictError,
    AmaracusRateLimitError,
    AmaracusValidationError,
)
from .webhooks import verify_signature, construct_event


class HttpClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        default_headers: Optional[Dict[str, str]] = None,
    ):
        self.api_key = api_key or os.getenv("AMARACUS_API_KEY")
        self.base_url = (base_url or os.getenv("AMARACUS_BASE_URL") or "https://api.amaracus.tech/api/v1").rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.default_headers = default_headers or {}

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        idempotency_key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        req_headers = {
            "User-Agent": "amaracus-python-sdk/1.0.0",
            "Accept": "application/json",
            **self.default_headers,
            **(headers or {}),
        }

        if self.api_key:
            req_headers["Authorization"] = f"Bearer {self.api_key}"

        if idempotency_key:
            req_headers["Idempotency-Key"] = idempotency_key

        encoded_data = None
        if body is not None:
            req_headers["Content-Type"] = "application/json"
            encoded_data = json.dumps(body).encode("utf-8")

        attempt = 0
        delay = 0.3

        while True:
            attempt += 1
            req = urllib.request.Request(url, data=encoded_data, headers=req_headers, method=method)

            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    status_code = response.status
                    resp_headers = dict(response.headers)
                    raw_body = response.read().decode("utf-8")
                    req_id = resp_headers.get("x-request-id", "")

                    if raw_body:
                        try:
                            parsed = json.loads(raw_body)
                            if isinstance(parsed, dict) and "data" in parsed:
                                return parsed
                            return {"data": parsed, "requestId": req_id}
                        except json.JSONDecodeError:
                            return {"data": raw_body, "requestId": req_id}
                    return {"data": None, "requestId": req_id}

            except urllib.error.HTTPError as e:
                status_code = e.code
                err_body_raw = e.read().decode("utf-8")
                req_id = e.headers.get("x-request-id", "")
                err_code = "API_ERROR"
                err_msg = str(e)
                details = None

                try:
                    err_json = json.loads(err_body_raw)
                    if isinstance(err_json, dict) and "error" in err_json:
                        err_code = err_json["error"].get("code", err_code)
                        err_msg = err_json["error"].get("message", err_msg)
                        details = err_json["error"].get("details")
                        req_id = err_json["error"].get("requestId", req_id)
                except Exception:
                    pass

                # Handle retryable 429 and 5xx
                if (status_code == 429 or status_code >= 500) and attempt <= self.max_retries:
                    retry_after = e.headers.get("Retry-After")
                    wait_sec = float(retry_after) if retry_after else delay
                    time.sleep(wait_sec)
                    delay *= 2
                    continue

                if status_code == 400:
                    raise AmaracusValidationError(err_msg, req_id, details)
                elif status_code == 401:
                    raise AmaracusAuthenticationError(err_msg, req_id, details)
                elif status_code == 403:
                    raise AmaracusPermissionError(err_msg, req_id, details)
                elif status_code == 404:
                    raise AmaracusNotFoundError(err_msg, req_id, details)
                elif status_code == 409:
                    raise AmaracusConflictError(err_msg, req_id, details)
                elif status_code == 429:
                    retry_after_val = e.headers.get("Retry-After")
                    sec = int(retry_after_val) if retry_after_val and retry_after_val.isdigit() else None
                    raise AmaracusRateLimitError(err_msg, sec, req_id, details)
                else:
                    raise AmaracusError(err_msg, err_code, status_code, req_id, details)

            except Exception as e:
                if attempt <= self.max_retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise AmaracusError(f"Network error: {str(e)}", "NETWORK_ERROR", 0)


class CredentialsClient:
    def __init__(self, http: HttpClient):
        self._http = http

    def list(self, limit: int = 50, cursor: Optional[str] = None) -> List[Dict[str, Any]]:
        q = f"?limit={limit}" + (f"&cursor={cursor}" if cursor else "")
        res = self._http.request("GET", f"/credentials{q}")
        return res.get("data", [])

    def create(self, name: str, scopes: List[str], environment: str = "live", **kwargs) -> Dict[str, Any]:
        payload = {"name": name, "scopes": scopes, "environment": environment, **kwargs}
        res = self._http.request("POST", "/credentials", payload)
        return res.get("data", {})

    def get(self, credential_id: str) -> Dict[str, Any]:
        res = self._http.request("GET", f"/credentials/{credential_id}")
        return res.get("data", {})

    def update(self, credential_id: str, status: Optional[str] = None, name: Optional[str] = None) -> Dict[str, Any]:
        payload = {}
        if status:
            payload["status"] = status
        if name:
            payload["name"] = name
        res = self._http.request("PATCH", f"/credentials/{credential_id}", payload)
        return res.get("data", {})

    def rotate(self, credential_id: str) -> Dict[str, Any]:
        res = self._http.request("POST", f"/credentials/{credential_id}/rotate", {})
        return res.get("data", {})

    def revoke(self, credential_id: str) -> bool:
        self._http.request("DELETE", f"/credentials/{credential_id}")
        return True


class CryptoClient:
    """Raw-key operations (/crypto/*): the caller supplies the key material in ``key``.

    With ``key_id`` (a managed key) the call goes to the managed-key endpoints instead,
    the same ones the top-level ``Amaracus.encrypt`` / ``decrypt`` / ``sign`` / ``verify`` use.
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def algorithms(self) -> List[Dict[str, Any]]:
        return self._http.request("GET", "/crypto/algorithms").get("data", [])

    def policies(self) -> List[Dict[str, Any]]:
        return self._http.request("GET", "/crypto/policies").get("data", [])

    def encrypt(self, algorithm: str, plaintext: str, key: Optional[str] = None, key_id: Optional[str] = None, associated_data: Optional[str] = None) -> Dict[str, Any]:
        if key_id:
            payload = {"key": key_id, "algorithm": algorithm, "data": plaintext}
            if associated_data:
                payload["aad"] = associated_data
            return self._http.request("POST", "/encrypt", payload).get("data", {})
        payload = {"algorithm": algorithm, "plaintext": plaintext}
        if key:
            payload["key"] = key
        if associated_data:
            payload["aad"] = associated_data
        return self._http.request("POST", "/crypto/encrypt", payload).get("data", {})

    def decrypt(self, algorithm: str, ciphertext: str, key: Optional[str] = None, key_id: Optional[str] = None, iv: Optional[str] = None, tag: Optional[str] = None, associated_data: Optional[str] = None) -> Dict[str, Any]:
        payload = {"algorithm": algorithm, "ciphertext": ciphertext}
        if key_id:
            payload["key"] = key_id
        elif key:
            payload["key"] = key
        if iv:
            payload["iv"] = iv
        if tag:
            payload["tag"] = tag
        if associated_data:
            payload["aad"] = associated_data
        return self._http.request("POST", "/decrypt" if key_id else "/crypto/decrypt", payload).get("data", {})

    def sign(self, algorithm: str, data: str, key: Optional[str] = None, key_id: Optional[str] = None) -> Dict[str, Any]:
        if key_id:
            return self._http.request("POST", "/sign", {"key": key_id, "algorithm": algorithm, "data": data}).get("data", {})
        payload = {"algorithm": algorithm, "data": data}
        if key:
            payload["key"] = key
        return self._http.request("POST", "/crypto/sign", payload).get("data", {})

    def verify(self, algorithm: str, data: str, signature: str, key: Optional[str] = None, key_id: Optional[str] = None) -> bool:
        if key_id:
            res = self._http.request("POST", "/verify", {"key": key_id, "algorithm": algorithm, "data": data, "signature": signature})
            return bool(res.get("data", {}).get("valid", False))
        payload = {"algorithm": algorithm, "data": data, "signature": signature}
        if key:
            payload["key"] = key
        res = self._http.request("POST", "/crypto/verify", payload)
        return bool(res.get("data", {}).get("valid", False))


class PqcClient:
    def __init__(self, http: HttpClient):
        self._http = http

    def algorithms(self) -> List[str]:
        return self._http.request("GET", "/pqc/algorithms").get("data", [])

    def keypair(self, algorithm: str = "ML_KEM_768") -> Dict[str, str]:
        return self._http.request("POST", "/pqc/keypair", {"algorithm": algorithm}).get("data", {})

    def encapsulate(self, algorithm: str, public_key: str) -> Dict[str, str]:
        return self._http.request("POST", "/pqc/encapsulate", {"algorithm": algorithm, "publicKey": public_key}).get("data", {})

    def decapsulate(self, algorithm: str, cipher_text: str, private_key: str) -> Dict[str, str]:
        return self._http.request("POST", "/pqc/decapsulate", {"algorithm": algorithm, "cipherText": cipher_text, "privateKey": private_key}).get("data", {})

    def sign(self, algorithm: str, message: str, private_key: str) -> Dict[str, str]:
        return self._http.request("POST", "/pqc/sign", {"algorithm": algorithm, "message": message, "privateKey": private_key}).get("data", {})

    def verify(self, algorithm: str, message: str, signature: str, public_key: str) -> bool:
        res = self._http.request("POST", "/pqc/verify", {"algorithm": algorithm, "message": message, "signature": signature, "publicKey": public_key})
        return res.get("data", {}).get("valid", False)


class KeysClient:
    def __init__(self, http: HttpClient):
        self._http = http

    def list(self) -> List[Dict[str, Any]]:
        return self._http.request("GET", "/keys").get("data", [])

    def create(self, name: str, project_id: str, environment_id: str, algorithm: str, purpose: str, provider: str = "LOCAL_DEV", **kwargs) -> Dict[str, Any]:
        payload = {
            "name": name,
            "projectId": project_id,
            "environmentId": environment_id,
            "algorithm": algorithm,
            "purpose": purpose,
            "provider": provider,
            **kwargs,
        }
        return self._http.request("POST", "/keys", payload).get("data", {})

    def get(self, key_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/keys/{key_id}").get("data", {})

    def rotate(self, key_id: str) -> Dict[str, Any]:
        return self._http.request("POST", f"/keys/{key_id}/rotate", {}).get("data", {})

    def disable(self, key_id: str) -> Dict[str, Any]:
        """Disable a key: it can still decrypt and verify, but not encrypt or sign. Reversible."""
        return self._http.request("PATCH", f"/keys/{key_id}", {"status": "DISABLED"}).get("data", {})

    def revoke(self, key_id: str) -> Dict[str, Any]:
        """Revoke a key: from then on it can only verify. Irreversible."""
        return self._http.request("PATCH", f"/keys/{key_id}", {"status": "REVOKED"}).get("data", {})


class CertificatesClient:
    def __init__(self, http: HttpClient):
        self._http = http

    def list(self) -> List[Dict[str, Any]]:
        return self._http.request("GET", "/pki/certificates").get("data", [])

    def get(self, certificate_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/pki/certificates/{certificate_id}").get("data", {})

    def authorities(self) -> List[Dict[str, Any]]:
        return self._http.request("GET", "/pki/certificate-authorities").get("data", [])

    def issue(
        self,
        authority_id: str,
        project_id: str,
        environment_id: str,
        subject: str,
        san_dns: Optional[List[str]] = None,
        validity_days: int = 397,
        **kwargs,
    ) -> Dict[str, Any]:
        """Issue a certificate. ``subject`` is a distinguished name, e.g. ``"CN=api.example.com, O=Example"``."""
        payload = {
            "authorityId": authority_id,
            "projectId": project_id,
            "environmentId": environment_id,
            "subject": subject,
            "validityDays": validity_days,
            **kwargs,
        }
        if san_dns:
            payload["san"] = {"dns": san_dns}
        return self._http.request("POST", "/pki/certificates", payload).get("data", {})

    def revoke(self, certificate_id: str, reason: str = "UNSPECIFIED") -> Dict[str, Any]:
        return self._http.request("POST", f"/pki/certificates/{certificate_id}/revoke", {"reason": reason}).get("data", {})

    def validate(self, certificate_id: str) -> Dict[str, Any]:
        """Chain, expiry and revocation check of an issued certificate."""
        return self._http.request("POST", f"/pki/certificates/{certificate_id}/validate", {}).get("data", {})


class WebhooksClient:
    def __init__(self, http: HttpClient):
        self._http = http

    def list(self) -> List[Dict[str, Any]]:
        return self._http.request("GET", "/webhooks").get("data", [])

    def create(self, url: str, events: List[str], description: Optional[str] = None) -> Dict[str, Any]:
        return self._http.request("POST", "/webhooks", {"url": url, "events": events, "description": description}).get("data", {})

    def get(self, webhook_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/webhooks/{webhook_id}").get("data", {})

    def delete(self, webhook_id: str) -> bool:
        self._http.request("DELETE", f"/webhooks/{webhook_id}")
        return True

    def get_deliveries(self, webhook_id: str) -> List[Dict[str, Any]]:
        return self._http.request("GET", f"/webhooks/{webhook_id}/deliveries").get("data", [])

    def test_ping(self, webhook_id: str) -> Dict[str, Any]:
        return self._http.request("POST", f"/webhooks/{webhook_id}/test", {}).get("data", {})

    @staticmethod
    def verify_signature(raw_payload: Union[str, bytes], header_value: str, secret: str, tolerance_seconds: int = 300) -> bool:
        return verify_signature(raw_payload, header_value, secret, tolerance_seconds)

    @staticmethod
    def construct_event(raw_payload: Union[str, bytes], header_value: str, secret: str, tolerance_seconds: int = 300) -> Dict[str, Any]:
        return construct_event(raw_payload, header_value, secret, tolerance_seconds)


class JobsClient:
    def __init__(self, http: HttpClient):
        self._http = http

    def list(self) -> List[Dict[str, Any]]:
        return self._http.request("GET", "/jobs").get("data", [])

    def submit(self, job_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._http.request("POST", "/jobs", {"type": job_type, "payload": payload}).get("data", {})

    def get(self, job_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/jobs/{job_id}").get("data", {})

    def cancel(self, job_id: str) -> bool:
        self._http.request("POST", f"/jobs/{job_id}/cancel", {})
        return True

    def poll_until_complete(self, job_id: str, poll_interval: float = 2.0, max_wait: float = 120.0) -> Dict[str, Any]:
        start_time = time.time()
        while time.time() - start_time < max_wait:
            job = self.get(job_id)
            status = job.get("status")
            if status == "COMPLETED":
                return job
            if status == "FAILED":
                raise AmaracusError(f"Async job failed: {job.get('error')}", "JOB_FAILED")
            if status == "CANCELLED":
                raise AmaracusError("Async job was cancelled", "JOB_CANCELLED")
            time.sleep(poll_interval)
        raise AmaracusError(f"Polling timed out after {max_wait}s", "TIMEOUT")


class Amaracus:
    """AMARACUS Cryptographic Developer Platform Python Client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self._http = HttpClient(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=max_retries)
        self.credentials = CredentialsClient(self._http)
        self.crypto = CryptoClient(self._http)
        self.cryptography = self.crypto
        self.pqc = PqcClient(self._http)
        self.keys = KeysClient(self._http)
        self.certificates = CertificatesClient(self._http)
        self.webhooks = WebhooksClient(self._http)
        self.jobs = JobsClient(self._http)

    @property
    def http(self) -> HttpClient:
        return self._http

    # Managed-key operations (/encrypt, /decrypt, /hash, /sign, /verify).
    # Binary input: pass bytes; it is sent base64-encoded.

    @staticmethod
    def _data_fields(data: Union[str, bytes]) -> Dict[str, Any]:
        if isinstance(data, (bytes, bytearray)):
            import base64
            return {"data": base64.b64encode(bytes(data)).decode("ascii"), "encoding": "base64"}
        return {"data": data}

    def encrypt(self, key: str, data: Union[str, bytes], aad: Optional[str] = None, algorithm: Optional[str] = None) -> Dict[str, Any]:
        """Encrypt with a managed key. Keep ``envelope`` from the result: it is all decrypt() needs."""
        payload: Dict[str, Any] = {"key": key, **self._data_fields(data)}
        if aad is not None:
            payload["aad"] = aad
        if algorithm:
            payload["algorithm"] = algorithm
        return self._http.request("POST", "/encrypt", payload).get("data", {})

    def decrypt(
        self,
        key: str,
        envelope: Optional[str] = None,
        ciphertext: Optional[str] = None,
        iv: Optional[str] = None,
        tag: Optional[str] = None,
        aad: Optional[str] = None,
        version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Decrypt with a managed key. Pass ``envelope`` from encrypt(), or ciphertext/iv/tag (plus ``version`` for rotated keys).

        The result's ``encoding`` says whether ``plaintext`` is UTF-8 text or base64 (binary data).
        """
        payload: Dict[str, Any] = {"key": key}
        for name, value in (("envelope", envelope), ("ciphertext", ciphertext), ("iv", iv), ("tag", tag), ("aad", aad), ("version", version)):
            if value is not None:
                payload[name] = value
        return self._http.request("POST", "/decrypt", payload).get("data", {})

    def hash(self, data: Union[str, bytes], algorithm: str = "SHA-256") -> Dict[str, Any]:
        return self._http.request("POST", "/hash", {"algorithm": algorithm, **self._data_fields(data)}).get("data", {})

    def sign(self, key: str, data: Union[str, bytes], algorithm: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"key": key, **self._data_fields(data)}
        if algorithm:
            payload["algorithm"] = algorithm
        return self._http.request("POST", "/sign", payload).get("data", {})

    def verify(self, key: str, data: Union[str, bytes], signature: str, algorithm: Optional[str] = None) -> bool:
        payload: Dict[str, Any] = {"key": key, "signature": signature, **self._data_fields(data)}
        if algorithm:
            payload["algorithm"] = algorithm
        return bool(self._http.request("POST", "/verify", payload).get("data", {}).get("valid", False))

    @staticmethod
    def verify_webhook_signature(raw_payload: Union[str, bytes], header_value: str, secret: str, tolerance_seconds: int = 300) -> bool:
        return verify_signature(raw_payload, header_value, secret, tolerance_seconds)

    @staticmethod
    def construct_webhook_event(raw_payload: Union[str, bytes], header_value: str, secret: str, tolerance_seconds: int = 300) -> Dict[str, Any]:
        return construct_event(raw_payload, header_value, secret, tolerance_seconds)
