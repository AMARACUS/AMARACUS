import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { hashApiKey } from '../src/lib/api-keys';
import { verifyWebhookSignature } from '@amaracus/sdk';
import crypto from 'crypto';

describe('Phase 10 — Developer Platform, Canonical /api/v1, SDK & DX Integration Tests', () => {
  let server: http.Server;
  let baseUrl: string;

  let sessionToken: string;
  let orgId: string;
  let projectId: string;
  let envId: string;

  let liveApiKey: string;
  let credentialId: string;

  beforeAll(async () => {
    // Start test server
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const address = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });

    // Sign up real user, organization, and establish session
    const signupRes = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `dev_platform_${Date.now()}@amaracus.dev`,
        password: 'Password1234!',
        name: 'Developer Alice',
        organizationName: 'Alice Cryptographic Enterprise',
        termsAccepted: true,
        ageAttested: true,
      }),
    });

    const signupData = await signupRes.json();
    sessionToken = signupData.session.token;
    orgId = signupData.activeOrganization.id;

    // Create project and environment
    const projRes = await fetch(`${baseUrl}/v1/organizations/${orgId}/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({ name: 'Production Payments' }),
    });
    const projData = await projRes.json();
    projectId = projData.project.id;
    envId = projData.project.environments[0].id;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  // 1. Health and Documentation
  describe('1. Health and OpenAPI Documentation', () => {
    it('GET /api/v1/health - returns operational envelope', async () => {
      const res = await fetch(`${baseUrl}/api/v1/health`);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.status).toBe('ok');
      expect(json.data.service).toBe('amaracus-developer-platform');
      expect(json.requestId).toBeDefined();
      expect(res.headers.get('x-request-id')).toBeDefined();
    });

    it('GET /api/v1/openapi.json - serves valid OpenAPI 3.1 specification', async () => {
      const res = await fetch(`${baseUrl}/api/v1/openapi.json`);
      expect(res.status).toBe(200);
      const spec = await res.json();
      expect(spec.openapi).toBe('3.1.0');
      expect(spec.info.title).toContain('AMARACUS');
      expect(spec.paths['/pqc/keypair']).toBeDefined();
      expect(spec.paths['/crypto/encrypt']).toBeDefined();
      expect(spec.paths['/credentials']).toBeDefined();
    });

    it('GET /api/v1/docs - serves interactive Swagger UI HTML', async () => {
      const res = await fetch(`${baseUrl}/api/v1/docs`);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('SwaggerUIBundle');
      expect(html).toContain('/api/v1/openapi.json');
    });
  });

  // 2. Credential Lifecycle & Scopes
  describe('2. API Credentials, Scopes & Authentication', () => {
    it('POST /api/v1/credentials - generates scoped API key with one-time raw secret', async () => {
      const res = await fetch(`${baseUrl}/api/v1/credentials`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`,
          'x-organization-id': orgId,
        },
        body: JSON.stringify({
          name: 'Core Payment Key',
          environment: 'live',
          scopes: [
            'crypto:execute',
            'crypto:read',
            'keys:read',
            'keys:create',
            'keys:rotate',
            'pqc:execute',
            'webhooks:read',
            'webhooks:write',
            'jobs:read',
            'jobs:write',
            'usage:read',
          ],
          projectId,
          environmentId: envId,
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.credential).toBeDefined();
      expect(json.data.rawApiKey).toBeDefined();
      expect(json.data.rawApiKey.startsWith('am_live_')).toBe(true);
      expect(json.data.credential.status).toBe('ACTIVE');
      expect(json.data.credential.scopes).toContain('crypto:execute');
      expect(json.data.credential.scopes).toContain('pqc:execute');

      liveApiKey = json.data.rawApiKey;
      credentialId = json.data.credential.id;

      // Verify zero secret leakage: rawApiKey must NOT be stored in database!
      const inDb = await db.findCredentialById(credentialId);
      expect(inDb).toBeDefined();
      expect((inDb as any).keyHash).toBe(hashApiKey(liveApiKey));
      expect(JSON.stringify(inDb)).not.toContain(liveApiKey);
    });

    it('GET /api/v1/auth/me - authenticates with Bearer API Key', async () => {
      const res = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: {
          Authorization: `Bearer ${liveApiKey}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.type).toBe('API_CREDENTIAL');
      expect(json.data.id).toBe(credentialId);
      expect(json.data.organizationId).toBe(orgId);
      expect(json.data.status).toBe('ACTIVE');
      expect(json.data.scopes).toContain('crypto:execute');
    });

    it('GET /api/v1/auth/me - rejects invalid API key with 401 UNAUTHENTICATED', async () => {
      const res = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: {
          Authorization: `Bearer am_live_invalid_fake_key_1234567890`,
        },
      });

      expect(res.status).toBe(401);
      const json = await res.json();
      expect(['UNAUTHENTICATED', 'INVALID_API_KEY']).toContain(json.error.code);
    });

    it('Scope Enforcement - blocks operations when required scope is missing', async () => {
      // Create credential with ONLY keys:read scope
      const credRes = await fetch(`${baseUrl}/api/v1/credentials`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`,
          'x-organization-id': orgId,
        },
        body: JSON.stringify({
          name: 'Read-Only Keys Token',
          scopes: ['keys:read'],
          projectId,
          environmentId: envId,
        }),
      });

      const readOnlyCred = await credRes.json();
      const readOnlyKey = readOnlyCred.data.rawApiKey;

      // Attempt crypto execution with read-only key -> MUST FAIL with 403 INSUFFICIENT_SCOPE
      const cryptoRes = await fetch(`${baseUrl}/api/v1/crypto/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${readOnlyKey}`,
        },
        body: JSON.stringify({
          algorithm: 'AES_256_GCM',
          plaintext: 'Secret Data',
          key: Buffer.alloc(32, 1).toString('base64'),
        }),
      });

      expect(cryptoRes.status).toBe(403);
      const cryptoErr = await cryptoRes.json();
      expect(cryptoErr.error.code).toBe('INSUFFICIENT_SCOPE');
      expect(cryptoErr.error.message).toContain('crypto:execute');

      // Attempt keys read with read-only key -> MUST SUCCEED
      const keysRes = await fetch(`${baseUrl}/api/v1/keys`, {
        headers: {
          Authorization: `Bearer ${readOnlyKey}`,
        },
      });
      expect(keysRes.status).toBe(200);
    });

    it('Multi-Tenant Isolation - prevents API key from accessing other organizations', async () => {
      // Attempt to access with x-organization-id set to another org
      const res = await fetch(`${baseUrl}/api/v1/keys`, {
        headers: {
          'Authorization': `Bearer ${liveApiKey}`,
          'x-organization-id': 'org_unauthorized_other_tenant',
        },
      });

      expect(res.status).toBe(403);
      const json = await res.json();
      expect(json.error.code).toBe('TENANT_ACCESS_DENIED');
    });

    it('POST /api/v1/credentials/:id/rotate - rotates key and invalidates previous secret', async () => {
      const rotateRes = await fetch(`${baseUrl}/api/v1/credentials/${credentialId}/rotate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
          'x-organization-id': orgId,
        },
      });

      expect(rotateRes.status).toBe(200);
      const rotateJson = await rotateRes.json();
      const newApiKey = rotateJson.data.rawApiKey;
      expect(newApiKey).toBeDefined();
      expect(newApiKey).not.toBe(liveApiKey);

      // Old API key MUST now be rejected with 401
      const oldCheck = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${liveApiKey}` },
      });
      expect(oldCheck.status).toBe(401);

      // New API key MUST now authenticate successfully
      const newCheck = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${newApiKey}` },
      });
      expect(newCheck.status).toBe(200);

      // Use new key for subsequent tests
      liveApiKey = newApiKey;
    });

    it('PATCH /api/v1/credentials/:id - disables and re-enables credential', async () => {
      // Disable key
      const disableRes = await fetch(`${baseUrl}/api/v1/credentials/${credentialId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`,
          'x-organization-id': orgId,
        },
        body: JSON.stringify({ status: 'DISABLED' }),
      });
      expect(disableRes.status).toBe(200);

      // Request with disabled key -> 401 CREDENTIAL_DISABLED
      const checkRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${liveApiKey}` },
      });
      expect(checkRes.status).toBe(401);
      const json = await checkRes.json();
      expect(['CREDENTIAL_DISABLED', 'API_KEY_DISABLED']).toContain(json.error.code);

      // Re-enable key
      await fetch(`${baseUrl}/api/v1/credentials/${credentialId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`,
          'x-organization-id': orgId,
        },
        body: JSON.stringify({ status: 'ACTIVE' }),
      });

      const reCheck = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${liveApiKey}` },
      });
      expect(reCheck.status).toBe(200);
    });
  });

  // 3. Idempotency Middleware
  describe('3. Idempotency & Safe Deduplication', () => {
    it('honors Idempotency-Key and replays identical response with X-Cache header', async () => {
      const idempotencyKey = `idem_test_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

      const payload = {
        name: `Idempotent Key ${Date.now()}`,
        algorithm: 'AES_256_GCM',
        purpose: 'ENCRYPT_DECRYPT',
        projectId,
        environmentId: envId,
        provider: 'LOCAL_DEV',
      };

      // 1. First execution
      const res1 = await fetch(`${baseUrl}/api/v1/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(payload),
      });

      expect(res1.status).toBe(201);
      expect(res1.headers.get('x-cache')).toBeNull();
      const data1 = await res1.json();
      const createdKeyId = data1.data.id;
      expect(createdKeyId).toBeDefined();

      // 2. Second execution with identical Idempotency-Key
      const res2 = await fetch(`${baseUrl}/api/v1/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(payload),
      });

      expect(res2.status).toBe(201);
      expect(res2.headers.get('x-cache')).toBe('IDEMPOTENT_REPLAY');
      const data2 = await res2.json();
      expect(data2.data.id).toBe(createdKeyId);
      expect(data2.data.name).toBe(payload.name);
    });
  });

  // 4. Post-Quantum Cryptography & Classical Operations via /api/v1
  describe('4. Post-Quantum & Classical Cryptographic Operations', () => {
    let kemPublicKey: string;
    let kemPrivateKey: string;
    let kemCipherText: string;
    let senderSharedSecret: string;

    it('POST /api/v1/pqc/keypair - generates NIST FIPS 203 ML-KEM-768 keypair', async () => {
      const res = await fetch(`${baseUrl}/api/v1/pqc/keypair`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
        },
        body: JSON.stringify({ algorithm: 'ML_KEM_768' }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.algorithm).toBe('ML_KEM_768');
      expect(json.data.publicKey).toBeDefined();
      expect(json.data.privateKey).toBeDefined();

      kemPublicKey = json.data.publicKey;
      kemPrivateKey = json.data.privateKey;
    });

    it('POST /api/v1/pqc/encapsulate - encapsulates shared secret under ML-KEM public key', async () => {
      const res = await fetch(`${baseUrl}/api/v1/pqc/encapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
        },
        body: JSON.stringify({
          algorithm: 'ML_KEM_768',
          publicKey: kemPublicKey,
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.cipherText).toBeDefined();
      expect(json.data.sharedSecret).toBeDefined();

      kemCipherText = json.data.cipherText;
      senderSharedSecret = json.data.sharedSecret;
    });

    it('POST /api/v1/pqc/decapsulate - decapsulates matching shared secret', async () => {
      const res = await fetch(`${baseUrl}/api/v1/pqc/decapsulate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
        },
        body: JSON.stringify({
          algorithm: 'ML_KEM_768',
          cipherText: kemCipherText,
          privateKey: kemPrivateKey,
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.sharedSecret).toBe(senderSharedSecret);
    });

    it('POST /api/v1/crypto/encrypt and /decrypt - round-trip AES-256-GCM', async () => {
      const rawKey = Buffer.alloc(32, 7).toString('base64');
      const plaintext = 'Secret Developer Platform Payload 2026';

      const encRes = await fetch(`${baseUrl}/api/v1/crypto/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
        },
        body: JSON.stringify({
          algorithm: 'AES_256_GCM',
          plaintext,
          key: rawKey,
        }),
      });

      expect(encRes.status).toBe(200);
      const encJson = await encRes.json();
      expect(encJson.data.ciphertext).toBeDefined();
      expect(encJson.data.iv).toBeDefined();
      expect(encJson.data.tag).toBeDefined();

      const decRes = await fetch(`${baseUrl}/api/v1/crypto/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
        },
        body: JSON.stringify({
          algorithm: 'AES_256_GCM',
          ciphertext: encJson.data.ciphertext,
          iv: encJson.data.iv,
          tag: encJson.data.tag,
          key: rawKey,
        }),
      });

      expect(decRes.status).toBe(200);
      const decJson = await decRes.json();
      expect(decJson.data.plaintext).toBe(plaintext);
    });
  });

  // 5. Webhooks & Signatures
  describe('5. Webhooks, Dispatcher & HMAC-SHA256 Signatures', () => {
    let webhookId: string;
    let signingSecret: string;

    it('POST /api/v1/webhooks - creates endpoint with one-time signing secret', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
        },
        body: JSON.stringify({
          url: 'https://api.external.corp/amaracus/events',
          description: 'Payment listener',
          events: ['key.rotated', 'certificate.issued'],
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.webhook.id).toBeDefined();
      expect(json.data.webhook.status).toBe('ACTIVE');
      expect(json.data.signingSecret).toBeDefined();
      expect(json.data.signingSecret.startsWith('whsec_')).toBe(true);

      webhookId = json.data.webhook.id;
      signingSecret = json.data.signingSecret;
    });

    it('POST /api/v1/webhooks/:id/test - triggers test ping and records delivery', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks/${webhookId}/test`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${liveApiKey}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.success).toBe(true);
      expect(json.data.delivery).toBeDefined();
      expect(json.data.delivery.event).toBe('webhook.test_ping');
    });

    it('verifies HMAC-SHA256 signature with SDK verifyWebhookSignature', () => {
      const payload = JSON.stringify({ event: 'key.rotated', keyId: 'key_123456' });
      const timestamp = Math.floor(Date.now() / 1000);
      const signedPayload = `${timestamp}.${payload}`;

      const hmac = crypto
        .createHmac('sha256', signingSecret)
        .update(signedPayload, 'utf-8')
        .digest('hex');

      const headerValue = `t=${timestamp},v1=${hmac}`;

      // Signature verification MUST return true
      const valid = verifyWebhookSignature(payload, headerValue, signingSecret, 300);
      expect(valid).toBe(true);

      // Tampered payload MUST return false
      const tampered = verifyWebhookSignature(payload + '!', headerValue, signingSecret, 300);
      expect(tampered).toBe(false);

      // Expired timestamp (>300s) MUST throw WebhookVerificationError
      const expiredHeader = `t=${timestamp - 400},v1=${hmac}`;
      expect(() => verifyWebhookSignature(payload, expiredHeader, signingSecret, 300)).toThrow();
    });
  });

  // 6. Async Jobs Runner
  describe('6. Asynchronous Cryptographic Heavy Jobs', () => {
    it('POST /api/v1/jobs - submits async ZK job and polls status until completion', async () => {
      const submitRes = await fetch(`${baseUrl}/api/v1/jobs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${liveApiKey}`,
        },
        body: JSON.stringify({
          type: 'ZK_PROVE',
          payload: { circuitId: 'circ_age_check', witness: 'val_42' },
        }),
      });

      expect(submitRes.status).toBe(202);
      const submitJson = await submitRes.json();
      const jobId = submitJson.data.id;
      expect(jobId).toBeDefined();
      expect(['QUEUED', 'PROCESSING', 'COMPLETED']).toContain(submitJson.data.status);

      // Poll job until complete
      let completed = false;
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 200));
        const statusRes = await fetch(`${baseUrl}/api/v1/jobs/${jobId}`, {
          headers: { Authorization: `Bearer ${liveApiKey}` },
        });
        const statusJson = await statusRes.json();
        if (statusJson.data.status === 'COMPLETED') {
          completed = true;
          expect(statusJson.data.result).toBeDefined();
          expect(statusJson.data.progress).toBe(100);
          break;
        }
      }
      expect(completed).toBe(true);
    });
  });

  // 7. Telemetry & Usage Tracking
  describe('7. Telemetry & API Usage', () => {
    it('GET /api/v1/usage - returns telemetry metrics', async () => {
      const res = await fetch(`${baseUrl}/api/v1/usage`, {
        headers: { Authorization: `Bearer ${liveApiKey}` },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.totalRequests).toBeGreaterThanOrEqual(0);
      expect(json.data.avgLatencyMs).toBeDefined();
    });
  });
});
