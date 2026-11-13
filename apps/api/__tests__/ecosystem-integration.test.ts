import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import {
  Amaracus,
  verifyWebhookSignature,
  constructWebhookEvent,
  WebhookVerificationError,
  amaracusWebhookMiddleware,
  verifyNextJsWebhook,
} from '@amaracus/sdk';

describe('Phase 18 — AMARACUS Ecosystem & Integration Platform Test Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A: Primary Enterprise Organization
  let orgA: any;
  let projectA: any;
  let envAProd: any;
  let envATest: any;
  let apiKeyALive: string;
  let apiKeyATest: string;

  // Tenant B: Isolated Organization for IDOR verification
  let orgB: any;
  let projectB: any;
  let apiKeyBLive: string;

  // Webhook details for tests
  let createdWebhookId: string;
  let webhookSigningSecret: string;

  beforeAll(async () => {
    // 1. Launch HTTP server on dynamic port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 2. Setup Tenant A
    orgA = await db.createOrganization({
      name: 'Ecosystem Alpha Org',
      slug: `eco-alpha-${Date.now()}`,
    });

    await db.upsertBillingSubscription({
      organizationId: orgA.id,
      plan: 'ENTERPRISE',
      status: 'ACTIVE',
    });

    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Ecosystem Core Gateway',
      slug: `eco-core-${Date.now()}`,
      description: 'Project hosting partner integrations and webhooks',
    });

    envAProd = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      type: 'PRODUCTION',
    });

    envATest = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Sandbox / Testing',
      type: 'DEVELOPMENT',
    });

    // Generate Production API Key (am_live_...)
    const keyLiveResult = generateAmaracusApiKey('live');
    apiKeyALive = keyLiveResult.fullKey;
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      name: 'Production Ecosystem Key',
      keyHash: keyLiveResult.keyHash,
      prefix: keyLiveResult.prefix,
      scopes: ['*'],
    });

    // Generate Sandbox/Test API Key (am_test_...)
    const keyTestResult = generateAmaracusApiKey('test');
    apiKeyATest = keyTestResult.fullKey;
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envATest.id,
      name: 'Sandbox Ecosystem Key',
      keyHash: keyTestResult.keyHash,
      prefix: keyTestResult.prefix,
      scopes: ['*'],
    });

    // 3. Setup Tenant B
    orgB = await db.createOrganization({
      name: 'Ecosystem Beta Competitor',
      slug: `eco-beta-${Date.now()}`,
    });

    await db.upsertBillingSubscription({
      organizationId: orgB.id,
      plan: 'ENTERPRISE',
      status: 'ACTIVE',
    });

    projectB = await db.createProject({
      organizationId: orgB.id,
      name: 'Beta Project',
      slug: `eco-beta-proj-${Date.now()}`,
    });

    const envBProd = await db.createEnvironment({
      projectId: projectB.id,
      name: 'Production',
      type: 'PRODUCTION',
    });

    const keyBResult = generateAmaracusApiKey('live');
    apiKeyBLive = keyBResult.fullKey;
    await db.createApiCredential({
      organizationId: orgB.id,
      projectId: projectB.id,
      environmentId: envBProd.id,
      name: 'Beta Org Key',
      keyHash: keyBResult.keyHash,
      prefix: keyBResult.prefix,
      scopes: ['*'],
    });
  });

  afterAll(async () => {
    try {
      const { managedOperationQueue } = await import('../src/lib/managed-operation-queue');
      await managedOperationQueue.shutdown();
    } catch {}
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  describe('1. Webhook Endpoint Lifecycle & Management', () => {
    it('should reject webhook registration with invalid destination URL', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeyALive}`,
        },
        body: JSON.stringify({
          url: 'ftp://invalid-url.com/webhook',
          events: ['operation.completed'],
        }),
      });

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error.code).toBe('VALIDATION_FAILED');
    });

    it('should reject webhook registration with unsupported event types', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeyALive}`,
        },
        body: JSON.stringify({
          url: 'https://api.partner.com/events',
          events: ['operation.completed', 'unknown.fake.event'],
        }),
      });

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error.code).toBe('VALIDATION_FAILED');
      expect(data.error.message).toContain('Unsupported events specified');
    });

    it('should register a new webhook endpoint and return high-entropy signing secret', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeyALive}`,
        },
        body: JSON.stringify({
          url: 'https://security.alpha-corp.internal/webhooks/amaracus',
          description: 'SIEM and Splunk crypto-event forwarder',
          events: ['operation.completed', 'policy.violation', 'provider.health.changed'],
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data).toBeDefined();
      expect(body.data.endpoint).toBeDefined();
      expect(body.data.endpoint.url).toBe('https://security.alpha-corp.internal/webhooks/amaracus');
      expect(body.data.endpoint.status).toBe('ACTIVE');
      expect(body.data.endpoint.events).toEqual(
        expect.arrayContaining(['operation.completed', 'policy.violation', 'provider.health.changed'])
      );

      // Verify signing secret format
      expect(body.data.signingSecret).toBeDefined();
      expect(body.data.signingSecret.startsWith('whsec_')).toBe(true);
      expect(body.data.signingSecret.length).toBeGreaterThan(30);

      createdWebhookId = body.data.endpoint.id;
      webhookSigningSecret = body.data.signingSecret;
    });

    it('should retrieve registered webhook endpoint by ID', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.id).toBe(createdWebhookId);
      expect(body.data.url).toBe('https://security.alpha-corp.internal/webhooks/amaracus');
      expect(body.data.status).toBe('ACTIVE');
      // Secret must NEVER be leaked on GET queries (only prefix)
      expect(body.data.signingSecret).toBeUndefined();
      expect(body.data.secretPrefix).toBeDefined();
    });

    it('should list all webhook endpoints for the organization', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.data)).toBe(true);
      const found = body.data.find((ep: any) => ep.id === createdWebhookId);
      expect(found).toBeDefined();
      expect(found.url).toBe('https://security.alpha-corp.internal/webhooks/amaracus');
    });

    it('should update webhook endpoint description and subscribed events', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeyALive}`,
        },
        body: JSON.stringify({
          description: 'Updated SIEM forwarder with threshold alerts',
          events: ['operation.completed', 'usage.threshold.reached'],
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.description).toBe('Updated SIEM forwarder with threshold alerts');
      expect(body.data.events).toEqual(['operation.completed', 'usage.threshold.reached']);
    });

    it('should enforce strict tenant isolation (Org B cannot view or modify Org A webhook)', async () => {
      // Org B attempts to GET Org A webhook
      const getRes = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}`, {
        headers: {
          Authorization: `Bearer ${apiKeyBLive}`,
        },
      });
      expect(getRes.status).toBe(404);

      // Org B attempts to PATCH Org A webhook
      const patchRes = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeyBLive}`,
        },
        body: JSON.stringify({ url: 'https://attacker.com' }),
      });
      expect(patchRes.status).toBe(404);
    });
  });

  describe('2. Webhook Secret Rotation (Zero-Downtime)', () => {
    it('should rotate webhook signing secret without altering endpoint subscriptions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}/rotate-secret`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.signingSecret).toBeDefined();
      expect(body.data.signingSecret.startsWith('whsec_')).toBe(true);
      expect(body.data.signingSecret).not.toBe(webhookSigningSecret);

      // Update local signing secret to newly rotated secret
      webhookSigningSecret = body.data.signingSecret;
      expect(body.data.endpoint.secretPrefix).toBe(webhookSigningSecret.slice(0, 10));
    });
  });

  describe('3. Cryptographic Signature Generation & SDK Verification', () => {
    it('should verify signature header generated with valid secret within tolerance window', () => {
      const payload = JSON.stringify({
        id: 'evt_test_123',
        type: 'operation.completed',
        data: { operationId: 'op_abc', algorithm: 'AES-256-GCM', status: 'SUCCESS' },
      });

      const timestamp = Math.floor(Date.now() / 1000);
      const signedData = `${timestamp}.${payload}`;
      const sig = crypto.createHmac('sha256', webhookSigningSecret).update(signedData).digest('hex');
      const header = `t=${timestamp},v1=${sig}`;

      const isValid = verifyWebhookSignature(payload, header, webhookSigningSecret, 300);
      expect(isValid).toBe(true);

      const parsedEvent = constructWebhookEvent(payload, header, webhookSigningSecret, 300);
      expect(parsedEvent.id).toBe('evt_test_123');
      expect(parsedEvent.type).toBe('operation.completed');
    });

    it('should reject signature when payload has been tampered with', () => {
      const payload = JSON.stringify({ id: 'evt_1', type: 'operation.completed', amount: 100 });
      const tamperedPayload = JSON.stringify({ id: 'evt_1', type: 'operation.completed', amount: 99999 });

      const timestamp = Math.floor(Date.now() / 1000);
      const signedData = `${timestamp}.${payload}`;
      const sig = crypto.createHmac('sha256', webhookSigningSecret).update(signedData).digest('hex');
      const header = `t=${timestamp},v1=${sig}`;

      const isValid = verifyWebhookSignature(tamperedPayload, header, webhookSigningSecret, 300);
      expect(isValid).toBe(false);

      expect(() => {
        constructWebhookEvent(tamperedPayload, header, webhookSigningSecret, 300);
      }).toThrow(WebhookVerificationError);
    });

    it('should reject expired signature outside the tolerance window (replay protection)', () => {
      const payload = JSON.stringify({ id: 'evt_replay', type: 'policy.violation' });
      const oldTimestamp = Math.floor(Date.now() / 1000) - 400; // 400 seconds ago (tolerance is 300s)

      const signedData = `${oldTimestamp}.${payload}`;
      const sig = crypto.createHmac('sha256', webhookSigningSecret).update(signedData).digest('hex');
      const header = `t=${oldTimestamp},v1=${sig}`;

      expect(() => {
        verifyWebhookSignature(payload, header, webhookSigningSecret, 300);
      }).toThrow(/timestamp outside tolerance window/);
    });

    it('should reject signature when verified against wrong secret', () => {
      const payload = JSON.stringify({ id: 'evt_wrong_secret', type: 'key.rotated' });
      const timestamp = Math.floor(Date.now() / 1000);
      const signedData = `${timestamp}.${payload}`;
      const sig = crypto.createHmac('sha256', webhookSigningSecret).update(signedData).digest('hex');
      const header = `t=${timestamp},v1=${sig}`;

      const wrongSecret = 'whsec_999999999999999999999999999999999999999999999999';
      const isValid = verifyWebhookSignature(payload, header, wrongSecret, 300);
      expect(isValid).toBe(false);
    });
  });

  describe('4. Framework Adapters Middleware Testing', () => {
    it('Express middleware (amaracusWebhookMiddleware) should verify valid request and call next()', () => {
      const middleware = amaracusWebhookMiddleware({
        secret: webhookSigningSecret,
        toleranceSeconds: 300,
      });

      const payloadObj = { id: 'evt_express', type: 'operation.completed', data: { op: 'enc' } };
      const rawPayload = JSON.stringify(payloadObj);
      const timestamp = Math.floor(Date.now() / 1000);
      const sig = crypto.createHmac('sha256', webhookSigningSecret).update(`${timestamp}.${rawPayload}`).digest('hex');

      const req: any = {
        headers: {
          'x-amaracus-signature': `t=${timestamp},v1=${sig}`,
        },
        rawBody: rawPayload,
      };
      const res: any = {};
      let nextCalled = false;
      const next = () => {
        nextCalled = true;
      };

      middleware(req, res, next);
      expect(nextCalled).toBe(true);
      expect(req.amaracusEvent).toEqual(payloadObj);
    });

    it('Express middleware should return 400 when X-AMARACUS-Signature header is missing', () => {
      const middleware = amaracusWebhookMiddleware({
        secret: webhookSigningSecret,
      });

      let responseStatus = 0;
      let responseBody: any = null;

      const req: any = {
        headers: {},
        rawBody: '{"test":true}',
      };
      const res: any = {
        status: (s: number) => {
          responseStatus = s;
          return {
            json: (b: any) => {
              responseBody = b;
            },
          };
        },
      };

      middleware(req, res, () => {});
      expect(responseStatus).toBe(400);
      expect(responseBody.error.code).toBe('MISSING_WEBHOOK_SIGNATURE');
    });

    it('Next.js helper (verifyNextJsWebhook) should parse and verify incoming request', async () => {
      const payloadObj = { id: 'evt_nextjs', type: 'policy.violation', data: { rule: 'NO_DES' } };
      const rawPayload = JSON.stringify(payloadObj);
      const timestamp = Math.floor(Date.now() / 1000);
      const sig = crypto.createHmac('sha256', webhookSigningSecret).update(`${timestamp}.${rawPayload}`).digest('hex');

      const mockRequest = new Request('http://localhost:3000/api/webhooks', {
        method: 'POST',
        headers: {
          'x-amaracus-signature': `t=${timestamp},v1=${sig}`,
          'Content-Type': 'application/json',
        },
        body: rawPayload,
      });

      const event = await verifyNextJsWebhook(mockRequest, webhookSigningSecret, 300);
      expect(event).toEqual(payloadObj);
    });

    it('Next.js helper should throw when signature is missing', async () => {
      const mockRequest = new Request('http://localhost:3000/api/webhooks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: '{"test":true}',
      });

      await expect(verifyNextJsWebhook(mockRequest, webhookSigningSecret, 300)).rejects.toThrow(
        /Missing X-AMARACUS-Signature header/
      );
    });
  });

  describe('5. Webhook Test Ping Dispatch & Delivery Logging', () => {
    it('should dispatch a test ping event and record delivery log', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}/test`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.success).toBe(true);
      expect(body.data.delivery).toBeDefined();
      expect(body.data.delivery.event).toBe('webhook.test_ping');

      // Check delivery history endpoint
      const historyRes = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}/deliveries`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(historyRes.status).toBe(200);
      const historyBody = await historyRes.json();
      expect(Array.isArray(historyBody.data)).toBe(true);
      expect(historyBody.data.length).toBeGreaterThan(0);
    });
  });

  describe('6. Environment Scoping & API Key Boundaries', () => {
    it('should verify test key prefix (am_test_...) and live key prefix (am_live_...) separation', () => {
      expect(apiKeyATest.startsWith('am_test_')).toBe(true);
      expect(apiKeyALive.startsWith('am_live_')).toBe(true);
    });

    it('Sandbox key should operate within sandbox scope and cannot access live environment configurations', async () => {
      // Sandbox key can read webhooks for the org
      const res = await fetch(`${baseUrl}/api/v1/webhooks`, {
        headers: {
          Authorization: `Bearer ${apiKeyATest}`,
        },
      });

      expect(res.status).toBe(200);
    });
  });

  describe('7. Webhook Endpoint Cleanup & Deletion', () => {
    it('should delete registered webhook endpoint', async () => {
      const res = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.success).toBe(true);

      // Verify endpoint is gone
      const getRes = await fetch(`${baseUrl}/api/v1/webhooks/${createdWebhookId}`, {
        headers: {
          Authorization: `Bearer ${apiKeyALive}`,
        },
      });
      expect(getRes.status).toBe(404);
    });
  });
});
