import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { CustomerAzureKeyVaultProvider } from '@amaracus/crypto-core';

// Key discovery reads the customer's vault. Without a live vault, stand in for Azure with
// the metadata it would return; the route must never invent this itself.
const discoveredKeyMetadata = {
  keyIdentifier: 'test-enterprise-rsa-key',
  keyType: 'RSA',
  algorithm: 'RSA-OAEP-256',
  purpose: 'ENCRYPTION',
  currentVersion: 'v1',
  enabled: true,
  isHsmBacked: false,
  hsmBackedStatus: 'STANDARD_VAULT',
  operations: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  capabilities: { encrypt: true, decrypt: true, sign: false, verify: false, wrap: true, unwrap: true, derive: 'unknown' },
  publicKey: null,
  keyFingerprint: null,
  createdAt: new Date(),
};


// These tests talk to a real Azure Key Vault. Without credentials they skip
// instead of failing, the same rule as byok-azure-live.test.ts.
const hasLiveAzure = !!(
  process.env.AZURE_KEY_VAULT_URL &&
  process.env.AZURE_TENANT_ID &&
  process.env.AZURE_CLIENT_ID &&
  process.env.AZURE_CLIENT_SECRET
);
const liveAzureTest = hasLiveAzure ? test : test.skip;

describe('Phase 5.4 — Concrete BYOK/BYO-HSM API Contract & State Enforcement', () => {
  jest.setTimeout(30000);

  let server: http.Server;
  let baseUrl: string;

  let ownerUser: any;
  let orgA: any;
  let projectA: any;
  let envA: any;
  let sessionA: any;

  let userB: any;
  let orgB: any;
  let projectB: any;
  let envB: any;
  let sessionB: any;

  let providerAId: string;
  let keyAId: string;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Setup Tenant A (Enterprise)
    ownerUser = await db.createUser({
      email: `tenant_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Admin',
    });

    orgA = await db.createOrganization({
      name: 'Tenant A Enterprise Corp',
      slug: `tenant-a-${Date.now()}`,
    });

    await db.addMember({
      organizationId: orgA.id,
      userId: ownerUser.id,
      role: 'OWNER',
    });

    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Project Alpha',
      slug: 'project-alpha',
    });

    envA = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      slug: 'prod',
      type: 'production',
    });

    sessionA = await db.createSession({
      userId: ownerUser.id,
      activeOrgId: orgA.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Setup Tenant B (Unrelated tenant for IDOR testing)
    userB = await db.createUser({
      email: `tenant_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B Admin',
    });

    orgB = await db.createOrganization({
      name: 'Tenant B LLC',
      slug: `tenant-b-${Date.now()}`,
    });

    await db.addMember({
      organizationId: orgB.id,
      userId: userB.id,
      role: 'OWNER',
    });

    projectB = await db.createProject({
      organizationId: orgB.id,
      name: 'Project Beta',
      slug: 'project-beta',
    });

    envB = await db.createEnvironment({
      projectId: projectB.id,
      name: 'Production',
      slug: 'prod',
      type: 'production',
    });

    sessionB = await db.createSession({
      userId: userB.id,
      activeOrgId: orgB.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
  }, 30000);

  afterAll((done) => {
    server.close(done);
  });

  // -------------------------------------------------------------------------
  // 1. Provider Creation & Runtime Boundary Validation
  // -------------------------------------------------------------------------
  describe('1. Provider Creation & Validation', () => {
    test('POST /api/v1/customer-key-providers: creates provider with canonical schema and zero secret leakage', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          organizationId: orgA.id,
          projectId: projectA.id,
          environmentId: envA.id,
          providerType: 'AZURE',
          resourceType: 'KEY_VAULT',
          displayName: 'Production Azure Key Vault',
          endpoint: 'https://amaracus-vault-prod.vault.azure.net/',
          resourceId: '/subscriptions/sub-123/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/prod-vault',
          auth: {
            method: 'SERVICE_PRINCIPAL',
          },
          tenantId: process.env.AZURE_TENANT_ID || 'dummy-tenant-id',
          clientId: process.env.AZURE_CLIENT_ID || 'dummy-client-id',
          clientSecret: process.env.AZURE_CLIENT_SECRET || 'dummy-client-secret',
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();

      expect(json.id).toBeDefined();
      expect(json.organizationId).toBe(orgA.id);
      expect(json.projectId).toBe(projectA.id);
      expect(json.environmentId).toBe(envA.id);
      expect(json.providerType).toBe('AZURE');
      expect(json.resourceType).toBe('KEY_VAULT');
      expect(json.displayName).toBe('Production Azure Key Vault');
      expect(json.endpoint).toBe('https://amaracus-vault-prod.vault.azure.net/');
      expect(json.ownershipType).toBe('CUSTOMER_OWNED');
      expect(json.status).toBe('PENDING_CONNECTION');
      expect(json.onboardingState).toBe('CONFIGURED');

      // Strict Zero Secret Leakage Check
      expect(json.clientSecret).toBeUndefined();
      expect(json.encryptedAuthConfig).toBeUndefined();

      providerAId = json.id;
    });

    test('rejects creation when required endpoint is missing', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          organizationId: orgA.id,
          projectId: projectA.id,
          environmentId: envA.id,
          displayName: 'Missing Endpoint Vault',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('INVALID_REQUEST');
      expect(json.error.requestId).toBeDefined();
    });

    test('rejects unsupported cloud provider AWS with clear explanation', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          organizationId: orgA.id,
          projectId: projectA.id,
          environmentId: envA.id,
          providerType: 'AWS',
          resourceType: 'KEY_VAULT',
          displayName: 'AWS KMS Attempt',
          endpoint: 'https://kms.us-east-1.amazonaws.com',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('INVALID_REQUEST');
      expect(json.error.message).toMatch(/Only AZURE is supported in this phase. AWS is not implemented./);
    });

    test('rejects invalid resourceType', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          organizationId: orgA.id,
          projectId: projectA.id,
          environmentId: envA.id,
          providerType: 'AZURE',
          resourceType: 'INVALID_HSM_TYPE',
          displayName: 'Invalid Resource Vault',
          endpoint: 'https://amaracus-vault-prod.vault.azure.net/',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('INVALID_REQUEST');
    });
  });

  // -------------------------------------------------------------------------
  // 2. Correlation ID Verification
  // -------------------------------------------------------------------------
  describe('2. Request Correlation IDs', () => {
    test('propagates provided x-request-id in response and errors', async () => {
      const testReqId = 'req_custom_trace_987654321';
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/non-existent-provider`, {
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'x-request-id': testReqId,
          'x-organization-id': orgA.id,
        },
      });

      expect(res.headers.get('x-request-id')).toBe(testReqId);
      const json = await res.json();
      expect(json.error.requestId).toBe(testReqId);
    });
  });

  // -------------------------------------------------------------------------
  // 3. Multi-Tenant Isolation & IDOR Protection
  // -------------------------------------------------------------------------
  describe('3. Multi-Tenant Isolation & IDOR Defense', () => {
    test('User B cannot retrieve User A provider by ID', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}`, {
        headers: {
          Authorization: `Bearer ${sessionB.sessionToken}`,
        },
      });

      // Must be forbidden or not found (cross-tenant access denied with IDOR defense)
      expect([403, 404]).toContain(res.status);
      const json = await res.json();
      expect(['FORBIDDEN', 'RESOURCE_NOT_FOUND', 'NOT_FOUND']).toContain(json.error.code);
    });

    test('User B cannot test User A provider connection', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/test`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionB.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });

      expect([403, 404]).toContain(res.status);
    });

    test('User B cannot list User A registered keys', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys`, {
        headers: {
          Authorization: `Bearer ${sessionB.sessionToken}`,
        },
      });

      expect([403, 404]).toContain(res.status);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Connection Test, Capability Discovery & Onboarding State Machine
  // -------------------------------------------------------------------------
  describe('4. Connection Test & Capability Discovery Transitions', () => {
    liveAzureTest('POST /api/v1/customer-key-providers/:providerId/test transitions state to CONNECTED', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/test`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.status).toBe('CONNECTED');
      expect(json.provider).toBe('AZURE');
      expect(json.message).toBe('Connection verified.');

      // Check onboarding state in database
      const provider = await db.findCustomerProviderById(providerAId);
      expect(provider?.onboardingState).toBe('CONNECTED');
    });

    liveAzureTest('GET /api/v1/customer-key-providers/:providerId/onboarding-status: returns CONNECTED with nextAction DISCOVER_CAPABILITIES', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/onboarding-status`, {
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.state).toBe('CONNECTED');
      expect(json.progress.connection).toBe('COMPLETE');
      expect(json.progress.capabilities).toBe('NOT_STARTED');
      expect(json.nextAction).toBe('DISCOVER_CAPABILITIES');
      expect(json.canProceed).toBe(false); // cannot proceed until READY
    });

    liveAzureTest('GET /api/v1/customer-key-providers/:providerId/capabilities: completes capability discovery and transitions to READY', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/capabilities`, {
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.providerType).toBe('AZURE');
      expect(json.status).toBe('COMPLETE');

      // Verify 3-State capability representation (true, false, "UNKNOWN")
      expect(json.capabilities.ENCRYPT).toBe(true);
      expect(json.capabilities.DECRYPT).toBe(true);
      expect(json.capabilities.SIGN).toBe(true);
      expect(json.capabilities.VERIFY).toBe(true);
      expect(json.capabilities.WRAP).toBe(true);
      expect(json.capabilities.UNWRAP).toBe(true);
      expect(json.capabilities.DERIVE).toBe('UNKNOWN'); // Must be explicit UNKNOWN

      // Verify provider is now READY in DB
      const provider = await db.findCustomerProviderById(providerAId);
      expect(provider?.onboardingState).toBe('READY');
    });

    liveAzureTest('GET /api/v1/customer-key-providers/:providerId/onboarding-status: now returns READY with canProceed=true', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/onboarding-status`, {
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.state).toBe('READY');
      expect(json.progress.capabilities).toBe('COMPLETE');
      expect(json.canProceed).toBe(true);
      expect(json.nextAction).toBe('REGISTER_KEY');
    });
  });

  // -------------------------------------------------------------------------
  // 5. Key Registration & Refresh
  // -------------------------------------------------------------------------
  describe('5. Key Registration & Refresh', () => {
    let discoverSpy: jest.SpyInstance;
    beforeAll(() => {
      discoverSpy = jest
        .spyOn(CustomerAzureKeyVaultProvider.prototype as any, 'discoverKey')
        .mockResolvedValue(discoveredKeyMetadata);
    });

    test('POST /api/v1/customer-key-providers/:providerId/keys: refuses to register a key the vault cannot read', async () => {
      discoverSpy.mockRejectedValueOnce(new Error('vault unreachable'));
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ providerKeyId: 'unreadable-key', version: 'current', purpose: 'ENCRYPTION' }),
      });

      expect(res.status).toBe(502);
      const json = await res.json();
      expect(json.error.code).toBe('KEY_DISCOVERY_FAILED');
    });

    test('POST /api/v1/customer-key-providers/:providerId/keys: registers key reference', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          providerKeyId: 'test-enterprise-rsa-key',
          version: 'current',
          purpose: 'ENCRYPTION',
          displayName: 'Test Enterprise RSA Key',
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.id).toBeDefined();
      expect(json.providerKeyId).toBe('test-enterprise-rsa-key');
      expect(json.status).toBe('ACTIVE');
      expect(json.keyState).toBe('ACTIVE');
      expect(json.capabilities.ENCRYPT).toBe(true);
      expect(json.capabilities.DECRYPT).toBe(true);

      keyAId = json.id;
    });

    test('POST /api/v1/customer-key-providers/:providerId/keys/:keyId/refresh: refreshes key version and metadata', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys/${keyAId}/refresh`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.keyId).toBe(keyAId);
      expect(json.status).toBe('REFRESHED');
      expect(json.keyVersion).toBeDefined();
      expect(json.refreshedAt).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // 6. Cryptographic Operation Pipeline & Fail-Closed Enforcement
  // -------------------------------------------------------------------------
  describe('6. 15-Step Operation Pipeline Enforcement', () => {
    test('Pipeline Step 6: fails closed with PROVIDER_NOT_CONFIGURED if provider is not READY', async () => {
      // Create a temporary unverified provider (in CONFIGURED state)
      const unverified = await db.createCustomerProvider({
        organizationId: orgA.id,
        projectId: projectA.id,
        environmentId: envA.id,
        name: 'Unverified Vault',
        vaultUrl: 'https://unverified.vault.azure.net/',
        providerType: 'AZURE_KEY_VAULT',
        onboardingState: 'CONFIGURED',
      });

      const tempKey = await db.createCustomerRegisteredKey({
        providerId: unverified.id,
        organizationId: orgA.id,
        projectId: projectA.id,
        environmentId: envA.id,
        keyIdentifier: 'temp-key',
        keyVaultUrl: unverified.vaultUrl,
        keyType: 'RSA',
        currentVersion: 'v1',
        capabilities: { ENCRYPT: true },
      });

      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${unverified.id}/keys/${tempKey.id}/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          operation: 'ENCRYPT',
          plaintext: 'Secret Data',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('PROVIDER_NOT_CONFIGURED');
      expect(json.error.message).toMatch(/is not READY for operations/);
    });

    liveAzureTest('Pipeline Step 8: fails closed with KEY_DISABLED if key is not active', async () => {
      const disabledKey = await db.createCustomerRegisteredKey({
        providerId: providerAId,
        organizationId: orgA.id,
        projectId: projectA.id,
        environmentId: envA.id,
        keyIdentifier: 'disabled-key-123',
        keyVaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
        keyType: 'RSA',
        currentVersion: 'v1',
        status: 'DISABLED',
        keyState: 'DISABLED',
        capabilities: { ENCRYPT: true },
      });

      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys/${disabledKey.id}/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          operation: 'ENCRYPT',
          plaintext: 'Secret Data',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('KEY_DISABLED');
      expect(json.error.message).toMatch(/is DISABLED/);
    });

    liveAzureTest('Pipeline Step 11: fails closed with CAPABILITY_UNKNOWN if capability is UNKNOWN', async () => {
      const deriveKey = await db.createCustomerRegisteredKey({
        providerId: providerAId,
        organizationId: orgA.id,
        projectId: projectA.id,
        environmentId: envA.id,
        keyIdentifier: 'unknown-derive-key',
        keyVaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
        keyType: 'EC',
        currentVersion: 'v1',
        status: 'ACTIVE',
        keyState: 'ACTIVE',
        capabilities: { DERIVE: 'UNKNOWN' },
      });

      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys/${deriveKey.id}/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          operation: 'DERIVE',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('CAPABILITY_UNKNOWN');
      expect(json.error.message).toMatch(/capability is UNKNOWN/);
    });

    liveAzureTest('Pipeline Step 11: fails closed with OPERATION_NOT_SUPPORTED if capability is false', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys/${keyAId}/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          operation: 'SIGN',
          data: 'Document to sign',
        }),
      });

      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('OPERATION_NOT_SUPPORTED');
    });

    liveAzureTest('Fail-closed security: unresolvable provider key fails closed with zero fallback to local crypto', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}/keys/${keyAId}/operations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          operation: 'ENCRYPT',
          plaintext: 'Production confidential payload',
        }),
      });

      // Must fail closed with 400, 502, or 503 and structured error code
      // strictly with zero silent fallback to local or software encryption!
      expect(res.status).toBeGreaterThanOrEqual(400);
      const json = await res.json();
      expect(json.error).toBeDefined();
      expect(['PROVIDER_UNAVAILABLE', 'CRYPTO_OPERATION_FAILED', 'KEY_NOT_FOUND']).toContain(json.error.code);
      expect(json.envelope).toBeUndefined(); // Zero secret or ciphertext emitted on failure
    });
  });

  // -------------------------------------------------------------------------
  // 7. Disconnect Behavior & Preservation Guarantee
  // -------------------------------------------------------------------------
  describe('7. Disconnect Semantics', () => {
    test('DELETE /api/v1/customer-key-providers/:providerId preserves customer resources and cleans up metadata', async () => {
      const res = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.status).toBe('DISCONNECTED');
      expect(json.message).toMatch(/remain fully preserved in your Azure subscription/);

      // Verify subsequent lookup returns 404
      const getRes = await fetch(`${baseUrl}/api/v1/customer-key-providers/${providerAId}`, {
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });
      expect(getRes.status).toBe(404);
    });
  });
});
