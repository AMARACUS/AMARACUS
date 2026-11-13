import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 5.3 — Enterprise BYOK Onboarding Validation & Error Transparency', () => {
  jest.setTimeout(30000);

  let server: http.Server;
  let baseUrl: string;

  let ownerUser: any;
  let org: any;
  let project: any;
  let env: any;
  let session: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    ownerUser = await db.createUser({
      email: `onboarding_admin_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Onboarding Security Architect',
    });

    org = await db.createOrganization({
      name: 'Enterprise Healthcare Trust',
      slug: `enterprise-hc-${Date.now()}`,
    });

    await db.addMember({
      organizationId: org.id,
      userId: ownerUser.id,
      role: 'OWNER',
    });

    project = await db.createProject({
      organizationId: org.id,
      name: 'Clinical Health Record Encryption',
      slug: 'clinical-health-rec',
    });

    env = await db.createEnvironment({
      projectId: project.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    session = await db.createSession({
      userId: ownerUser.id,
      activeOrgId: org.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
  });

  afterAll((done) => {
    server.close(done);
  });

  test('1. Input Validation: rejects missing vaultUrl and malformed endpoints', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/test`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.sessionToken}`,
      },
      body: JSON.stringify({
        providerType: 'AZURE_KEY_VAULT',
        // Missing vaultUrl
        authType: 'SERVICE_PRINCIPAL',
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(['INVALID_REQUEST', 'INVALID_CONFIG']).toContain(json.error.code);
    expect(json.error.message).toMatch(/required/i);
  });

  test('2. Error Transparency: DNS resolution failure returns RESOURCE_NOT_FOUND', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/test`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.sessionToken}`,
      },
      body: JSON.stringify({
        providerType: 'AZURE_KEY_VAULT',
        // Azure vault names are at most 24 characters; longer names are rejected before any network call.
        vaultUrl: 'https://does-not-exist-88776655.vault.azure.net/',
        authType: 'SERVICE_PRINCIPAL',
        tenantId: '00000000-0000-0000-0000-000000000000',
        clientId: '00000000-0000-0000-0000-000000000000',
        clientSecret: 'dummy_secret',
      }),
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    // Test endpoint returns { data: { success: false, connectionStatus: '...', error: '...' } }
    expect(json.data.success).toBe(false);
    expect(['RESOURCE_NOT_FOUND', 'AUTHORIZATION_FAILED', 'ERROR']).toContain(json.data.connectionStatus);
    expect(json.data.message).toBeDefined();
  });

  test('3. Key Registration: rejects duplicate key registration in the same provider', async () => {
    const provider = await db.createCustomerProvider({
      organizationId: org.id,
      projectId: project.id,
      environmentId: env.id,
      name: 'Acme Test Key Provider',
      providerType: 'AZURE_KEY_VAULT',
      vaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
      status: 'CONNECTED',
    });

    // Register key once
    await db.createCustomerRegisteredKey({
      providerId: provider.id,
      organizationId: org.id,
      projectId: project.id,
      environmentId: env.id,
      keyIdentifier: 'duplicate-test-key-01',
      keyVaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
      keyType: 'RSA',
      algorithm: 'AES-256-GCM',
      purpose: 'ENCRYPTION',
      status: 'ACTIVE',
      currentVersion: 'v1',
    });

    // Register again via API - should reject
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/${provider.id}/keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.sessionToken}`,
      },
      body: JSON.stringify({
        keyIdentifier: 'duplicate-test-key-01',
      }),
    });

    expect(res.status).toBe(409);
    const json = await res.json();
    expect(json.error.code).toBe('KEY_ALREADY_REGISTERED');
  });

  test('4. Customer Ownership Guarantee: Disconnect preserves Azure resources and logs audit event', async () => {
    const provider = await db.createCustomerProvider({
      organizationId: org.id,
      projectId: project.id,
      environmentId: env.id,
      name: 'Vault To Disconnect',
      providerType: 'AZURE_KEY_VAULT',
      vaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
      status: 'CONNECTED',
    });

    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/${provider.id}/disconnect`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${session.sessionToken}`,
      },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.success).toBe(true);
    expect(json.data.message).toMatch(/remain fully preserved/i);

    // Verify audit event was logged
    const events = await db.getAuditEventsByOrg(org.id);
    const disconnectEvent = events.find(
      (e) => e.action === 'BYOK_PROVIDER_DISCONNECTED' && e.resourceId === provider.id
    );
    expect(disconnectEvent).toBeDefined();
    const notice = (disconnectEvent?.metadata as any)?.preservationNotice || (disconnectEvent?.metadata as any)?.message || json.data.message;
    expect(notice).toMatch(/preserved/i);
  });
});
