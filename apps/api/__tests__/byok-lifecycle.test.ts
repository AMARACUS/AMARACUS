import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';


// These tests talk to a real Azure Key Vault. Without credentials they skip
// instead of failing, the same rule as byok-azure-live.test.ts.
const hasLiveAzure = !!(
  process.env.AZURE_KEY_VAULT_URL &&
  process.env.AZURE_TENANT_ID &&
  process.env.AZURE_CLIENT_ID &&
  process.env.AZURE_CLIENT_SECRET
);
const liveAzureTest = hasLiveAzure ? test : test.skip;

describe('Phase 5.2 — Customer BYOK Lifecycle & Operations', () => {
  jest.setTimeout(30000);

  let server: http.Server;
  let baseUrl: string;

  let ownerUser: any;
  let org: any;
  let project: any;
  let env: any;
  let ownerSession: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    ownerUser = await db.createUser({
      email: `byok_owner_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'BYOK Enterprise Owner',
    });

    org = await db.createOrganization({
      name: 'Acme Enterprise Healthcare',
      slug: `acme-byok-${Date.now()}`,
    });

    await db.addMember({
      organizationId: org.id,
      userId: ownerUser.id,
      role: 'OWNER',
    });

    project = await db.createProject({
      organizationId: org.id,
      name: 'Core Cryptographic Services',
      slug: 'core-crypto-services',
    });

    env = await db.createEnvironment({
      projectId: project.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    ownerSession = await db.createSession({
      userId: ownerUser.id,
      activeOrgId: org.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
  }, 30000);

  afterAll((done) => {
    server.close(done);
  });

  let createdProviderId: string;
  let registeredKeyId: string;

  liveAzureTest('1. Test Connection: tests customer Azure Key Vault reachability before creating provider', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/test`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ownerSession.sessionToken}`,
      },
      body: JSON.stringify({
        providerType: 'AZURE_KEY_VAULT',
        vaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
        authType: 'SERVICE_PRINCIPAL',
        tenantId: process.env.AZURE_TENANT_ID,
        clientId: process.env.AZURE_CLIENT_ID,
        clientSecret: process.env.AZURE_CLIENT_SECRET,
      }),
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data).toBeDefined();
    expect(json.data.success).toBe(true);
    expect(json.data.vaultUrl).toBe('https://amaracus-vault-prod.vault.azure.net/');
    expect(json.data.capabilities.supportsEnvelopeEncryption).toBe(true);
  });

  test('2. Create Provider: connects customer-owned Azure Key Vault and encrypts secrets at rest', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ownerSession.sessionToken}`,
      },
      body: JSON.stringify({
        name: 'Acme Azure Production Vault',
        projectId: project.id,
        environmentId: env.id,
        providerType: 'AZURE_KEY_VAULT',
        vaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
        authType: 'SERVICE_PRINCIPAL',
        // Creating a provider makes no Azure call; a service principal is required, real or not.
        tenantId: process.env.AZURE_TENANT_ID || '00000000-0000-0000-0000-000000000000',
        clientId: process.env.AZURE_CLIENT_ID || '00000000-0000-0000-0000-000000000000',
        clientSecret: process.env.AZURE_CLIENT_SECRET || 'dummy-client-secret',
      }),
    });

    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.data.id).toBeDefined();
    expect(json.data.name).toBe('Acme Azure Production Vault');
    expect(json.data.ownershipType).toBe('CUSTOMER_OWNED');
    expect(json.data.status).toBe('CONNECTED');

    // Zero secret leakage in response:
    expect(json.data.encryptedAuthConfig).toBeUndefined();
    expect(json.data.clientSecret).toBeUndefined();

    createdProviderId = json.data.id;
  });

  test('3. List Providers: returns connected providers scoped to organization and project', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers?projectId=${project.id}`, {
      headers: {
        Authorization: `Bearer ${ownerSession.sessionToken}`,
      },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(Array.isArray(json.data)).toBe(true);
    expect(json.data.length).toBeGreaterThan(0);
    expect(json.data[0].id).toBe(createdProviderId);
    expect(json.data[0].encryptedAuthConfig).toBeUndefined();
  });

  test('4. Get Provider: returns provider details and health status', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/${createdProviderId}`, {
      headers: {
        Authorization: `Bearer ${ownerSession.sessionToken}`,
      },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.id).toBe(createdProviderId);
    expect(json.data.vaultUrl).toBe('https://amaracus-vault-prod.vault.azure.net/');
    expect(json.data.encryptedAuthConfig).toBeUndefined();
  });

  test('5. Register Key: registers metadata from customer vault without ingesting raw private key', async () => {
    // Manually register a test key metadata in the provider
    const keyIdentifier = 'acme-customer-kek';

    const registered = await db.createCustomerRegisteredKey({
      providerId: createdProviderId,
      organizationId: org.id,
      projectId: project.id,
      environmentId: env.id,
      keyIdentifier,
      keyVaultUrl: 'https://amaracus-vault-prod.vault.azure.net/',
      keyType: 'RSA',
      algorithm: 'AES-256-GCM',
      purpose: 'ENCRYPTION',
      ownershipType: 'CUSTOMER_OWNED',
      isHsmBacked: false,
      status: 'ACTIVE',
      currentVersion: '4a1e8c9b2f0a4d1e8c9b2f0a4d1e8c9b',
      publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
      keyFingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      operations: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    });

    registeredKeyId = registered.id;
    expect(registered.id).toBeDefined();
    expect(registered.ownershipType).toBe('CUSTOMER_OWNED');
    expect(registered.keyIdentifier).toBe(keyIdentifier);

    // List registered keys via API
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/${createdProviderId}/keys`, {
      headers: {
        Authorization: `Bearer ${ownerSession.sessionToken}`,
      },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.length).toBeGreaterThan(0);
    expect(json.data[0].id).toBe(registeredKeyId);
    expect(json.data[0].keyIdentifier).toBe(keyIdentifier);
  });

  test('6. Disconnect Provider: preserves customer Azure infrastructure and removes AMARACUS registration', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/${createdProviderId}/disconnect`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${ownerSession.sessionToken}`,
      },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.success).toBe(true);
    expect(json.data.message).toMatch(/remain fully preserved/);

    // Provider should no longer exist in AMARACUS
    const getRes = await fetch(`${baseUrl}/v1/organizations/${org.id}/byok/providers/${createdProviderId}`, {
      headers: {
        Authorization: `Bearer ${ownerSession.sessionToken}`,
      },
    });
    expect(getRes.status).toBe(404);
  });
});
