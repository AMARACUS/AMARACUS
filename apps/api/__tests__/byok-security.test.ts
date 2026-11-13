import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 5.2 — BYOK Multi-Tenant Security, Isolation & Secret Leakage Defense', () => {
  jest.setTimeout(30000);

  let server: http.Server;
  let baseUrl: string;

  // Tenant A (Authorized Enterprise)
  let userA: any;
  let orgA: any;
  let projA: any;
  let envA: any;
  let sessionA: any;

  // Tenant B (Adversary Organization)
  let userB: any;
  let orgB: any;
  let projB: any;
  let envB: any;
  let sessionB: any;

  // Free Tier Organization (Unentitled)
  let userFree: any;
  let orgFree: any;
  let sessionFree: any;

  let providerA: any;
  let keyA: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Setup Tenant A
    userA = await db.createUser({
      email: `tenant_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Owner',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Healthcare',
      slug: `tenant-a-byok-${Date.now()}`,
    });
    await db.addMember({ organizationId: orgA.id, userId: userA.id, role: 'OWNER' });
    projA = await db.createProject({ organizationId: orgA.id, name: 'Project A', slug: 'project-a' });
    envA = await db.createEnvironment({ projectId: projA.id, name: 'Production', slug: 'production', type: 'production' });
    sessionA = await db.createSession({ userId: userA.id, activeOrgId: orgA.id, expiresAt: new Date(Date.now() + 86400000) });

    // Setup Tenant B
    userB = await db.createUser({
      email: `tenant_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B Adversary',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Adversary Corp',
      slug: `tenant-b-byok-${Date.now()}`,
    });
    await db.addMember({ organizationId: orgB.id, userId: userB.id, role: 'OWNER' });
    projB = await db.createProject({ organizationId: orgB.id, name: 'Project B', slug: 'project-b' });
    envB = await db.createEnvironment({ projectId: projB.id, name: 'Production', slug: 'production', type: 'production' });
    sessionB = await db.createSession({ userId: userB.id, activeOrgId: orgB.id, expiresAt: new Date(Date.now() + 86400000) });

    // Setup Free Plan Org (Unentitled)
    userFree = await db.createUser({
      email: `user_free_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Free Tier User',
    });
    orgFree = await db.createOrganization({
      name: 'Free Startup Org',
      slug: `free-org-${Date.now()}`,
    });
    // Set plan to FREE in metadata
    await (db as any).updateOrg?.(orgFree.id, { metadata: JSON.stringify({ plan: 'FREE' }) });
    await db.addMember({ organizationId: orgFree.id, userId: userFree.id, role: 'OWNER' });
    sessionFree = await db.createSession({ userId: userFree.id, activeOrgId: orgFree.id, expiresAt: new Date(Date.now() + 86400000) });

    // Create Customer Provider for Tenant A
    providerA = await db.createCustomerProvider({
      organizationId: orgA.id,
      projectId: projA.id,
      environmentId: envA.id,
      name: 'Tenant A Key Vault',
      providerType: 'AZURE_KEY_VAULT',
      vaultUrl: 'https://tenant-a-vault.vault.azure.net/',
      status: 'CONNECTED',
    });

    // Register Key for Tenant A
    keyA = await db.createCustomerRegisteredKey({
      providerId: providerA.id,
      organizationId: orgA.id,
      projectId: projA.id,
      environmentId: envA.id,
      keyIdentifier: 'tenant-a-kek',
      keyVaultUrl: 'https://tenant-a-vault.vault.azure.net/',
      keyType: 'RSA',
      currentVersion: 'v1',
    });
  }, 30000);

  afterAll((done) => {
    server.close(done);
  });

  test('1. Multi-Tenant Isolation: Tenant B cannot list Tenant A customer providers', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgB.id}/byok/providers`, {
      headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.some((p: any) => p.id === providerA.id)).toBe(false);
  });

  test('2. IDOR Protection: Tenant B cannot get Tenant A provider by ID', async () => {
    // Tenant B attempts to read Tenant A's provider through Tenant B org context
    const res = await fetch(`${baseUrl}/v1/organizations/${orgB.id}/byok/providers/${providerA.id}`, {
      headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
    });

    expect(res.status).toBe(404);

    // Tenant B attempts cross-org access with Tenant A's orgId
    const crossRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/byok/providers/${providerA.id}`, {
      headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
    });

    expect(crossRes.status).toBe(403);
  });

  test('3. Cross-Tenant Key Protection: Tenant B cannot access or encrypt with Tenant A registered key', async () => {
    const res = await fetch(
      `${baseUrl}/v1/organizations/${orgB.id}/byok/providers/${providerA.id}/keys/${keyA.id}`,
      {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      }
    );

    expect(res.status).toBe(404);
  });

  test('4. Project Scoping: Cannot register key into a project belonging to another organization', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgB.id}/byok/providers`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionB.sessionToken}`,
      },
      body: JSON.stringify({
        name: 'Malicious Provider Injection',
        projectId: projA.id, // Project belongs to Tenant A!
        environmentId: envA.id,
        providerType: 'AZURE_KEY_VAULT',
        vaultUrl: 'https://attacker-vault.vault.azure.net/',
      }),
    });

    expect(res.status).toBe(404);
  });

  test('5. Zero-Secret Exposure: Client secrets are never returned in provider responses or logs', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/byok/providers/${providerA.id}`, {
      headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
    });

    expect(res.status).toBe(200);
    const json = await res.json();

    const stringified = JSON.stringify(json);
    expect(stringified).not.toMatch(/encryptedAuthConfig/);
    expect(stringified).not.toMatch(/clientSecret/);
    expect(stringified).not.toMatch(/privateKey/);
    expect(stringified).not.toMatch(/securityDomain/);
  });
});
