import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 5 — Key Management API, RBAC, Multi-Tenant Security & Zero-Secret Auditing', () => {
  jest.setTimeout(30000);

  let server: http.Server;
  let baseUrl: string;

  let userA_Owner: any;
  let userA_Member: any;
  let orgA: any;
  let projA: any;
  let envA: any;
  let sessionA_Owner: any;
  let sessionA_Member: any;

  let userB_Owner: any;
  let orgB: any;
  let projB: any;
  let envB: any;
  let sessionB_Owner: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Setup Tenant A
    userA_Owner = await db.createUser({
      email: `key_owner_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Owner',
    });
    userA_Member = await db.createUser({
      email: `key_member_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Member',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Enterprise Cryptography',
      slug: `tenant-a-kms-${Date.now()}`,
    });
    await db.addMember({ organizationId: orgA.id, userId: userA_Owner.id, role: 'OWNER' });
    await db.addMember({ organizationId: orgA.id, userId: userA_Member.id, role: 'MEMBER' });

    projA = await db.createProject({
      organizationId: orgA.id,
      name: 'Core Security Suite',
      slug: 'core-sec-suite',
    });
    envA = await db.createEnvironment({
      projectId: projA.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    sessionA_Owner = await db.createSession({
      userId: userA_Owner.id,
      activeOrgId: orgA.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
    sessionA_Member = await db.createSession({
      userId: userA_Member.id,
      activeOrgId: orgA.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Setup Tenant B
    userB_Owner = await db.createUser({
      email: `key_owner_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B Owner',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Adversary Corp',
      slug: `tenant-b-kms-${Date.now()}`,
    });
    await db.addMember({ organizationId: orgB.id, userId: userB_Owner.id, role: 'OWNER' });

    projB = await db.createProject({
      organizationId: orgB.id,
      name: 'Adversary System',
      slug: 'adversary-sys',
    });
    envB = await db.createEnvironment({
      projectId: projB.id,
      name: 'Staging',
      slug: 'staging',
      type: 'staging',
    });

    sessionB_Owner = await db.createSession({
      userId: userB_Owner.id,
      activeOrgId: orgB.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
  }, 30000);

  afterAll((done) => {
    server.close(done);
  });

  let createdKeyId: string;

  test('1. Provider Discovery: lists Azure Key Vault, Azure Managed HSM, and Local Dev providers', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/providers`, {
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(Array.isArray(json.data)).toBe(true);

    const providerIds = json.data.map((p: any) => p.provider);
    expect(providerIds).toContain('LOCAL_DEV');
    expect(providerIds).toContain('AZURE_KEY_VAULT');
    expect(providerIds).toContain('AZURE_MANAGED_HSM');

    // Zero AWS
    expect(providerIds).not.toContain('AWS_KMS');
    expect(providerIds).not.toContain('AMAZON_KMS');
  });

  test('2. Key Creation: creates managed key and verifies Zero Secret Material in response', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionA_Owner.sessionToken}`,
      },
      body: JSON.stringify({
        name: 'database-pii-kek',
        description: 'Primary envelope encryption KEK for patient PII',
        projectId: projA.id,
        environmentId: envA.id,
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
        provider: 'LOCAL_DEV',
      }),
    });

    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.data).toBeDefined();
    expect(json.data.name).toBe('database-pii-kek');
    expect(json.data.status).toBe('ACTIVE');
    expect(json.data.currentVersion).toBe(1);

    createdKeyId = json.data.id;

    // ZERO SECRET LEAKAGE VERIFICATION:
    expect(json.data).not.toHaveProperty('encryptedKeyMaterial');
    expect(json.data).not.toHaveProperty('rawKey');
    expect(json.data).not.toHaveProperty('secret');
    if (json.data.versions && json.data.versions.length > 0) {
      expect(json.data.versions[0]).not.toHaveProperty('encryptedKeyMaterial');
    }
  });

  test('3. Multi-Tenant Boundary: Tenant B cannot read or access Tenant A keys', async () => {
    // Attempt to get Tenant A key using Tenant B session and Org B URL context
    const resOrgB = await fetch(`${baseUrl}/v1/organizations/${orgB.id}/keys/${createdKeyId}`, {
      headers: { Authorization: `Bearer ${sessionB_Owner.sessionToken}` },
    });
    expect(resOrgB.status).toBe(404);

    // Attempt to access Tenant A URL directly with Tenant B session
    const resCrossOrg = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}`, {
      headers: { Authorization: `Bearer ${sessionB_Owner.sessionToken}` },
    });
    expect(resCrossOrg.status).toBe(403);
  });

  test('4. IDOR Defense: Cannot create a key in Org A referencing a Project in Org B', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionA_Owner.sessionToken}`,
      },
      body: JSON.stringify({
        name: 'idor-attempt-key',
        projectId: projB.id, // Project belongs to Org B!
        environmentId: envB.id,
        algorithm: 'AES-256-GCM',
        purpose: 'ENCRYPTION',
        provider: 'LOCAL_DEV',
      }),
    });

    expect(res.status).toBe(404);
    const json = await res.json();
    expect(json.error.message).toMatch(/Project not found in this organization/i);
  });

  test('5. RBAC Enforcement: MEMBER role cannot rotate or destroy keys', async () => {
    // MEMBER attempts to rotate key -> 403 Forbidden
    const rotateRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/rotate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionA_Member.sessionToken}` },
    });
    expect(rotateRes.status).toBe(403);

    // MEMBER attempts to delete key -> 403 Forbidden
    const deleteRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${sessionA_Member.sessionToken}` },
    });
    expect(deleteRes.status).toBe(403);
  });

  test('6. Key Rotation: OWNER rotates key, increments version from v1 to v2', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/rotate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.key.currentVersion).toBe(2);
    expect(json.data.newVersion.version).toBe(2);
    expect(json.data.newVersion.status).toBe('ACTIVE');
  });

  test('7. Cryptographic Envelope Operations: Encrypt & Decrypt roundtrip', async () => {
    const plaintext = 'AMARACUS Production EHR Record: Patient #48192';

    // Encrypt
    const encRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/encrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionA_Member.sessionToken}`,
      },
      body: JSON.stringify({ plaintext }),
    });

    expect(encRes.status).toBe(200);
    const encJson = await encRes.json();
    expect(encJson.data.envelope).toBeDefined();
    expect(encJson.data.envelope.alg).toBe('AES-256-GCM');
    expect(encJson.data.version).toBe(2);

    // Decrypt
    const decRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/decrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionA_Member.sessionToken}`,
      },
      body: JSON.stringify({ envelope: encJson.data.envelope }),
    });

    expect(decRes.status).toBe(200);
    const decJson = await decRes.json();
    expect(decJson.data.plaintext).toBe(plaintext);
  });

  test('8. Lifecycle Disable & Re-Enable', async () => {
    // Disable
    const disRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/disable`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });
    expect(disRes.status).toBe(200);
    const disJson = await disRes.json();
    expect(disJson.data.status).toBe('DISABLED');

    // Attempting to encrypt with DISABLED key must fail
    const encFailRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/encrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionA_Owner.sessionToken}`,
      },
      body: JSON.stringify({ plaintext: 'Should fail' }),
    });
    expect(encFailRes.status).toBe(400);

    // Re-enable
    const enRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/enable`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });
    expect(enRes.status).toBe(200);
    const enJson = await enRes.json();
    expect(enJson.data.status).toBe('ACTIVE');
  });

  test('9. Scheduled Deletion & Recovery', async () => {
    // Schedule deletion for 7 days
    const schedRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/schedule-deletion`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionA_Owner.sessionToken}`,
      },
      body: JSON.stringify({ pendingDays: 7 }),
    });

    expect(schedRes.status).toBe(200);
    const schedJson = await schedRes.json();
    expect(schedJson.data.status).toBe('SCHEDULED_FOR_DELETION');

    // Recover
    const recRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/recover`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });

    expect(recRes.status).toBe(200);
    const recJson = await recRes.json();
    expect(recJson.data.status).toBe('ACTIVE');
  });

  test('10. Permanent Purge & Terminal Destruction', async () => {
    const purgeRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/purge`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });

    expect(purgeRes.status).toBe(200);
    const purgeJson = await purgeRes.json();
    expect(purgeJson.data.status).toBe('DESTROYED');

    // Attempting to re-enable or recover destroyed key must fail
    const enableFail = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/keys/${createdKeyId}/enable`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });
    expect(enableFail.status).toBe(400);
  });

  test('11. Zero-Secret Audit Logging: Audit trail contains actions with zero secret leakage', async () => {
    const auditRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/audit`, {
      headers: { Authorization: `Bearer ${sessionA_Owner.sessionToken}` },
    });

    expect(auditRes.status).toBe(200);
    const auditJson = await auditRes.json();
    const events = auditJson.auditEvents || auditJson.events || auditJson.data || [];

    const keyEvents = events.filter((e: any) => e.resourceType === 'CryptographicKey');
    expect(keyEvents.length).toBeGreaterThan(0);

    const actions = keyEvents.map((e: any) => e.action);
    expect(actions).toContain('key.create');
    expect(actions).toContain('key.rotate');
    expect(actions).toContain('key.disable');
    expect(actions).toContain('key.purge');

    // Ensure no audit event contains plaintext, key material, or secrets
    for (const ev of keyEvents) {
      const stringified = JSON.stringify(ev);
      expect(stringified).not.toMatch(/Patient #48192/);
      expect(stringified).not.toMatch(/rawKey/);
      expect(stringified).not.toMatch(/secret/);
      expect(stringified).not.toMatch(/encryptedKeyMaterial/);
    }
  });
});
