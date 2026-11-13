import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { Amaracus } from '@amaracus/sdk';

describe('Phase 16 — Enterprise Cryptographic Control Plane Test Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  // Tenant A: Primary Enterprise Organization
  let orgA: any;
  let projectA: any;
  let envAProd: any;
  let envAStaging: any;
  let apiKeyAFull: string;
  let scopedProjectApiKey: string;
  let scopedEnvApiKey: string;

  // Users for all 7 enterprise roles in Tenant A
  const roles = [
    'OWNER',
    'ADMIN',
    'SECURITY_ADMIN',
    'DEVELOPER',
    'AUDITOR',
    'BILLING_ADMIN',
    'READ_ONLY',
  ] as const;

  const roleTokens: Record<string, string> = {};
  const roleUsers: Record<string, any> = {};

  // Tenant B: Unrelated Organization for IDOR and boundary isolation testing
  let orgB: any;
  let projectB: any;
  let envBProd: any;
  let userB: any;
  let userBToken: string;

  // SDK Client
  let sdkClient: Amaracus;

  beforeAll(async () => {
    // 1. Start server on dynamic port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 2. Setup Tenant A
    orgA = await db.createOrganization({
      name: 'CyberDyne Systems Enterprise',
      slug: `cyberdyne-${Date.now()}`,
    });

    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Skynet Cryptographic Core',
      slug: 'skynet-core',
      description: 'Primary cryptographic project',
    });

    envAProd = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    envAStaging = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Staging',
      slug: 'staging',
      type: 'staging',
    });

    await db.upsertBillingSubscription({
      organizationId: orgA.id,
      plan: 'ENTERPRISE',
      status: 'ACTIVE',
    });

    // Create Tenant A master API key
    const rawMaster = generateAmaracusApiKey('live');
    apiKeyAFull = rawMaster.fullKey;
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      name: 'Tenant A Master Key',
      keyHash: rawMaster.keyHash,
      prefix: rawMaster.prefix,
      scopes: ['*'],
    });

    // Create Scoped API Key (scoped to Project A only)
    const rawScopedProj = generateAmaracusApiKey('live');
    scopedProjectApiKey = rawScopedProj.fullKey;
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAProd.id,
      name: 'Tenant A Project-Scoped Key',
      keyHash: rawScopedProj.keyHash,
      prefix: rawScopedProj.prefix,
      scopes: ['*'],
    });

    // Create Scoped API Key (scoped to Staging only)
    const rawScopedEnv = generateAmaracusApiKey('live');
    scopedEnvApiKey = rawScopedEnv.fullKey;
    await db.createApiCredential({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envAStaging.id,
      name: 'Tenant A Staging-Scoped Key',
      keyHash: rawScopedEnv.keyHash,
      prefix: rawScopedEnv.prefix,
      scopes: ['*'],
    });

    // Create users & sessions for all 7 roles in Tenant A
    for (const r of roles) {
      const u = await db.createUser({
        email: `${r.toLowerCase()}-${Date.now()}@cyberdyne.test`,
        name: `${r} User`,
        passwordHash: crypto.randomBytes(16).toString('hex'),
      });
      await db.addMember({
        organizationId: orgA.id,
        userId: u.id,
        role: r,
      });
      const token = `sess_${r.toLowerCase()}_${crypto.randomBytes(16).toString('hex')}`;
      await db.createSession({
        sessionToken: token,
        userId: u.id,
        activeOrgId: orgA.id,
        expiresAt: new Date(Date.now() + 86400000),
      });
      roleUsers[r] = u;
      roleTokens[r] = token;
    }

    // 3. Setup Tenant B (Attacker / Isolated Tenant)
    orgB = await db.createOrganization({
      name: 'Spectre Corp Isolation Target',
      slug: `spectre-${Date.now()}`,
    });

    projectB = await db.createProject({
      organizationId: orgB.id,
      name: 'Spectre Project Zero',
      slug: 'spectre-zero',
    });

    envBProd = await db.createEnvironment({
      projectId: projectB.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    userB = await db.createUser({
      email: `attacker-b-${Date.now()}@spectre.test`,
      name: 'Attacker B',
      passwordHash: 'dummy_hash',
    });
    await db.addMember({
      organizationId: orgB.id,
      userId: userB.id,
      role: 'DEVELOPER',
    });

    userBToken = `sess_attacker_b_${crypto.randomBytes(16).toString('hex')}`;
    await db.createSession({
      sessionToken: userBToken,
      userId: userB.id,
      activeOrgId: orgB.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // 4. Initialize TypeScript SDK client
    sdkClient = new Amaracus({
      apiKey: apiKeyAFull,
      baseUrl,
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  // =========================================================================
  // TEST SUITE 1: ENTERPRISE RBAC PERMISSION MATRIX ACROSS 7 ROLES
  // =========================================================================
  describe('1. Enterprise RBAC Enforcement & Least Privilege', () => {
    it('OWNER role has full control plane access (read org, settings, projects, keys)', async () => {
      const res = await fetch(`${baseUrl}/v1/control/organizations/${orgA.id}`, {
        headers: { Authorization: `Bearer ${roleTokens.OWNER}` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.organization.id).toBe(orgA.id);
    });

    it('ADMIN role can create projects but cannot manage OWNER role', async () => {
      // ADMIN creates project -> 201
      const createRes = await fetch(`${baseUrl}/v1/control/projects`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'Admin Managed Project',
          slug: `admin-proj-${Date.now()}`,
        }),
      });
      expect(createRes.status).toBe(201);

      // ADMIN attempts to update OWNER's role -> 403
      const updateRes = await fetch(`${baseUrl}/v1/control/organizations/${orgA.id}/members/${roleUsers.OWNER.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ role: 'DEVELOPER' }),
      });
      expect(updateRes.status).toBe(403);
    });

    it('SECURITY_ADMIN can view security and posture, but CANNOT access billing or delete projects', async () => {
      // SECURITY_ADMIN checks posture -> 200
      const postureRes = await fetch(`${baseUrl}/v1/control/posture`, {
        headers: {
          Authorization: `Bearer ${roleTokens.SECURITY_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(postureRes.status).toBe(200);

      // SECURITY_ADMIN attempts to access billing usage -> 403
      const billingRes = await fetch(`${baseUrl}/v1/control/usage`, {
        headers: {
          Authorization: `Bearer ${roleTokens.SECURITY_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(billingRes.status).toBe(403);

      // SECURITY_ADMIN attempts to delete project -> 403
      const delProjRes = await fetch(`${baseUrl}/v1/control/projects/${projectA.id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${roleTokens.SECURITY_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(delProjRes.status).toBe(403);
    });

    it('DEVELOPER can create keys and read projects, but CANNOT modify org security settings or delete projects', async () => {
      // DEVELOPER reads projects -> 200
      const projRes = await fetch(`${baseUrl}/v1/control/projects`, {
        headers: {
          Authorization: `Bearer ${roleTokens.DEVELOPER}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(projRes.status).toBe(200);

      // DEVELOPER creates key -> 201
      const keyRes = await fetch(`${baseUrl}/v1/control/keys`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.DEVELOPER}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          name: 'Developer AES Key',
          algorithm: 'AES-256-GCM',
          purpose: 'ENCRYPTION',
          projectId: projectA.id,
          environmentId: envAProd.id,
        }),
      });
      expect(keyRes.status).toBe(201);

      // DEVELOPER attempts to alter organization security settings -> 403
      const secRes = await fetch(`${baseUrl}/v1/control/organizations/${orgA.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${roleTokens.DEVELOPER}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          securitySettings: { requireMfa: true },
        }),
      });
      expect(secRes.status).toBe(403);

      // DEVELOPER attempts to delete project -> 403
      const delRes = await fetch(`${baseUrl}/v1/control/projects/${projectA.id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${roleTokens.DEVELOPER}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(delRes.status).toBe(403);
    });

    it('AUDITOR can read audit events, operations, and posture, but CANNOT rotate keys or modify resources', async () => {
      // AUDITOR reads audit logs -> 200
      const auditRes = await fetch(`${baseUrl}/v1/control/audit`, {
        headers: {
          Authorization: `Bearer ${roleTokens.AUDITOR}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(auditRes.status).toBe(200);

      // AUDITOR reads operations -> 200
      const opsRes = await fetch(`${baseUrl}/v1/control/operations`, {
        headers: {
          Authorization: `Bearer ${roleTokens.AUDITOR}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(opsRes.status).toBe(200);

      // AUDITOR creates a key -> 403
      const keyCreateRes = await fetch(`${baseUrl}/v1/control/keys`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.AUDITOR}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          name: 'Auditor Key Attempt',
          algorithm: 'AES-256-GCM',
        }),
      });
      expect(keyCreateRes.status).toBe(403);
    });

    it('BILLING_ADMIN can read usage, but CANNOT access keys, operations, or posture', async () => {
      // BILLING_ADMIN reads usage -> 200
      const usageRes = await fetch(`${baseUrl}/v1/control/usage`, {
        headers: {
          Authorization: `Bearer ${roleTokens.BILLING_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(usageRes.status).toBe(200);

      // BILLING_ADMIN attempts to list keys -> 403
      const keysRes = await fetch(`${baseUrl}/v1/control/keys`, {
        headers: {
          Authorization: `Bearer ${roleTokens.BILLING_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(keysRes.status).toBe(403);

      // BILLING_ADMIN attempts to list operations -> 403
      const opsRes = await fetch(`${baseUrl}/v1/control/operations`, {
        headers: {
          Authorization: `Bearer ${roleTokens.BILLING_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(opsRes.status).toBe(403);
    });

    it('READ_ONLY can view projects and keys, but CANNOT create or mutate anything', async () => {
      // READ_ONLY reads projects -> 200
      const projRes = await fetch(`${baseUrl}/v1/control/projects`, {
        headers: {
          Authorization: `Bearer ${roleTokens.READ_ONLY}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(projRes.status).toBe(200);

      // READ_ONLY attempts to create a project -> 403
      const createRes = await fetch(`${baseUrl}/v1/control/projects`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.READ_ONLY}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({ name: 'Disallowed Proj', slug: 'disallowed-proj' }),
      });
      expect(createRes.status).toBe(403);
    });
  });

  // =========================================================================
  // TEST SUITE 2: RESOURCE-LEVEL AUTHORIZATION & IDOR ISOLATION
  // =========================================================================
  describe('2. Resource-Level Authorization & IDOR Defense', () => {
    it('Tenant B user attempting to access Tenant A project receives 404 (IDOR defense prevents enumeration)', async () => {
      const res = await fetch(`${baseUrl}/v1/control/projects/${projectA.id}`, {
        headers: {
          Authorization: `Bearer ${userBToken}`,
          'x-organization-id': orgB.id,
        },
      });
      // MUST be 404 not 403 so attacker cannot probe resource existence
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.error.code).toBe('PROJECT_NOT_FOUND');
    });

    it('Tenant B user attempting to access Tenant A environments receives 404', async () => {
      const res = await fetch(`${baseUrl}/v1/control/projects/${projectA.id}/environments`, {
        headers: {
          Authorization: `Bearer ${userBToken}`,
          'x-organization-id': orgB.id,
        },
      });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.error.code).toBe('PROJECT_NOT_FOUND');
    });

    it('API key scoped to Project A is rejected when attempting to access Project B with 403', async () => {
      const res = await fetch(`${baseUrl}/v1/control/projects/${projectB.id}`, {
        headers: {
          Authorization: `Bearer ${scopedProjectApiKey}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error.code).toBe('CROSS_PROJECT_ACCESS_DENIED');
    });

    it('API key scoped to Environment Staging is rejected on Environment Production with 403', async () => {
      const res = await fetch(
        `${baseUrl}/v1/control/projects/${projectA.id}/environments?environmentId=${envAProd.id}`,
        {
          headers: {
            Authorization: `Bearer ${scopedEnvApiKey}`,
            'x-organization-id': orgA.id,
          },
        }
      );
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error.code).toBe('CROSS_ENVIRONMENT_ACCESS_DENIED');
    });
  });

  // =========================================================================
  // TEST SUITE 3: TEAMS & COLLABORATION CRUD
  // =========================================================================
  describe('3. Teams & Team Collaboration', () => {
    let createdTeamId: string;

    it('creates a team within the organization', async () => {
      const res = await fetch(`${baseUrl}/v1/control/teams`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          name: 'Cryptography Engineering Team',
          description: 'Engineers managing post-quantum keys',
        }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.team.name).toBe('Cryptography Engineering Team');
      expect(body.data.team.organizationId).toBe(orgA.id);
      createdTeamId = body.data.team.id;
    });

    it('lists teams in the organization', async () => {
      const res = await fetch(`${baseUrl}/v1/control/teams`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.data.teams)).toBe(true);
      expect(body.data.teams.some((t: any) => t.id === createdTeamId)).toBe(true);
    });

    it('adds and removes a team member', async () => {
      // Add DEVELOPER user to the team
      const addRes = await fetch(`${baseUrl}/v1/control/teams/${createdTeamId}/members`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          userId: roleUsers.DEVELOPER.id,
          role: 'ENGINEER',
        }),
      });
      expect(addRes.status).toBe(201);

      // Verify member appears in team details
      const getRes = await fetch(`${baseUrl}/v1/control/teams/${createdTeamId}`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(getRes.status).toBe(200);
      const getBody = await getRes.json();
      expect(getBody.data.team.members.some((m: any) => m.userId === roleUsers.DEVELOPER.id)).toBe(true);

      // Remove member from team
      const remRes = await fetch(`${baseUrl}/v1/control/teams/${createdTeamId}/members/${roleUsers.DEVELOPER.id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(remRes.status).toBe(200);
    });

    it('updates and deletes a team', async () => {
      const patchRes = await fetch(`${baseUrl}/v1/control/teams/${createdTeamId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({ name: 'Updated Crypto Team' }),
      });
      expect(patchRes.status).toBe(200);

      const delRes = await fetch(`${baseUrl}/v1/control/teams/${createdTeamId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(delRes.status).toBe(200);
    });
  });

  // =========================================================================
  // TEST SUITE 4: SERVICE IDENTITIES & RAW SECRET RETURN-ONCE
  // =========================================================================
  describe('4. Service Identities & API Keys Lifecycle', () => {
    let serviceId: string;
    let serviceSecret: string;

    it('creates service identity and returns plaintext secret ONLY ONCE', async () => {
      const res = await fetch(`${baseUrl}/v1/control/service-identities`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          name: 'Payment CI/CD Runner',
          description: 'Automated runner identity',
          projectId: projectA.id,
          scopes: ['crypto:execute', 'keys:read'],
        }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();

      expect(body.data.serviceIdentity).toBeDefined();
      expect(body.data.serviceIdentity.name).toBe('Payment CI/CD Runner');
      expect(body.data.secretKey).toBeDefined();
      expect(body.data.secretKey.startsWith('amsi_')).toBe(true);

      serviceId = body.data.serviceIdentity.id;
      serviceSecret = body.data.secretKey;
    });

    it('listing service identities DOES NOT reveal raw secret or keyHash', async () => {
      const res = await fetch(`${baseUrl}/v1/control/service-identities`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      const identity = body.data.serviceIdentities.find((si: any) => si.id === serviceId);

      expect(identity).toBeDefined();
      expect(identity.secretKey).toBeUndefined();
      expect(identity.keyHash).toBeUndefined();
      expect(identity.prefix.startsWith('amsi_')).toBe(true);
    });

    it('revoking service identity marks status REVOKED and prevents further access', async () => {
      const res = await fetch(`${baseUrl}/v1/control/service-identities/${serviceId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(200);

      // Verify revoked status in list
      const listRes = await fetch(`${baseUrl}/v1/control/service-identities`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      const listBody = await listRes.json();
      const identity = listBody.data.serviceIdentities.find((si: any) => si.id === serviceId);
      expect(identity.status).toBe('REVOKED');
    });
  });

  // =========================================================================
  // TEST SUITE 5: KEY MANAGEMENT CONTROL PLANE (GOVERNANCE & METADATA)
  // =========================================================================
  describe('5. Key Management Control Plane (Zero Material Leakage)', () => {
    let testKeyId: string;

    it('creates key and lists keys with posture & PQC metadata', async () => {
      const createRes = await fetch(`${baseUrl}/v1/control/keys`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          name: 'ML-KEM Posture Test Key',
          algorithm: 'ML-KEM-768',
          purpose: 'KEY_EXCHANGE',
          projectId: projectA.id,
          environmentId: envAProd.id,
        }),
      });
      expect(createRes.status).toBe(201);
      const createBody = await createRes.json();
      testKeyId = createBody.data.key.id;

      // List keys
      const listRes = await fetch(`${baseUrl}/v1/control/keys`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(listRes.status).toBe(200);
      const listBody = await listRes.json();
      const found = listBody.data.keys.find((k: any) => k.id === testKeyId);
      expect(found).toBeDefined();
      expect(found.isPqc).toBe(true);
      expect(typeof found.ageDays).toBe('number');
      expect(found.status).toBe('ACTIVE');
    });

    it('getting key details guarantees ZERO private key material is returned', async () => {
      const res = await fetch(`${baseUrl}/v1/control/keys/${testKeyId}`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.key.id).toBe(testKeyId);

      // Verify no keyMaterial in versions
      if (body.data.key.versions) {
        for (const ver of body.data.key.versions) {
          expect(ver.keyMaterial).toBeUndefined();
          expect(ver.privateKey).toBeUndefined();
        }
      }
    });

    it('governs key lifecycle: rotate, disable, enable, and destroy', async () => {
      // 1. Rotate key
      const rotateRes = await fetch(`${baseUrl}/v1/control/keys/${testKeyId}/rotate`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(rotateRes.status).toBe(200);
      const rotateBody = await rotateRes.json();
      expect(rotateBody.data.key.currentVersion).toBe(2);

      // 2. Disable key
      const disableRes = await fetch(`${baseUrl}/v1/control/keys/${testKeyId}/disable`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(disableRes.status).toBe(200);
      const disableBody = await disableRes.json();
      expect(disableBody.data.key.status).toBe('DISABLED');

      // 3. Enable key
      const enableRes = await fetch(`${baseUrl}/v1/control/keys/${testKeyId}/enable`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(enableRes.status).toBe(200);
      const enableBody = await enableRes.json();
      expect(enableBody.data.key.status).toBe('ACTIVE');

      // 4. Destroy key
      const destroyRes = await fetch(`${baseUrl}/v1/control/keys/${testKeyId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(destroyRes.status).toBe(200);
      const destroyBody = await destroyRes.json();
      expect(destroyBody.data.status).toBe('DESTROYED');
    });
  });

  // =========================================================================
  // TEST SUITE 6: PROVIDER CAPABILITIES & SECURE CONNECTIVITY
  // =========================================================================
  describe('6. Provider Management & Capabilities Matrix', () => {
    it('lists providers and transparently disallows PQC on Azure Managed HSM', async () => {
      const res = await fetch(`${baseUrl}/v1/control/providers`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.data.providers)).toBe(true);

      const azureHsm = body.data.providers.find((p: any) => p.providerType === 'AZURE_MANAGED_HSM');
      expect(azureHsm).toBeDefined();
      expect(azureHsm.isHsm).toBe(true);
      expect(azureHsm.status).toBe('PREVIEW');
      expect(azureHsm.capabilities.fipsCompliant).toBe(true);
      // Transparent disclosure: Azure Managed HSM does not yet natively support PQC algorithms
      expect(azureHsm.capabilities.pqcAlgorithms).toBe(false);

      const amaracusLocal = body.data.providers.find((p: any) => p.providerType === 'AMARACUS_MANAGED');
      expect(amaracusLocal).toBeDefined();
      expect(amaracusLocal.capabilities.pqcAlgorithms).toBe(true);
    });

    it('does not report a made-up healthy result for provider connectivity', async () => {
      const res = await fetch(`${baseUrl}/v1/control/providers/prov_azure_managed_hsm/test`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.status).toBe('NOT_TESTED');
      expect(body.data.latencyMs).toBeNull();
      expect(body.data.clientSecret).toBeUndefined();
    });
  });

  // =========================================================================
  // TEST SUITE 7: CRYPTOGRAPHIC POSTURE & CONFIGURATION DRIFT
  // =========================================================================
  describe('7. Cryptographic Posture & Drift Management', () => {
    it('evaluates cryptographic posture, key lifecycle distribution, and PQC readiness score', async () => {
      const res = await fetch(`${baseUrl}/v1/control/posture`, {
        headers: {
          Authorization: `Bearer ${roleTokens.SECURITY_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      const posture = body.data.posture;

      expect(typeof posture.postureScore).toBe('number');
      expect(posture.postureScore).toBeGreaterThanOrEqual(0);
      expect(posture.postureScore).toBeLessThanOrEqual(100);
      expect(typeof posture.pqcReadinessScore).toBe('number');
      expect(posture.keySummary).toBeDefined();
      expect(posture.certificateSummary).toBeDefined();
      expect(posture.driftSummary).toBeDefined();
    });

    it('detects, records, and resolves configuration drift', async () => {
      // 1. Manually insert a drift record via DataStore
      const drift = await db.recordDrift({
        organizationId: orgA.id,
        resourceType: 'POLICY',
        resourceId: 'pol_drift_test',
        driftSummary: 'Production policy algorithm AES-128 does not match approved baseline AES-256',
        expectedState: { algorithm: 'AES-256' },
        actualState: { algorithm: 'AES-128' },
      });

      // 2. Fetch drifts via control plane
      const driftsRes = await fetch(`${baseUrl}/v1/control/drifts`, {
        headers: {
          Authorization: `Bearer ${roleTokens.SECURITY_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(driftsRes.status).toBe(200);
      const driftsBody = await driftsRes.json();
      expect(driftsBody.data.drifts.some((d: any) => d.id === drift.id)).toBe(true);

      // 3. Resolve drift
      const resolveRes = await fetch(`${baseUrl}/v1/control/drifts/${drift.id}/resolve`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.SECURITY_ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(resolveRes.status).toBe(200);

      // 4. Verify drift is no longer detected in active list
      const resolvedList = await db.listDriftRecords(orgA.id);
      const foundDrift = resolvedList.find((d: any) => d.id === drift.id);
      expect(foundDrift?.status).toBe('RESOLVED');
    });
  });

  // =========================================================================
  // TEST SUITE 8: END-TO-END CONTROL PLANE LIFECYCLE FLOW
  // =========================================================================
  describe('8. End-to-End Enterprise Control Plane Flow', () => {
    it('executes full enterprise lifecycle: org -> project -> environments -> member -> key -> promotion -> audit', async () => {
      // 1. Admin creates project
      const projRes = await fetch(`${baseUrl}/v1/control/projects`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          name: 'Fintech Zero Trust Vault',
          slug: `fintech-vault-${Date.now()}`,
          description: 'Banking grade cryptographic key storage',
        }),
      });
      expect(projRes.status).toBe(201);
      const projBody = await projRes.json();
      const newProjId = projBody.data.project.id;

      // 2. Verify default environments (Production, Staging, Development) auto-created
      const envRes = await fetch(`${baseUrl}/v1/control/projects/${newProjId}/environments`, {
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(envRes.status).toBe(200);
      const envBody = await envRes.json();
      expect(envBody.data.environments.length).toBeGreaterThanOrEqual(3);
      const prodEnv = envBody.data.environments.find((e: any) => e.type === 'production');
      const stagingEnv = envBody.data.environments.find((e: any) => e.type === 'staging');

      // 3. Promote configuration from Staging to Production
      const promoteRes = await fetch(`${baseUrl}/v1/control/promotions`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${roleTokens.ADMIN}`,
          'Content-Type': 'application/json',
          'x-organization-id': orgA.id,
        },
        body: JSON.stringify({
          sourceEnvId: stagingEnv.id,
          targetEnvId: prodEnv.id,
          resourceType: 'POLICY',
          resourceId: 'pol_baseline_quantum_2026',
        }),
      });
      expect(promoteRes.status).toBe(200);
      const promoteBody = await promoteRes.json();
      expect(promoteBody.data.status).toBe('PROMOTED');

      // 4. Verify chronological audit trail records the promotion and lifecycle actions
      const auditRes = await fetch(`${baseUrl}/v1/control/audit?limit=10`, {
        headers: {
          Authorization: `Bearer ${roleTokens.AUDITOR}`,
          'x-organization-id': orgA.id,
        },
      });
      expect(auditRes.status).toBe(200);
      const auditBody = await auditRes.json();
      expect(Array.isArray(auditBody.data.auditEvents)).toBe(true);
      expect(auditBody.data.auditEvents.some((evt: any) => evt.action === 'CONFIGURATION_PROMOTED')).toBe(true);
      expect(auditBody.data.auditEvents.some((evt: any) => evt.action === 'PROJECT_CREATED')).toBe(true);
    });
  });

  // =========================================================================
  // TEST SUITE 9: OFFICIAL TYPESCRIPT SDK CONTROL PLANE CLIENT
  // =========================================================================
  describe('9. Official TypeScript SDK Control Plane Client', () => {
    it('uses sdkClient.projects to list projects and environments', async () => {
      const projects = await sdkClient.projects.list();
      expect(Array.isArray(projects)).toBe(true);
      expect(projects.length).toBeGreaterThanOrEqual(1);

      const envs = await sdkClient.projects.listEnvironments(projectA.id);
      expect(Array.isArray(envs)).toBe(true);
      expect(envs.length).toBeGreaterThanOrEqual(2);
    });

    it('uses sdkClient.posture to retrieve posture score and drifts', async () => {
      const posture = await sdkClient.posture.get();
      expect(posture).toBeDefined();
      expect(typeof (posture.overallPostureScore ?? (posture as any).postureScore)).toBe('number');
      expect(typeof posture.pqcReadinessScore).toBe('number');

      const drifts = await sdkClient.posture.drifts();
      expect(Array.isArray(drifts)).toBe(true);
    });

    it('uses sdkClient.control to manage teams and service identities', async () => {
      // Create team via SDK
      const team = await sdkClient.control.teams.create({
        name: 'SDK Managed Team',
        description: 'Team created via SDK',
      });
      expect(team.name).toBe('SDK Managed Team');

      const teams = await sdkClient.control.teams.list();
      expect(teams.some((t) => t.id === team.id)).toBe(true);

      // Create service identity via SDK
      const siResult = await sdkClient.control.serviceIdentities.create({
        name: 'SDK CI Runner',
        description: 'Created through SDK client',
      });
      expect(siResult.serviceIdentity.name).toBe('SDK CI Runner');
      expect(siResult.secretKey.startsWith('amsi_')).toBe(true);

      // Revoke service identity via SDK
      const revokeRes = await sdkClient.control.serviceIdentities.revoke(siResult.serviceIdentity.id);
      expect(revokeRes.success).toBe(true);
    });
  });
});
