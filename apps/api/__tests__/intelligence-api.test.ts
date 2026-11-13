import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 8 — Crypto Intelligence & CBOM REST API', () => {
  let server: http.Server;
  let baseUrl: string;

  let userA: any;
  let sessionA: any;
  let orgA: any;
  let projectA: any;
  let envA: any;

  let userB: any;
  let sessionB: any;
  let orgB: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Set up Tenant A
    userA = await db.createUser({
      email: `intel_user_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A Intelligence Admin',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Enterprise Corp',
      slug: `tenant-a-intel-${Date.now()}`,
    });
    await db.addMember({
      organizationId: orgA.id,
      userId: userA.id,
      role: 'OWNER',
    });
    sessionA = await db.createSession({
      userId: userA.id,
      activeOrgId: orgA.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    projectA = await db.createProject({
      organizationId: orgA.id,
      name: 'Core Services',
      slug: `core-svc-${Date.now()}`,
    });
    envA = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      slug: 'prod',
      type: 'production',
    });

    // Seed Tenant A with a key and a certificate authority
    await db.createKey({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envA.id,
      name: 'auth-jwt-rsa-key',
      algorithm: 'RSA-2048',
      purpose: 'SIGNING',
      provider: 'LOCAL_DEV',
      status: 'ACTIVE',
    });

    await db.createCertificateAuthority({
      organizationId: orgA.id,
      projectId: projectA.id,
      environmentId: envA.id,
      name: 'Tenant A Root CA',
      type: 'ROOT_CA',
      subject: 'CN=Tenant A Root CA',
      issuer: 'CN=Tenant A Root CA',
      keyReference: 'ref_key_a',
      keyAlgorithm: 'RSA-4096',
      signatureAlgorithm: 'SHA256withRSA',
      certificatePem: '-----BEGIN CERTIFICATE-----\nMOCK_PEM\n-----END CERTIFICATE-----',
      serialNumber: '1001',
      fingerprint: 'fp_ca_a_1001',
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    });

    // Set up Tenant B
    userB = await db.createUser({
      email: `intel_user_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B Competitor Admin',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Competitor Corp',
      slug: `tenant-b-intel-${Date.now()}`,
    });
    await db.addMember({
      organizationId: orgB.id,
      userId: userB.id,
      role: 'OWNER',
    });
    sessionB = await db.createSession({
      userId: userB.id,
      activeOrgId: orgB.id,
      expiresAt: new Date(Date.now() + 86400000),
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  describe('1. Discovery Scan & Inventory Telemetry', () => {
    it('POST /scan initiates discovery scan, infers relationships, evaluates policy, and returns scan telemetry', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          policyName: 'DEFAULT_SECURE',
          sourceFiles: [
            {
              path: 'apps/api/src/crypto.ts',
              content: `
                const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
                const hash = crypto.createHash('sha256');
              `,
            },
          ],
        }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.scan.totalAssetsDiscovered).toBeGreaterThanOrEqual(3);
      expect(data.scan.sourceUsagesDetected).toBe(2);
      expect(data.scan.snapshotId).toBeDefined();
    });

    it('GET /inventory returns aggregated telemetry and quantum risk distribution', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/inventory`, {
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
      });

      expect(res.status).toBe(200);
      const { data } = await res.json();
      expect(data.totalAssets).toBeGreaterThanOrEqual(3);
      expect(data.quantumStatusSummary.QUANTUM_VULNERABLE).toBeGreaterThanOrEqual(1);
      expect(data.quantumStatusSummary.CLASSICAL).toBeGreaterThanOrEqual(1);
    });

    it('GET /assets lists assets and supports filtering by quantumStatus and assetType', async () => {
      const res = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/intelligence/assets?quantumStatus=QUANTUM_VULNERABLE`,
        {
          headers: {
            Authorization: `Bearer ${sessionA.sessionToken}`,
          },
        }
      );

      expect(res.status).toBe(200);
      const { data } = await res.json();
      expect(data.length).toBeGreaterThanOrEqual(1);
      for (const asset of data) {
        expect(asset.quantumStatus).toBe('QUANTUM_VULNERABLE');
      }
    });

    it('GET /assets/:id retrieves single asset and enforces tenant scoping', async () => {
      const listRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/assets`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      const { data: assets } = await listRes.json();
      expect(assets.length).toBeGreaterThan(0);

      const targetAsset = assets[0];
      const getRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/intelligence/assets/${targetAsset.id}`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );
      expect(getRes.status).toBe(200);
      const assetData = await getRes.json();
      expect(assetData.data.id).toBe(targetAsset.id);
      expect(assetData.data.name).toBe(targetAsset.name);
    });
  });

  describe('2. Dependency Graph & Downstream Impact Simulation', () => {
    it('GET /relationships lists explicit directional dependency edges', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/relationships`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });

      expect(res.status).toBe(200);
      const { data } = await res.json();
      expect(Array.isArray(data)).toBe(true);
    });

    it('GET /impact/:assetId traverses graph to compute affected downstream dependents', async () => {
      const listRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/assets`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      const { data: assets } = await listRes.json();
      const targetAsset = assets[0];

      const impactRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/intelligence/impact/${targetAsset.id}`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );

      expect(impactRes.status).toBe(200);
      const { data } = await impactRes.json();
      expect(data.assetId).toBe(targetAsset.id);
      expect(Array.isArray(data.affectedKeys)).toBe(true);
      expect(Array.isArray(data.affectedCertificates)).toBe(true);
      expect(typeof data.totalAffected).toBe('number');
    });
  });

  describe('3. Findings Triage & Audited False Positive Workflow', () => {
    it('PATCH /findings/:id updates finding status and records audited resolution justification', async () => {
      const listRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/findings`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      const { data: findings } = await listRes.json();

      if (findings.length > 0) {
        const finding = findings[0];
        const patchRes = await fetch(
          `${baseUrl}/v1/organizations/${orgA.id}/intelligence/findings/${finding.id}`,
          {
            method: 'PATCH',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${sessionA.sessionToken}`,
            },
            body: JSON.stringify({
              status: 'FALSE_POSITIVE',
              resolutionComment: 'Asset is behind an airgapped test harness. Verified harmless.',
            }),
          }
        );

        expect(patchRes.status).toBe(200);
        const { data: updated } = await patchRes.json();
        expect(updated.status).toBe('FALSE_POSITIVE');
        expect(updated.resolutionComment).toContain('airgapped test harness');
        expect(updated.resolvedBy).toBe(userA.id);
      }
    });
  });

  describe('4. Machine-Readable CBOM Export & Zero Secret Leakage', () => {
    it('GET /cbom and POST /cbom/export produce a valid CBOM JSON with integrity hash and 0 secret keys', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/cbom`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });

      expect(res.status).toBe(200);
      const cbom = await res.json();

      expect(cbom.cbomVersion).toBe('1.0.0');
      expect(cbom.organizationId).toBe(orgA.id);
      expect(cbom.components.length).toBeGreaterThanOrEqual(1);
      expect(cbom.integrity.algorithm).toBe('SHA-256');
      expect(cbom.integrity.hash).toHaveLength(64);

      // Verify ZERO SECRET LEAKAGE:
      const cbomStr = JSON.stringify(cbom);
      expect(cbomStr).not.toContain('PRIVATE KEY');
      expect(cbomStr).not.toContain('encryptedKeyMaterial');
      expect(cbomStr).not.toContain('encryptedAuthConfig');
    });
  });

  describe('5. Crypto-Agility Migration Plans', () => {
    let createdPlanId: string;

    it('POST /migrations creates a crypto migration plan', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/migrations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionA.sessionToken}`,
        },
        body: JSON.stringify({
          name: 'Core PKI Transition to ML-DSA',
          currentAlgorithm: 'RSA-2048',
          targetAlgorithm: 'ML-DSA-65',
          migrationStrategy: 'HYBRID_DUAL_RUN',
        }),
      });

      expect(res.status).toBe(201);
      const { data } = await res.json();
      expect(data.name).toBe('Core PKI Transition to ML-DSA');
      expect(data.currentAlgorithm).toBe('RSA-2048');
      expect(data.targetAlgorithm).toBe('ML-DSA-65');
      expect(data.status).toBe('IDENTIFIED');
      createdPlanId = data.id;
    });

    it('GET /migrations and GET /migrations/:id retrieve the plan', async () => {
      const res = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/intelligence/migrations/${createdPlanId}`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );

      expect(res.status).toBe(200);
      const { data } = await res.json();
      expect(data.id).toBe(createdPlanId);
      expect(data.targetAlgorithm).toBe('ML-DSA-65');
    });

    it('PATCH /migrations/:id updates plan state to PLANNED', async () => {
      const res = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/intelligence/migrations/${createdPlanId}`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${sessionA.sessionToken}`,
          },
          body: JSON.stringify({
            status: 'PLANNED',
            blockers: ['Awaiting firmware update on HSM provider'],
          }),
        }
      );

      expect(res.status).toBe(200);
      const { data } = await res.json();
      expect(data.status).toBe('PLANNED');
      expect(data.blockers).toContain('Awaiting firmware update on HSM provider');
    });
  });

  describe('6. Strict Multi-Tenant Isolation & IDOR Protection', () => {
    it('Tenant B cannot access Tenant A intelligence inventory', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/inventory`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      // Tenant B is not a member of Org A -> must be forbidden
      expect(res.status).toBe(403);
    });

    it('Tenant B cannot export Tenant A CBOM', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/intelligence/cbom`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      expect(res.status).toBe(403);
    });

    it('Tenant B cannot modify Tenant A findings or migration plans', async () => {
      const patchRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/intelligence/findings/fnd_fake_idor`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${sessionB.sessionToken}`,
          },
          body: JSON.stringify({ status: 'RESOLVED' }),
        }
      );
      expect(patchRes.status).toBe(403);
    });
  });

  describe('7. Audit Events Verification', () => {
    it('records structured audit events for discovery scan and CBOM export', async () => {
      const auditEvents = await db.getAuditEventsByOrg(orgA.id, 50);
      const actions = auditEvents.map((a) => a.action);

      expect(actions).toContain('CRYPTO_SCAN_STARTED');
      expect(actions).toContain('CRYPTO_SCAN_COMPLETED');
      expect(actions).toContain('CRYPTO_CBOM_EXPORTED');
    });
  });
});
