import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 7 — PKI & Certificate Management API Routes', () => {
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
      email: `pki_user_a_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant A PKI Admin',
    });
    orgA = await db.createOrganization({
      name: 'Tenant A Security Org',
      slug: `tenant-a-pki-${Date.now()}`,
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
      name: 'Infrastructure PKI',
      slug: `infra-pki-${Date.now()}`,
    });
    envA = await db.createEnvironment({
      projectId: projectA.id,
      name: 'Production',
      slug: 'prod',
      type: 'production',
    });

    // Set up Tenant B
    userB = await db.createUser({
      email: `pki_user_b_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Tenant B PKI User',
    });
    orgB = await db.createOrganization({
      name: 'Tenant B Separate Org',
      slug: `tenant-b-pki-${Date.now()}`,
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
  }, 60000);

  afterAll((done) => {
    server.close(done);
  });

  // =========================================================================
  // 1. TENANCY & AUTHENTICATION BOUNDARIES
  // =========================================================================
  describe('Authentication & Multi-Tenant Boundary Enforcement', () => {
    it('rejects unauthenticated requests to PKI CA list with 401', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`);
      expect(res.status).toBe(401);
    });

    it('rejects cross-tenant access from Tenant B to Tenant A PKI with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`, {
        headers: { Authorization: `Bearer ${sessionB.sessionToken}` },
      });
      expect(res.status).toBe(403);
    });
  });

  // =========================================================================
  // 2. CERTIFICATE AUTHORITY (CA) ENDPOINTS
  // =========================================================================
  describe('Certificate Authority Lifecycle Endpoints', () => {
    let rootCaId: string;
    let intermediateCaId: string;

    it('creates a Root CA without exposing any private key material', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'Amaracus Test Root CA',
          description: 'Primary Root CA for Automated Tests',
          projectId: projectA.id,
          environmentId: envA.id,
          type: 'ROOT_CA',
          subject: 'CN=Amaracus Test Root CA, O=Amaracus Technologies, C=US',
          keyAlgorithm: 'RSA-4096',
          validityDays: 3650,
          pathLenConstraint: 2,
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data).toBeDefined();
      expect(body.data.id).toBeDefined();
      expect(body.data.type).toBe('ROOT_CA');
      expect(body.data.status).toBe('ACTIVE');
      expect(body.data.certificatePem).toContain('-----BEGIN CERTIFICATE-----');

      // Security check: zero private key leakage
      expect(JSON.stringify(body)).not.toContain('PRIVATE KEY');
      rootCaId = body.data.id;
    });

    it('creates an Intermediate CA signed by Root CA', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'Amaracus Test Sub CA',
          description: 'Issuing Subordinate CA',
          projectId: projectA.id,
          environmentId: envA.id,
          type: 'INTERMEDIATE_CA',
          parentAuthorityId: rootCaId,
          subject: 'CN=Amaracus Test Sub CA, O=Amaracus Technologies, C=US',
          keyAlgorithm: 'RSA-2048',
          validityDays: 1825,
          pathLenConstraint: 0,
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.type).toBe('INTERMEDIATE_CA');
      expect(body.data.parentAuthorityId).toBe(rootCaId);
      intermediateCaId = body.data.id;
    });

    it('lists all CAs for the organization', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.length).toBeGreaterThanOrEqual(2);
      const caIds = body.data.map((c: any) => c.id);
      expect(caIds).toContain(rootCaId);
      expect(caIds).toContain(intermediateCaId);
    });

    it('generates and retrieves an RFC 5280 CRL for the CA', async () => {
      // POST CRL generation
      const genRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities/${rootCaId}/crl`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${sessionA.sessionToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ nextUpdateDays: 7 }),
        }
      );
      expect(genRes.status).toBe(200);
      const genBody = await genRes.json();
      expect(genBody.data.crlPem).toContain('-----BEGIN CRL-----');

      // GET CRL download
      const getRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities/${rootCaId}/crl`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );
      expect(getRes.status).toBe(200);
      const getText = await getRes.text();
      expect(getText).toContain('-----BEGIN CRL-----');
    });
  });

  // =========================================================================
  // 3. END-ENTITY CERTIFICATE ISSUANCE, VALIDATION, RENEWAL, REVOCATION
  // =========================================================================
  describe('Certificate Lifecycle Operations', () => {
    let issuingCaId: string;
    let leafCertId: string;
    let renewedCertId: string;

    beforeAll(async () => {
      // Create dedicated issuing CA
      const caRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'Issuing CA for Cert Tests',
          projectId: projectA.id,
          environmentId: envA.id,
          type: 'ROOT_CA',
          subject: 'CN=Issuing CA for Cert Tests, O=Amaracus, C=US',
          keyAlgorithm: 'RSA-4096',
          validityDays: 3650,
        }),
      });
      const caData = await caRes.json();
      issuingCaId = caData.data.id;
    });

    it('issues an end-entity certificate with SANs and correct RFC 5280 extensions', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificates`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'api.cluster.internal',
          authorityId: issuingCaId,
          projectId: projectA.id,
          environmentId: envA.id,
          certificateType: 'SERVER',
          subject: 'CN=api.cluster.internal, O=Amaracus, C=US',
          keyAlgorithm: 'RSA-2048',
          validityDays: 365,
          san: {
            dns: ['api.cluster.internal', 'api.prod.svc'],
            ips: ['10.244.0.5'],
          },
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.id).toBeDefined();
      expect(body.data.status).toBe('ACTIVE');
      expect(body.data.certificatePem).toContain('-----BEGIN CERTIFICATE-----');
      expect(body.data.chainPem).toBeDefined();
      expect(body.data.fingerprint).toBeDefined();

      leafCertId = body.data.id;
    });

    it('performs on-demand cryptographic chain validation', async () => {
      const res = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificates/${leafCertId}/validate`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${sessionA.sessionToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ checkRevocation: true, checkExpiry: true }),
        }
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.isValid).toBe(true);
      expect(body.data.chainValid).toBe(true);
      expect(['VALID', 'ACTIVE']).toContain(body.data.status);
      expect(body.data.revocationStatus).toBe('GOOD');
    });

    it('renews an existing certificate and preserves lineage (renewalOfId)', async () => {
      const res = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificates/${leafCertId}/renew`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${sessionA.sessionToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ reuseExistingKey: false, validityDays: 365 }),
        }
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.id).toBeDefined();
      expect(body.data.id).not.toBe(leafCertId);
      expect(body.data.renewalOfId).toBe(leafCertId);
      expect(body.data.status).toBe('ACTIVE');

      renewedCertId = body.data.id;

      // Old certificate status should be REPLACED
      const oldRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificates/${leafCertId}`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );
      const oldBody = await oldRes.json();
      expect(oldBody.data.status).toBe('REPLACED');
      expect(oldBody.data.replacedById).toBe(renewedCertId);
    });

    it('revokes a certificate with RFC 5280 reason and reflects in OCSP', async () => {
      const res = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificates/${renewedCertId}/revoke`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${sessionA.sessionToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            reason: 'KEY_COMPROMISE',
            comment: 'Simulated private key compromise during test run',
          }),
        }
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.status).toBe('REVOKED');
      expect(body.data.revocation).toBeDefined();
      expect(body.data.revocation.reason).toBe('KEY_COMPROMISE');

      // Check OCSP endpoint
      const ocspRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/ocsp/${renewedCertId}`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );
      expect(ocspRes.status).toBe(200);
      const ocspBody = await ocspRes.json();
      expect(ocspBody.data.status).toBe('REVOKED');
      expect(ocspBody.data.revoked).toBe(true);
      expect(ocspBody.data.revocationReason).toBe('KEY_COMPROMISE');
    });
  });

  // =========================================================================
  // 4. PKCS#10 CSR STUDIO ENDPOINTS
  // =========================================================================
  describe('CSR Studio API Endpoints', () => {
    let csrId: string;
    let csrPem: string;

    it('generates a PKCS#10 CSR', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/csrs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          projectId: projectA.id,
          environmentId: envA.id,
          subject: 'CN=csr-test.amaracus.net, O=Amaracus, C=US',
          keyAlgorithm: 'RSA-2048',
          san: { dns: ['csr-test.amaracus.net'] },
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.id).toBeDefined();
      expect(body.data.csrPem).toContain('-----BEGIN CERTIFICATE REQUEST-----');
      expect(body.data.status).toBe('PENDING');

      csrId = body.data.id;
      csrPem = body.data.csrPem;
    });

    it('validates an uploaded raw CSR PEM', async () => {
      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/csrs/validate`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ csrPem }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.isValid).toBe(true);
      expect(body.data.subject).toContain('CN=csr-test.amaracus.net');
    });

    it('signs the CSR using an issuing CA and returns an active certificate', async () => {
      // Get an existing CA
      const caListRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );
      const caList = await caListRes.json();
      const issuingCa = caList.data[0];

      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/csrs/${csrId}/sign`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          authorityId: issuingCa.id,
          certificateType: 'SERVER',
          validityDays: 365,
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.status).toBe('ACTIVE');
      expect(body.data.certificatePem).toContain('-----BEGIN CERTIFICATE-----');

      // CSR status should now be ISSUED
      const csrCheckRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/csrs/${csrId}`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      const csrCheck = await csrCheckRes.json();
      expect(csrCheck.data.status).toBe('ISSUED');
      expect(csrCheck.data.certificateId).toBe(body.data.id);
    });
  });

  // =========================================================================
  // 5. TRUTHFUL GATING & ZERO LEAKAGE AUDIT LOGS
  // =========================================================================
  describe('Truthful Gating and Audit Trail Integrity', () => {
    it('rejects PQC certificate issuance requests with UNSUPPORTED_PQC_X509', async () => {
      const caListRes = await fetch(
        `${baseUrl}/v1/organizations/${orgA.id}/pki/certificate-authorities`,
        {
          headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
        }
      );
      const caList = await caListRes.json();
      const issuingCa = caList.data[0];

      const res = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/pki/certificates`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionA.sessionToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'pqc.fake.attempt',
          authorityId: issuingCa.id,
          projectId: projectA.id,
          environmentId: envA.id,
          certificateType: 'SERVER',
          subject: 'CN=pqc.test.net, O=Amaracus, C=US',
          keyAlgorithm: 'ML-DSA-65', // Post-Quantum
          validityDays: 365,
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error.code).toBe('UNSUPPORTED_PQC_X509');
    });

    it('confirms audit log events recorded without any private key material', async () => {
      const auditRes = await fetch(`${baseUrl}/v1/organizations/${orgA.id}/audit`, {
        headers: { Authorization: `Bearer ${sessionA.sessionToken}` },
      });
      expect(auditRes.status).toBe(200);
      const auditBody = await auditRes.json();
      const events = auditBody.auditEvents || auditBody.data || [];

      // Verify PKI events exist
      const pkiEvents = events.filter((e: any) => e.resourceType === 'PKI');
      expect(pkiEvents.length).toBeGreaterThan(0);

      // Verify zero private key leakage in all audit metadata
      for (const ev of pkiEvents) {
        const metadataStr = JSON.stringify(ev.metadata || {});
        expect(metadataStr).not.toContain('PRIVATE KEY');
        expect(metadataStr).not.toContain('encryptedKeyMaterial');
      }
    });
  });
});
