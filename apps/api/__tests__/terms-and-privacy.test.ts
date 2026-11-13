import http from 'http';
import { TERMS_VERSION, PRIVACY_POLICY_VERSION } from '../src/lib/legal-versions';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Terms of Service & Privacy Compliance Integration Tests', () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll((done) => {
    server = app.listen(0, () => {
      const address = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${address.port}`;
      done();
    });
  });

  afterAll((done) => {
    if (server) {
      if (typeof (server as any).closeAllConnections === 'function') {
        (server as any).closeAllConnections();
      }
      server.close(done);
    } else {
      done();
    }
  });

  async function createTestUserSession() {
    const userId = `usr_terms_${crypto.randomUUID().slice(0, 8)}`;
    const orgId = `org_terms_${crypto.randomUUID().slice(0, 8)}`;
    const email = `compliance_${crypto.randomUUID().slice(0, 8)}@amaracus.tech`;

    await db.createOrganization({
      id: orgId,
      name: 'Legal Test Org',
      slug: `org-${crypto.randomUUID().slice(0, 6)}`,
    });

    const user = await db.createUser({
      id: userId,
      email,
      name: 'Legal Auditor',
      passwordHash: 'hash',
    });

    await db.addMember({
      organizationId: orgId,
      userId: user.id,
      role: 'OWNER',
    });

    const token = `sess_${crypto.randomUUID()}`;
    await db.createSession({
      sessionToken: token,
      userId: user.id,
      activeOrgId: orgId,
      expiresAt: new Date(Date.now() + 86400000),
    });

    return { userId: user.id, orgId, email, token };
  }

  it('1. POST /v1/auth/signup strictly rejects signup without explicit terms acceptance (400 TERMS_REQUIRED)', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `reject_${Date.now()}@amaracus.dev`,
        password: 'Password123!',
        name: 'Unconsenting User',
        organizationName: 'Unconsenting Org',
        termsAccepted: false,
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe('TERMS_REQUIRED');
  });

  it('2. POST /v1/user/accept-terms requires authentication (401 Unauthorized)', async () => {
    const res = await fetch(`${baseUrl}/v1/user/accept-terms`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        termsVersion: '1.0.0',
      }),
    });

    expect(res.status).toBe(401);
  });

  it('3. POST /v1/user/accept-terms creates an auditable legal record with version and timestamp', async () => {
    const { token, orgId, email } = await createTestUserSession();

    const res = await fetch(`${baseUrl}/v1/user/accept-terms`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'X-Organization-Id': orgId,
      },
      body: JSON.stringify({
        termsVersion: '1.0.0',
        privacyPolicyVersion: '1.0.0',
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.record).toBeDefined();
    expect(body.record.termsVersion).toBe('1.0.0');
    expect(body.record.privacyPolicyVersion).toBe('1.0.0');
    expect(body.record.acceptedAt).toBeDefined();
    expect(body.record.auditId).toBeDefined();
  });

  it('4. GET /v1/user/privacy-status returns DPDPA & GDPR frameworks and retention schedules', async () => {
    const { token, orgId } = await createTestUserSession();

    const res = await fetch(`${baseUrl}/v1/user/privacy-status`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Organization-Id': orgId,
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.termsVersion).toBe(TERMS_VERSION);
    expect(body.privacyPolicyVersion).toBe(PRIVACY_POLICY_VERSION);
    expect(body.retentionSchedules.auditLogsDays).toBe(180);
    expect(body.retentionSchedules.taxAndBillingYears).toBe(7);
    expect(body.applicableFrameworks).toContain('Digital Personal Data Protection Act, 2023 (DPDPA - India)');
    expect(body.applicableFrameworks).toContain('General Data Protection Regulation (GDPR - EU 2016/679)');
  });

  it('5. GET /v1/user/export-data exports user data in structured JSON without leaking password hashes', async () => {
    const { token, orgId, email } = await createTestUserSession();

    const res = await fetch(`${baseUrl}/v1/user/export-data`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Organization-Id': orgId,
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.exportMetadata).toBeDefined();
    expect(body.exportMetadata.exportFormat).toBe('JSON');
    expect(body.userProfile.email).toBe(email);
    expect(body.userProfile.passwordHash).toBeUndefined();
  });
});
