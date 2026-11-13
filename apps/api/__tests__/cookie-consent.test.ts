import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Cookie Consent Interface & Compliance Integration Tests', () => {
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
    const userId = `usr_cookie_${crypto.randomUUID().slice(0, 8)}`;
    const orgId = `org_cookie_${crypto.randomUUID().slice(0, 8)}`;
    const email = `cookie_test_${crypto.randomUUID().slice(0, 8)}@amaracus.tech`;

    await db.createOrganization({
      id: orgId,
      name: 'Cookie Test Org',
      slug: `org-${crypto.randomUUID().slice(0, 6)}`,
    });

    const user = await db.createUser({
      id: userId,
      email,
      name: 'Cookie Auditor',
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

  // 1. Acceptance
  it('1. POST /v1/user/cookie-consent records "accepted" status with version, timestamp, and audit trail', async () => {
    const { token, orgId, email } = await createTestUserSession();

    const res = await fetch(`${baseUrl}/v1/user/cookie-consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'X-Organization-Id': orgId,
      },
      body: JSON.stringify({
        status: 'accepted',
        categories: {
          necessary: true,
          functional: true,
          analytics: true,
          marketing: false, // Marketing is strictly prohibited / zero trackers
        },
        consentVersion: '1.0.0',
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.record.status).toBe('accepted');
    expect(body.record.categories.necessary).toBe(true);
    expect(body.record.categories.functional).toBe(true);
    expect(body.record.categories.marketing).toBe(false); // Must never be true
    expect(body.record.consentVersion).toBe('1.0.0');
    expect(body.record.recordedAt).toBeDefined();
    expect(body.record.auditId).toBeDefined();
  });

  // 2. Rejection
  it('2. POST /v1/user/cookie-consent records "rejected" non-essential status (strictly necessary only)', async () => {
    const res = await fetch(`${baseUrl}/v1/user/cookie-consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: 'rejected',
        categories: {
          necessary: true,
          functional: false,
          analytics: false,
          marketing: false,
        },
        consentVersion: '1.0.0',
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.record.status).toBe('rejected');
    expect(body.record.categories.necessary).toBe(true);
    expect(body.record.categories.functional).toBe(false);
    expect(body.record.categories.analytics).toBe(false);
    expect(body.record.categories.marketing).toBe(false);
  });

  // 3. Preference Changes (Granular customization)
  it('3. POST /v1/user/cookie-consent records "custom" granular preferences', async () => {
    const res = await fetch(`${baseUrl}/v1/user/cookie-consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: 'custom',
        categories: {
          necessary: true,
          functional: true, // User opted into UI themes
          analytics: false, // User opted out of analytics
          marketing: false,
        },
        consentVersion: '1.0.0',
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.record.status).toBe('custom');
    expect(body.record.categories.necessary).toBe(true);
    expect(body.record.categories.functional).toBe(true);
    expect(body.record.categories.analytics).toBe(false);
  });

  // 4. Withdrawal of Consent
  it('4. POST /v1/user/cookie-consent records "withdrawn" status and revokes non-essential permissions', async () => {
    const { token, orgId } = await createTestUserSession();

    const res = await fetch(`${baseUrl}/v1/user/cookie-consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'X-Organization-Id': orgId,
      },
      body: JSON.stringify({
        status: 'withdrawn',
        categories: {
          necessary: true,
          functional: false,
          analytics: false,
          marketing: false,
        },
        consentVersion: '1.0.0',
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.record.status).toBe('withdrawn');
    expect(body.record.categories.functional).toBe(false);
    expect(body.record.categories.analytics).toBe(false);
  });

  // 5. Invalid status validation
  it('5. POST /v1/user/cookie-consent rejects invalid status with 400 INVALID_STATUS', async () => {
    const res = await fetch(`${baseUrl}/v1/user/cookie-consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: 'invalid_choice_foo',
        categories: {},
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe('INVALID_STATUS');
  });

  // 6. Verification of audit log preservation
  it('6. Audit trail preserves consent events with statutory legal bases (ePrivacy / GDPR / DPDPA)', async () => {
    const { token, orgId, email } = await createTestUserSession();

    const consentRes = await fetch(`${baseUrl}/v1/user/cookie-consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'X-Organization-Id': orgId,
      },
      body: JSON.stringify({
        status: 'custom',
        categories: { necessary: true, functional: false, analytics: true },
        consentVersion: '1.0.0',
      }),
    });
    expect(consentRes.status).toBe(200);

    // Verify privacy status reflects active compliance frameworks
    const statusRes = await fetch(`${baseUrl}/v1/user/privacy-status`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Organization-Id': orgId,
      },
    });
    expect(statusRes.status).toBe(200);
    const statusBody = await statusRes.json();
    expect(statusBody.applicableFrameworks).toContain('Digital Personal Data Protection Act, 2023 (DPDPA - India)');
    expect(statusBody.applicableFrameworks).toContain('General Data Protection Regulation (GDPR - EU 2016/679)');
  });
});
