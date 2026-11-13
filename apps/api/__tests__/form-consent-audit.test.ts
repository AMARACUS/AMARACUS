import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { hashPassword } from '../src/lib/crypto-security';

describe('Form Audit, Consent Separation & Statutory Compliance Integration Tests', () => {
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

  async function createTestUserSession(emailPrefix = 'user') {
    const userId = `usr_form_${crypto.randomUUID().slice(0, 8)}`;
    const orgId = `org_form_${crypto.randomUUID().slice(0, 8)}`;
    const email = `${emailPrefix}_${crypto.randomUUID().slice(0, 8)}@amaracus.tech`;
    const password = 'SecurePassword123!';
    const passwordHash = await hashPassword(password);

    await db.createOrganization({
      id: orgId,
      name: 'Form Audit Org',
      slug: `form-org-${crypto.randomUUID().slice(0, 6)}`,
    });

    const user = await db.createUser({
      id: userId,
      email,
      name: 'Form Audit Specialist',
      passwordHash,
    });

    await db.addMember({
      organizationId: orgId,
      userId: user.id,
      role: 'OWNER',
    });

    const token = `sess_form_${crypto.randomUUID()}`;
    await db.createSession({
      sessionToken: token,
      userId: user.id,
      activeOrgId: orgId,
      expiresAt: new Date(Date.now() + 86400000),
    });

    return { userId: user.id, orgId, email, password, token };
  }

  // --- 1. REGISTRATION FORM & CONSENT SEPARATION ---
  it('1. Registration Form: Rejects signup without explicit Terms acceptance (400 TERMS_REQUIRED)', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signup/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `no_terms_${Date.now()}@amaracus.tech`,
        password: 'ValidPassword123!',
        name: 'Unconsenting User',
        organizationName: 'Unconsenting Inc',
        termsAccepted: false,
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe('TERMS_REQUIRED');
  });

  it('2. Registration Form: Server validates required inputs (email format & password length >= 8)', async () => {
    // Test invalid email
    const resBadEmail = await fetch(`${baseUrl}/v1/auth/signup/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'invalid-email-address',
        password: 'ValidPassword123!',
        termsAccepted: true,
      }),
    });
    expect(resBadEmail.status).toBe(400);
    const bodyBadEmail = await resBadEmail.json();
    expect(bodyBadEmail.error.code).toBe('VALIDATION_ERROR');

    // Test short password
    const resShortPass = await fetch(`${baseUrl}/v1/auth/signup/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `short_pass_${Date.now()}@amaracus.tech`,
        password: '123',
        termsAccepted: true,
      }),
    });
    expect(resShortPass.status).toBe(400);
    const bodyShortPass = await resShortPass.json();
    expect(bodyShortPass.error.code).toBe('VALIDATION_ERROR');
  });

  it('3. Registration Form: Accepts terms and records marketingOptIn: true audit event upon verification', async () => {
    const email = `optin_${Date.now()}@amaracus.tech`;
    const sendRes = await fetch(`${baseUrl}/v1/auth/signup/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password: 'StrongPassword123!',
        name: 'OptIn User',
        organizationName: 'OptIn Security Corp',
        termsAccepted: true,
        marketingOptIn: true,
      }),
    });

    expect(sendRes.status).toBe(200);
    const sendData = await sendRes.json();
    expect(sendData.devOtp).toBeDefined();

    // Verify OTP to finalize registration
    const verifyRes = await fetch(`${baseUrl}/v1/auth/signup/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        otp: sendData.devOtp,
      }),
    });

    expect(verifyRes.status).toBe(201);
    const verifyData = await verifyRes.json();
    expect(verifyData.user.email).toBe(email);

    // Verify audit logs record marketing consent granted
    const { events: auditLogs } = await db.listAuditEvents({ actorId: verifyData.user.id });
    const marketingConsentEvent = auditLogs.find(
      (e) => e.action === 'privacy.marketing_consent_granted'
    );
    expect(marketingConsentEvent).toBeDefined();
    expect(marketingConsentEvent?.metadata.category).toBe('MARKETING_UPDATES');
    expect(marketingConsentEvent?.metadata.consentGranted).toBe(true);

    // Verify Terms agreed audit event also logged
    const termsEvent = auditLogs.find(
      (e) => e.action === 'auth.universal_terms_agreed'
    );
    expect(termsEvent).toBeDefined();
  });

  it('4. Registration Form: Optional marketing consent does not gate registration when omitted (unprechecked default)', async () => {
    const email = `optout_${Date.now()}@amaracus.tech`;
    const sendRes = await fetch(`${baseUrl}/v1/auth/signup/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password: 'StrongPassword123!',
        name: 'Unchecked OptOut User',
        organizationName: 'Privacy First Ltd',
        termsAccepted: true,
        marketingOptIn: false,
      }),
    });

    expect(sendRes.status).toBe(200);
    const sendData = await sendRes.json();

    const verifyRes = await fetch(`${baseUrl}/v1/auth/signup/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        otp: sendData.devOtp,
      }),
    });

    expect(verifyRes.status).toBe(201);
    const verifyData = await verifyRes.json();

    // Verify audit logs record consent withheld, NOT granted
    const { events: auditLogs } = await db.listAuditEvents({ actorId: verifyData.user.id });
    const marketingWithheldEvent = auditLogs.find(
      (e) => e.action === 'privacy.marketing_consent_withheld'
    );
    expect(marketingWithheldEvent).toBeDefined();
    expect(marketingWithheldEvent?.metadata.consentGranted).toBe(false);

    // Ensure marketing_consent_granted was NOT created
    const marketingGrantedEvent = auditLogs.find(
      (e) => e.action === 'privacy.marketing_consent_granted'
    );
    expect(marketingGrantedEvent).toBeUndefined();
  });

  // --- 2. OTP VERIFICATION FORM VALIDATION ---
  it('5. OTP Verification Form: Rejects invalid or expired OTP code (400 INVALID_OTP)', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signup/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'nobody@amaracus.tech',
        otp: '000000',
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe('INVALID_OTP');
  });

  // --- 3. COMMUNICATION & CONSENT PREFERENCES & WITHDRAWAL ---
  it('6. Account Preferences: GET /v1/user/preferences returns current consent states', async () => {
    const { token } = await createTestUserSession('pref_get');

    const res = await fetch(`${baseUrl}/v1/user/preferences`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.preferences).toBeDefined();
    expect(body.preferences.securityAlertsOnly).toBe(true);
    expect(typeof body.preferences.marketingEmails).toBe('boolean');
  });

  it('7. Account Preferences: PUT /v1/user/preferences records marketing consent withdrawal in audit log', async () => {
    const { token, userId, email } = await createTestUserSession('pref_withdraw');

    // First, grant consent
    await fetch(`${baseUrl}/v1/user/preferences`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ marketingEmails: true }),
    });

    // Now withdraw consent
    const withdrawRes = await fetch(`${baseUrl}/v1/user/preferences`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ marketingEmails: false }),
    });

    expect(withdrawRes.status).toBe(200);
    const withdrawBody = await withdrawRes.json();
    expect(withdrawBody.preferences.marketingEmails).toBe(false);

    // Verify audit log has privacy.marketing_consent_withdrawn
    const { events: auditLogs } = await db.listAuditEvents({ actorId: userId });
    const withdrawEvent = auditLogs.find(
      (e) => e.action === 'privacy.marketing_consent_withdrawn'
    );
    expect(withdrawEvent).toBeDefined();
    expect(withdrawEvent?.metadata.category).toBe('MARKETING_UPDATES');
    expect(withdrawEvent?.metadata.consentGranted).toBe(false);
    expect(withdrawEvent?.metadata.legalBases).toContain('GDPR_ART_7_3');
  });

  it('8. Security Alerts notice: securityAlertsOnly remains non-derogable for essential service delivery', async () => {
    const { token } = await createTestUserSession('pref_security');

    // Attempt to set securityAlertsOnly to false
    const res = await fetch(`${baseUrl}/v1/user/preferences`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ securityAlertsOnly: false }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    // Security alerts cannot be disabled while account is active
    expect(body.preferences.securityAlertsOnly).toBe(true);
  });
});
