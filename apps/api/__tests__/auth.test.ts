import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';

describe('Authentication & Session API Endpoints', () => {
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
    server.close(done);
  });

  const testEmail = `auth_test_${Date.now()}@amaracus.dev`;
  const testPassword = 'Password1234!';
  let sessionToken: string;
  let orgId: string;

  it('POST /v1/auth/signup - rejects signup if universal terms are not accepted with 400 TERMS_REQUIRED', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'unagreed_terms@amaracus.dev',
        password: testPassword,
        name: 'Unagreed User',
        organizationName: 'Unagreed Org',
        termsAccepted: false,
      }),
    });

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error.code).toBe('TERMS_REQUIRED');
    expect(data.error.message).toContain('AMARACUS Universal Terms and Conditions');
  });

  it('POST /v1/auth/signup - creates user, org, and establishes session', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
        name: 'Cryptographer Alice',
        organizationName: 'Alice Cipher Labs',
        termsAccepted: true,
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.user).toBeDefined();
    expect(data.user.email).toBe(testEmail);
    expect(data.user.name).toBe('Cryptographer Alice');
    expect(data.session.token).toBeDefined();
    expect(data.activeOrganization).toBeDefined();
    expect(data.activeOrganization.role).toBe('OWNER');

    sessionToken = data.session.token;
    orgId = data.activeOrganization.id;
  });

  it('POST /v1/auth/signup - rejects duplicate email with 409 Conflict', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
        name: 'Duplicate Alice',
        termsAccepted: true,
      }),
    });

    expect(res.status).toBe(409);
    const data = await res.json();
    expect(data.error.code).toBe('CONFLICT');
  });

  it('POST /v1/auth/signup - rejects short password with 400 Validation Error', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'short_pw@amaracus.dev',
        password: 'short',
        termsAccepted: true,
      }),
    });

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error.code).toBe('VALIDATION_ERROR');
  });

  it('POST /v1/auth/signin - successfully authenticates with valid credentials', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
      }),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.user.email).toBe(testEmail);
    expect(data.session.token).toBeDefined();
    expect(data.organizations.length).toBeGreaterThanOrEqual(1);
  });

  it('POST /v1/auth/signin - rejects invalid password with 401', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testEmail,
        password: 'WrongPassword999!',
      }),
    });

    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('GET /v1/auth/me - returns user and active organization context when authenticated', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/me`, {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.user.email).toBe(testEmail);
    expect(data.activeOrganization.id).toBe(orgId);
    expect(data.role).toBe('OWNER');
  });

  it('GET /v1/auth/me - rejects unauthenticated requests with 401', async () => {
    const res = await fetch(`${baseUrl}/v1/auth/me`);
    expect(res.status).toBe(401);
  });

  it('POST /v1/auth/signout - terminates session', async () => {
    const signoutRes = await fetch(`${baseUrl}/v1/auth/signout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
    });
    expect(signoutRes.status).toBe(200);

    const meRes = await fetch(`${baseUrl}/v1/auth/me`, {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
      },
    });
    expect(meRes.status).toBe(401);
  });

  describe('OTP Email Verification Flow', () => {
    const otpEmail = `otp_user_${Date.now()}@amaracus.dev`;
    const otpPassword = 'StrongPassword987!';
    let sentOtp: string;

    it('POST /v1/auth/signup/send-otp - rejects OTP dispatch when universal terms are not accepted', async () => {
      const res = await fetch(`${baseUrl}/v1/auth/signup/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'unagreed_otp@amaracus.dev',
          password: otpPassword,
          name: 'Unagreed OTP User',
          termsAccepted: false,
        }),
      });

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error.code).toBe('TERMS_REQUIRED');
      expect(data.error.message).toContain('AMARACUS Universal Terms and Conditions');
    });

    it('POST /v1/auth/signup/send-otp - dispatches OTP and returns pending status', async () => {
      const res = await fetch(`${baseUrl}/v1/auth/signup/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: otpEmail,
          password: otpPassword,
          name: 'OTP User Bob',
          organizationName: 'Bob Cyber Labs',
          termsAccepted: true,
        }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.email).toBe(otpEmail);
      expect(data.devOtp).toBeDefined();
      expect(data.devOtp.length).toBe(6);

      sentOtp = data.devOtp;
    });

    it('POST /v1/auth/signup/verify-otp - rejects invalid OTP code', async () => {
      const res = await fetch(`${baseUrl}/v1/auth/signup/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: otpEmail,
          otp: '000000',
        }),
      });

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error.code).toBe('INVALID_OTP');
    });

    it('POST /v1/auth/signup/verify-otp - activates account with valid OTP and creates session', async () => {
      const res = await fetch(`${baseUrl}/v1/auth/signup/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: otpEmail,
          otp: sentOtp,
        }),
      });

      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.user).toBeDefined();
      expect(data.user.email).toBe(otpEmail);
      expect(data.user.name).toBe('OTP User Bob');
      expect(data.session.token).toBeDefined();
      expect(data.activeOrganization).toBeDefined();
      expect(data.activeOrganization.role).toBe('OWNER');

      // Verify signin works immediately with credentials
      const signinRes = await fetch(`${baseUrl}/v1/auth/signin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: otpEmail,
          password: otpPassword,
        }),
      });
      expect(signinRes.status).toBe(200);
    });
  });
});
