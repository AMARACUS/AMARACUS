import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';

describe('Multi-Tenancy, IDOR Protection & RBAC', () => {
  jest.setTimeout(30000);
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

  let tokenA: string;
  let orgAId: string;
  let projectAId: string;
  let envAId: string;

  let tokenB: string;
  let orgBId: string;
  let projectBId: string;

  it('Setup: creates Tenant A and Tenant B', async () => {
    // Tenant A
    const resA = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `tenant_a_${Date.now()}@alpha.dev`,
        password: 'Password1234!',
        name: 'Alice Alpha',
        organizationName: 'Alpha Corp',
      }),
    });
    const dataA = await resA.json();
    tokenA = dataA.session.token;
    orgAId = dataA.activeOrganization.id;

    // Tenant B
    const resB = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `tenant_b_${Date.now()}@beta.dev`,
        password: 'Password1234!',
        name: 'Bob Beta',
        organizationName: 'Beta Corp',
      }),
    });
    const dataB = await resB.json();
    tokenB = dataB.session.token;
    orgBId = dataB.activeOrganization.id;

    expect(orgAId).not.toBe(orgBId);
  });

  it('Tenant A creates Project in Org A', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgAId}/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`,
      },
      body: JSON.stringify({
        name: 'Alpha Enclave',
        slug: 'alpha-enclave',
        description: 'High security cryptographic isolation enclave',
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    projectAId = data.project.id;
    envAId = data.project.environments[0].id;
    expect(projectAId).toBeDefined();
    expect(envAId).toBeDefined();
  });

  it('Tenant B creates Project in Org B', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgBId}/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenB}`,
      },
      body: JSON.stringify({
        name: 'Beta KMS',
        slug: 'beta-kms',
        description: 'Key Management Service',
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    projectBId = data.project.id;
  });

  it('Security: Tenant B CANNOT list projects from Org A (403 Forbidden)', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgAId}/projects`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error.code).toBe('FORBIDDEN');
  });

  it('Security: Tenant B CANNOT access Project A via IDOR (403 Forbidden)', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgAId}/projects/${projectAId}`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });

    expect(res.status).toBe(403);
  });

  it('Security: Tenant B CANNOT access Project A by forging orgId parameter (404 Not Found)', async () => {
    // Bob sends his own orgId in URL path, but puts Project A's ID
    const res = await fetch(`${baseUrl}/v1/organizations/${orgBId}/projects/${projectAId}`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });

    expect(res.status).toBe(404);
  });

  it('Security: Tenant B CANNOT delete Project A', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgAId}/projects/${projectAId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenB}` },
    });

    expect(res.status).toBe(403);
  });

  it('Credentials & One-Time Reveal: Tenant A creates an API key in Org A', async () => {
    const res = await fetch(`${baseUrl}/v1/organizations/${orgAId}/credentials`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`,
      },
      body: JSON.stringify({
        name: 'HSM Connector Key',
        environmentId: envAId,
        envType: 'prod',
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.rawKey).toBeDefined();
    expect(data.rawKey.startsWith('amk_prod_')).toBe(true);
    expect(data.credential.prefix).toBeDefined();

    const credId = data.credential.id;

    // Tenant B cannot see this key
    const listB = await fetch(`${baseUrl}/v1/organizations/${orgBId}/credentials`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    const dataListB = await listB.json();
    expect(dataListB.credentials.some((c: any) => c.id === credId)).toBe(false);
  });

  it('RBAC: MEMBER role can read projects but cannot delete projects', async () => {
    const memberEmail = `member_charlie_${Date.now()}@alpha.dev`;
    const memberPassword = 'CharliePassword123!';

    // Alice (OWNER) invites Charlie as MEMBER
    const inviteRes = await fetch(`${baseUrl}/v1/organizations/${orgAId}/members`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`,
      },
      body: JSON.stringify({
        email: memberEmail,
        role: 'MEMBER',
      }),
    });
    expect(inviteRes.status).toBe(201);

    // Charlie signs up with that email and joins
    const signupCharlie = await fetch(`${baseUrl}/v1/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `charlie_alt_${Date.now()}@alpha.dev`,
        password: memberPassword,
        name: 'Charlie Member',
      }),
    });
    // In our test, we directly test with a MEMBER session in Org A:
    // Let's create member session:
    const dataCharlie = await signupCharlie.json();
    const tokenCharlie = dataCharlie.session.token;

    // Alice adds Charlie to Org A as MEMBER
    await fetch(`${baseUrl}/v1/organizations/${orgAId}/members`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`,
      },
      body: JSON.stringify({
        email: dataCharlie.user.email,
        role: 'MEMBER',
      }),
    });

    // Charlie switches to Org A
    const switchRes = await fetch(`${baseUrl}/v1/organizations/${orgAId}/switch`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenCharlie}` },
    });
    expect(switchRes.status).toBe(200);

    // Charlie can list projects in Org A
    const listRes = await fetch(`${baseUrl}/v1/organizations/${orgAId}/projects`, {
      headers: { Authorization: `Bearer ${tokenCharlie}` },
    });
    expect(listRes.status).toBe(200);

    // Charlie CANNOT delete project in Org A (403 Forbidden)
    const deleteRes = await fetch(`${baseUrl}/v1/organizations/${orgAId}/projects/${projectAId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenCharlie}` },
    });
    expect(deleteRes.status).toBe(403);
    const deleteData = await deleteRes.json();
    expect(deleteData.error.message).toContain('Insufficient permissions');
  });
});
