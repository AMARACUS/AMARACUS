import { describeCloud, itCloud } from './helpers/edition';
import http from 'http';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

describe('Phase 5.3 — BYOK Cryptographic Capability Discovery & Unified Operations', () => {
  jest.setTimeout(30000);

  let server: http.Server;
  let baseUrl: string;

  let ownerUser: any;
  let enterpriseOrg: any;
  let freeOrg: any;
  let freeUser: any;
  let project: any;
  let env: any;
  let enterpriseSession: any;
  let freeSession: any;

  let provider: any;
  let rsaWrapKey: any;
  let ecSignKey: any;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Enterprise Tenant
    ownerUser = await db.createUser({
      email: `byok_cap_owner_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'BYOK Capability Enterprise Admin',
    });

    enterpriseOrg = await db.createOrganization({
      name: 'Global Financial BYOK Cloud',
      slug: `global-fin-byok-${Date.now()}`,
    });

    await db.addMember({
      organizationId: enterpriseOrg.id,
      userId: ownerUser.id,
      role: 'OWNER',
    });

    project = await db.createProject({
      organizationId: enterpriseOrg.id,
      name: 'Key Vault Banking Service',
      slug: 'kv-banking-svc',
    });

    env = await db.createEnvironment({
      projectId: project.id,
      name: 'Production',
      slug: 'production',
      type: 'production',
    });

    enterpriseSession = await db.createSession({
      userId: ownerUser.id,
      activeOrgId: enterpriseOrg.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Free Tier Tenant (Unentitled)
    freeUser = await db.createUser({
      email: `free_tier_${Date.now()}@amaracus.dev`,
      passwordHash: 'scrypt$dummy_hash',
      name: 'Free Startup Developer',
    });

    freeOrg = await db.createOrganization({
      name: 'Free Dev Org',
      slug: `free-org-${Date.now()}`,
      metadata: JSON.stringify({ plan: 'FREE' }),
    });
    await db.addMember({
      organizationId: freeOrg.id,
      userId: freeUser.id,
      role: 'OWNER',
    });

    freeSession = await db.createSession({
      userId: freeUser.id,
      activeOrgId: freeOrg.id,
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Create Connected Customer Key Provider for Enterprise
    provider = await db.createCustomerProvider({
      organizationId: enterpriseOrg.id,
      projectId: project.id,
      environmentId: env.id,
      name: 'Enterprise Production HSM Vault',
      providerType: 'AZURE_MANAGED_HSM',
      vaultUrl: 'https://enterprise-hsm-eastus.managedhsm.azure.net/',
      status: 'CONNECTED',
      connectionStatus: 'CONNECTED',
      isHsmBacked: true,
      ownershipType: 'CUSTOMER_MANAGED',
    });

    // 1. RSA Wrap/Unwrap Key (supports wrap/unwrap, but NOT sign/verify)
    rsaWrapKey = await db.createCustomerRegisteredKey({
      providerId: provider.id,
      organizationId: enterpriseOrg.id,
      projectId: project.id,
      environmentId: env.id,
      keyIdentifier: 'enterprise-kek-rsa-4096',
      keyVaultUrl: 'https://enterprise-hsm-eastus.managedhsm.azure.net/',
      keyType: 'RSA-HSM',
      algorithm: 'RSA-OAEP-256',
      purpose: 'KEY_WRAPPING',
      ownershipType: 'CUSTOMER_MANAGED',
      isHsmBacked: true,
      hsmBackedStatus: 'VERIFIED_HSM',
      status: 'ACTIVE',
      currentVersion: 'v1_rsa_version',
      operations: ['wrapKey', 'unwrapKey'],
      capabilities: {
        encrypt: true,
        decrypt: true,
        wrap: true,
        unwrap: true,
        sign: false,
        verify: false,
        derive: false,
        rotate: false,
        unavailableReasons: {
          sign: 'This key is an RSA-OAEP encryption key configured exclusively for key wrapping.',
          verify: 'This key is an RSA-OAEP encryption key configured exclusively for key wrapping.',
          rotate: 'Key rotation must be managed directly within your customer Azure HSM portal.',
        },
      },
    });

    // 2. EC Signing Key (supports sign/verify, but NOT encrypt/decrypt/wrap)
    ecSignKey = await db.createCustomerRegisteredKey({
      providerId: provider.id,
      organizationId: enterpriseOrg.id,
      projectId: project.id,
      environmentId: env.id,
      keyIdentifier: 'enterprise-signing-p384',
      keyVaultUrl: 'https://enterprise-hsm-eastus.managedhsm.azure.net/',
      keyType: 'EC-HSM',
      algorithm: 'ES384',
      purpose: 'SIGNING',
      ownershipType: 'CUSTOMER_MANAGED',
      isHsmBacked: true,
      hsmBackedStatus: 'VERIFIED_HSM',
      status: 'ACTIVE',
      currentVersion: 'v1_ec_version',
      operations: ['sign', 'verify'],
      capabilities: {
        encrypt: false,
        decrypt: false,
        wrap: false,
        unwrap: false,
        sign: true,
        verify: true,
        derive: false,
        rotate: false,
        unavailableReasons: {
          encrypt: 'Elliptic curve (EC) keys in Azure Key Vault / Managed HSM cannot be used for symmetric payload encryption.',
          decrypt: 'Elliptic curve (EC) keys in Azure Key Vault / Managed HSM cannot be used for symmetric payload decryption.',
          wrap: 'EC keys do not support direct key wrapping without key agreement protocols.',
        },
      },
    });
  });

  afterAll((done) => {
    server.close(done);
  });

  test('1. Capability Discovery: returns granular capabilities and truthful explanations', async () => {
    const res = await fetch(
      `${baseUrl}/v1/organizations/${enterpriseOrg.id}/byok/providers/${provider.id}/keys/${rsaWrapKey.id}/capabilities`,
      {
        headers: {
          Authorization: `Bearer ${enterpriseSession.sessionToken}`,
        },
      }
    );

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data).toBeDefined();
    expect(json.data.keyIdentifier).toBe('enterprise-kek-rsa-4096');
    expect(json.data.hsmBackedStatus).toBe('VERIFIED_HSM');
    expect(json.data.capabilities.wrap).toBe(true);
    expect(json.data.capabilities.unwrap).toBe(true);
    expect(json.data.capabilities.sign).toBe(false);
    expect(json.data.capabilities.unavailableReasons?.sign).toBeDefined();
    expect(json.data.capabilities.unavailableReasons?.rotate).toBeDefined();
  });

  test('2. Unified Operations: rejects unsupported operation with OPERATION_NOT_SUPPORTED and clear reason', async () => {
    // Attempting to 'sign' with an RSA wrapping key that has sign: false
    const res = await fetch(
      `${baseUrl}/v1/organizations/${enterpriseOrg.id}/byok/providers/${provider.id}/keys/${rsaWrapKey.id}/operations`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${enterpriseSession.sessionToken}`,
        },
        body: JSON.stringify({
          operation: 'sign',
          payload: Buffer.from('important invoice data').toString('base64'),
        }),
      }
    );

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
    expect(json.error.code).toBe('OPERATION_NOT_SUPPORTED');
    expect(json.error.message).toMatch(/not supported/i);
    expect(json.error.reason).toBe(rsaWrapKey.capabilities.unavailableReasons.sign);
  });

  test('3. Unified Operations: rejects payload encryption on EC signing key with OPERATION_NOT_SUPPORTED', async () => {
    // Attempting to 'encrypt' with an EC signing key
    const res = await fetch(
      `${baseUrl}/v1/organizations/${enterpriseOrg.id}/byok/providers/${provider.id}/keys/${ecSignKey.id}/operations`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${enterpriseSession.sessionToken}`,
        },
        body: JSON.stringify({
          operation: 'encrypt',
          plaintext: Buffer.from('confidential medical record').toString('base64'),
        }),
      }
    );

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
    expect(json.error.code).toBe('OPERATION_NOT_SUPPORTED');
    expect(json.error.message).toMatch(/not supported/i);
    expect(json.error.reason).toBe(ecSignKey.capabilities.unavailableReasons.encrypt);
  });

  test('4. Security & Isolation: rejects operation on DISABLED or REVOKED key', async () => {
    // Create a disabled key
    const disabledKey = await db.createCustomerRegisteredKey({
      providerId: provider.id,
      organizationId: enterpriseOrg.id,
      projectId: project.id,
      environmentId: env.id,
      keyIdentifier: 'disabled-backup-key',
      keyVaultUrl: 'https://enterprise-hsm-eastus.managedhsm.azure.net/',
      keyType: 'RSA-HSM',
      algorithm: 'RSA-OAEP-256',
      purpose: 'KEY_WRAPPING',
      ownershipType: 'CUSTOMER_MANAGED',
      status: 'DISABLED',
      currentVersion: 'v1_disabled',
      operations: ['wrapKey', 'unwrapKey'],
    });

    const res = await fetch(
      `${baseUrl}/v1/organizations/${enterpriseOrg.id}/byok/providers/${provider.id}/keys/${disabledKey.id}/operations`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${enterpriseSession.sessionToken}`,
        },
        body: JSON.stringify({
          operation: 'encrypt',
          plaintext: Buffer.from('sensitive test payload').toString('base64'),
        }),
      }
    );

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error.code).toBe('KEY_DISABLED');
    expect(json.error.message).toMatch(/is not active/);
  });

  test('5. Fail-Closed Security: non-existent Azure endpoint fails closed with zero fallback', async () => {
    // When attempting to use an unreachable provider, the system MUST fail closed
    const deadProvider = await db.createCustomerProvider({
      organizationId: enterpriseOrg.id,
      projectId: project.id,
      environmentId: env.id,
      name: 'Unreachable Provider Vault',
      providerType: 'AZURE_KEY_VAULT',
      vaultUrl: 'https://nonexistent-vault-999999.vault.azure.net/',
      status: 'CONNECTED',
      connectionStatus: 'CONNECTED',
      ownershipType: 'CUSTOMER_MANAGED',
    });

    const deadKey = await db.createCustomerRegisteredKey({
      providerId: deadProvider.id,
      organizationId: enterpriseOrg.id,
      projectId: project.id,
      environmentId: env.id,
      keyIdentifier: 'key-on-dead-vault',
      keyVaultUrl: 'https://nonexistent-vault-999999.vault.azure.net/',
      keyType: 'RSA',
      algorithm: 'AES-256-GCM',
      purpose: 'ENCRYPTION',
      ownershipType: 'CUSTOMER_MANAGED',
      status: 'ACTIVE',
      currentVersion: 'v1_dead',
      operations: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
      capabilities: {
        encrypt: true,
        decrypt: true,
        wrap: true,
        unwrap: true,
        sign: false,
        verify: false,
        derive: false,
        rotate: false,
      },
    });

    const res = await fetch(
      `${baseUrl}/v1/organizations/${enterpriseOrg.id}/byok/providers/${deadProvider.id}/keys/${deadKey.id}/operations`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${enterpriseSession.sessionToken}`,
        },
        body: JSON.stringify({
          operation: 'encrypt',
          plaintext: Buffer.from('vital data').toString('base64'),
        }),
      }
    );

    // Must fail closed with 502/500/503 or error code PROVIDER_UNAVAILABLE
    // ZERO silent fallback to local dev or internal keys
    expect(res.status).toBeGreaterThanOrEqual(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
    // This provider has no stored service principal, so it fails before any Azure call (INVALID_INPUT)
    // rather than borrowing the platform identity.
    expect(['PROVIDER_UNAVAILABLE', 'CRYPTO_OPERATION_FAILED', 'RESOURCE_NOT_FOUND', 'INVALID_INPUT']).toContain(json.error.code);
  });

  itCloud('6. Entitlement Protection: Free tier tenants are blocked with ENTITLEMENT_REQUIRED', async () => {
    const res = await fetch(
      `${baseUrl}/v1/organizations/${freeOrg.id}/byok/providers/${provider.id}/keys/${rsaWrapKey.id}/operations`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${freeSession.sessionToken}`,
        },
        body: JSON.stringify({
          operation: 'encrypt',
          plaintext: Buffer.from('test').toString('base64'),
        }),
      }
    );

    expect(res.status).toBe(403);
    const json = await res.json();
    expect(json.error.code).toBe('BYOK_ENTITLEMENT_REQUIRED');
  });
});
