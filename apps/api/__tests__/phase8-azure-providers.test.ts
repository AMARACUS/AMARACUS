import crypto from 'crypto';
import http from 'http';
import { AddressInfo } from 'net';
import {
  AzureKeyVaultKeyProvider,
  AzureManagedHsmProvider,
  CustomerAzureKeyVaultProvider,
  validateAzureVaultUrl,
  tenantScopedKeyName,
  LocalDevKeyProvider,
  loadPlatformMasterKey,
  sealPlatformMasterKey,
  getPlatformMasterSecret,
  resetPlatformMasterKeyForTests,
} from '@amaracus/crypto-core';
import { validateStartupConfig } from '../src/lib/runtime-config';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';

/**
 * An in-memory stand-in for Azure Key Vault / Managed HSM. Wrap and unwrap are real
 * (RSA-OAEP-256 and AES key wrap), so envelopes round-trip; sign/verify record the
 * digest they were given, which is what the double-hash bug got wrong.
 */
function fakeVault(vaultOrigin: string) {
  type Version = { id: string; version: string; keyType: string; crv?: string; rsa?: crypto.KeyPairKeyObjectResult; oct?: Buffer; ec?: crypto.KeyPairKeyObjectResult; enabled: boolean };
  const keys = new Map<string, Version[]>();
  const calls: { op: string; args: any[] }[] = [];
  const signedDigests: Buffer[] = [];
  let counter = 0;

  const toKeyVaultKey = (name: string, v: Version): any => {
    const jwk: any = v.rsa ? v.rsa.publicKey.export({ format: 'jwk' }) : v.ec ? v.ec.publicKey.export({ format: 'jwk' }) : {};
    return {
      id: v.id,
      name,
      keyType: v.keyType,
      key: {
        kty: v.keyType,
        n: jwk.n ? Buffer.from(jwk.n, 'base64url') : undefined,
        e: jwk.e ? Buffer.from(jwk.e, 'base64url') : undefined,
        crv: v.crv,
      },
      properties: { name, version: v.version, enabled: v.enabled },
    };
  };
  const byId = (id: string) => {
    for (const [name, versions] of keys) {
      const v = versions.find((x) => x.id === id);
      if (v) return { name, v };
    }
    throw Object.assign(new Error('KeyNotFound'), { statusCode: 404 });
  };

  const keyClient: any = {
    async createKey(name: string, keyType: string, options: any = {}) {
      calls.push({ op: 'createKey', args: [name, keyType, options] });
      const version = `v${++counter}`;
      const v: Version = { id: `${vaultOrigin}keys/${name}/${version}`, version, keyType, enabled: true };
      if (keyType.startsWith('RSA')) v.rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      else if (keyType.startsWith('oct')) v.oct = crypto.randomBytes(32);
      else if (keyType.startsWith('EC')) {
        v.crv = options.curve || 'P-256';
        v.ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      }
      keys.set(name, [...(keys.get(name) || []), v]);
      return toKeyVaultKey(name, v);
    },
    async getKey(name: string, options: any = {}) {
      const versions = keys.get(name);
      const v = versions && (options.version ? versions.find((x) => x.version === options.version) : versions[versions.length - 1]);
      if (!v) throw Object.assign(new Error('KeyNotFound'), { statusCode: 404 });
      return toKeyVaultKey(name, v);
    },
    async updateKeyProperties(...args: any[]) {
      calls.push({ op: 'updateKeyProperties', args });
      return {};
    },
    listPropertiesOfKeys() {
      const all = [...keys.keys()].map((name) => ({ name, enabled: true }));
      return Object.assign(all[Symbol.iterator](), {
        next: async () => ({ done: true, value: undefined }),
        [Symbol.asyncIterator]() {
          let i = 0;
          return { next: async () => (i < all.length ? { done: false, value: all[i++] } : { done: true, value: undefined }) };
        },
      });
    },
  };

  const cryptoClient = (keyId: string): any => ({
    async wrapKey(alg: string, dek: Uint8Array) {
      calls.push({ op: 'wrapKey', args: [alg] });
      const { v } = byId(keyId);
      if (alg === 'RSA-OAEP-256' && v.rsa) {
        return { result: crypto.publicEncrypt({ key: v.rsa.publicKey, oaepHash: 'sha256' }, Buffer.from(dek)) };
      }
      if (alg === 'A256KW' && v.oct) {
        const c = crypto.createCipheriv('id-aes256-wrap', v.oct, Buffer.alloc(8, 0xa6));
        return { result: Buffer.concat([c.update(Buffer.from(dek)), c.final()]) };
      }
      throw Object.assign(new Error(`Algorithm ${alg} not valid for ${v.keyType}`), { statusCode: 400 });
    },
    async unwrapKey(alg: string, wrapped: Uint8Array) {
      calls.push({ op: 'unwrapKey', args: [alg] });
      const { v } = byId(keyId);
      if (alg === 'RSA-OAEP-256' && v.rsa) {
        return { result: crypto.privateDecrypt({ key: v.rsa.privateKey, oaepHash: 'sha256' }, Buffer.from(wrapped)) };
      }
      if (alg === 'A256KW' && v.oct) {
        const d = crypto.createDecipheriv('id-aes256-wrap', v.oct, Buffer.alloc(8, 0xa6));
        return { result: Buffer.concat([d.update(Buffer.from(wrapped)), d.final()]) };
      }
      throw Object.assign(new Error(`Algorithm ${alg} not valid for ${v.keyType}`), { statusCode: 400 });
    },
    async sign(alg: string, digest: Uint8Array) {
      calls.push({ op: 'sign', args: [alg] });
      signedDigests.push(Buffer.from(digest));
      return { result: crypto.createHmac('sha256', keyId).update(digest).digest() };
    },
    async verify(alg: string, digest: Uint8Array, signature: Uint8Array) {
      calls.push({ op: 'verify', args: [alg] });
      const expected = crypto.createHmac('sha256', keyId).update(digest).digest();
      return { result: expected.equals(Buffer.from(signature)) };
    },
  });

  return {
    calls,
    signedDigests,
    keys,
    factory: { keyClient: () => keyClient, cryptoClient: (id: string) => cryptoClient(id) } as any,
  };
}

const fakeCredential: any = { getToken: async () => ({ token: 'fake', expiresOnTimestamp: Date.now() + 3600_000 }) };
const servicePrincipal = {
  authType: 'SERVICE_PRINCIPAL' as const,
  tenantId: '00000000-0000-0000-0000-000000000000',
  clientId: '00000000-0000-0000-0000-000000000000',
  clientSecret: 'dummy',
};

describe('Phase 8: Azure vault URL and key-name rules', () => {
  it('accepts only Azure vault origins and normalizes them', () => {
    expect(validateAzureVaultUrl('https://Contoso-KV.vault.azure.net')).toEqual({
      origin: 'https://contoso-kv.vault.azure.net/',
      kind: 'KEY_VAULT',
    });
    expect(validateAzureVaultUrl('https://hsm01.managedhsm.azure.net/').kind).toBe('MANAGED_HSM');
    expect(validateAzureVaultUrl('https://gov-vault.vault.usgovcloudapi.net/').kind).toBe('KEY_VAULT');

    for (const bad of [
      'https://evil.example.com/',
      'https://kv.vault.azure.net.evil.com/',
      'https://a.b.vault.azure.net/',
      'http://contoso.vault.azure.net/',
      'https://contoso.vault.azure.net:8443/',
      'https://user:pw@contoso.vault.azure.net/',
      'https://contoso.vault.azure.net/keys/x',
      'https://contoso.vault.azure.net/?x=1',
      'https://this-name-is-far-too-long-for-azure.vault.azure.net/',
      'not a url',
    ]) {
      expect(() => validateAzureVaultUrl(bad)).toThrow(/Azure vault endpoint|not a valid URL/);
    }
    expect(() => validateAzureVaultUrl('https://hsm01.managedhsm.azure.net/', 'KEY_VAULT')).toThrow();
  });

  it('scopes platform key names by tenant and keeps them within Azure limits', () => {
    const a = tenantScopedKeyName('org_A', 'payments key');
    const b = tenantScopedKeyName('org_B', 'payments key');
    expect(a).toMatch(/^am-org-a-payments-key-[0-9a-f]{8}$/);
    expect(b.startsWith('am-org-b-')).toBe(true);
    expect(tenantScopedKeyName('org_A', 'payments key')).not.toBe(a);
    const long = tenantScopedKeyName('o'.repeat(300), 'n'.repeat(300));
    expect(long.length).toBeLessThanOrEqual(127);
    expect(long).toMatch(/^[0-9a-zA-Z-]+$/);
  });
});

describe('Phase 8: platform Azure Key Vault provider', () => {
  const VAULT = 'https://amaracus-test.vault.azure.net/';
  const saved = process.env.AZURE_KEY_VAULT_URL;
  beforeAll(() => {
    process.env.AZURE_KEY_VAULT_URL = VAULT;
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.AZURE_KEY_VAULT_URL;
    else process.env.AZURE_KEY_VAULT_URL = saved;
  });

  const createParams = (organizationId: string, name = 'payments') => ({
    name,
    algorithm: 'AES-256-GCM' as const,
    purpose: 'ENCRYPTION' as const,
    organizationId,
    projectId: 'prj_1',
    environmentId: 'env_1',
  });

  it('creates an RSA-3072 wrap-only key under a tenant-scoped name', async () => {
    const vault = fakeVault(VAULT);
    const provider = new AzureKeyVaultKeyProvider(vault.factory, fakeCredential);
    const result = await provider.createKey(createParams('org_A'));
    const [name, keyType, options] = vault.calls.find((c) => c.op === 'createKey')!.args;
    expect(name).toMatch(/^am-org-a-payments-/);
    expect(keyType).toBe('RSA');
    expect(options.keySize).toBe(3072);
    expect(options.keyOps).toEqual(['wrapKey', 'unwrapKey']);
    expect(options.tags.organizationId).toBe('org_A');
    expect(result.providerKeyId.startsWith(`${VAULT}keys/${name}/`)).toBe(true);

    const other = await provider.createKey(createParams('org_B'));
    expect(other.metadata!.azureKeyName).not.toBe(name);
  });

  it('round-trips an envelope with AAD and rejects tampering', async () => {
    const vault = fakeVault(VAULT);
    const provider = new AzureKeyVaultKeyProvider(vault.factory, fakeCredential);
    const { providerKeyId } = await provider.createKey(createParams('org_A'));
    const data = crypto.randomBytes(100);
    const aad = Buffer.from('tenant=org_A');

    const envelope = await provider.encrypt(providerKeyId, data, aad);
    expect(envelope.wrapAlg).toBe('RSA-OAEP-256');
    expect((await provider.decrypt(providerKeyId, envelope)).equals(data)).toBe(true);

    await expect(
      provider.decrypt(providerKeyId, { ...envelope, aad: Buffer.from('tenant=org_B').toString('base64url') })
    ).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED' });
  });

  it('refuses an envelope that names a different wrap algorithm, before calling Azure', async () => {
    const vault = fakeVault(VAULT);
    const provider = new AzureKeyVaultKeyProvider(vault.factory, fakeCredential);
    const { providerKeyId } = await provider.createKey(createParams('org_A'));
    const envelope = await provider.encrypt(providerKeyId, Buffer.from('x'));
    const unwrapsBefore = vault.calls.filter((c) => c.op === 'unwrapKey').length;

    for (const wrapAlg of ['RSA1_5', 'RSA-OAEP', 'A256KW']) {
      await expect(provider.decrypt(providerKeyId, { ...envelope, wrapAlg })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    }
    expect(vault.calls.filter((c) => c.op === 'unwrapKey').length).toBe(unwrapsBefore);
  });

  it('does not offer signing or other algorithms with Azure-held keys', async () => {
    const provider = new AzureKeyVaultKeyProvider(fakeVault(VAULT).factory, fakeCredential);
    await expect(
      provider.createKey({ ...createParams('org_A'), algorithm: 'ED25519', purpose: 'SIGNING' })
    ).rejects.toMatchObject({ code: 'OPERATION_NOT_SUPPORTED' });
    await expect(
      provider.createKey({ ...createParams('org_A'), algorithm: 'HMAC-SHA-256' as any })
    ).rejects.toMatchObject({ code: 'OPERATION_NOT_SUPPORTED' });
  });

  it('refuses stored key ids that point at another vault', async () => {
    const provider = new AzureKeyVaultKeyProvider(fakeVault(VAULT).factory, fakeCredential);
    await expect(
      provider.encrypt('https://someone-else.vault.azure.net/keys/k/v1', Buffer.from('x'))
    ).rejects.toMatchObject({ code: 'INVALID_KEY' });
  });

  it('rotates by adding a version to the same Azure key, and disables by name and version', async () => {
    const vault = fakeVault(VAULT);
    const provider = new AzureKeyVaultKeyProvider(vault.factory, fakeCredential);
    const created = await provider.createKey(createParams('org_A'));
    const azureName = created.metadata!.azureKeyName;

    const rotated = await provider.rotateKey({
      key: {} as any,
      currentActiveVersion: { providerKeyId: created.providerKeyId } as any,
    });
    expect(rotated.providerKeyId).toBe(`${VAULT}keys/${azureName}/v2`);
    expect(vault.keys.get(azureName)!.length).toBe(2);

    await provider.disableKey(rotated.providerKeyId);
    expect(vault.calls.find((c) => c.op === 'updateKeyProperties')!.args).toEqual([azureName, 'v2', { enabled: false }]);
  });

  it('reports an unconfigured or invalid vault URL as a 503, not a client error', async () => {
    const provider = new AzureKeyVaultKeyProvider(fakeVault(VAULT).factory, fakeCredential);
    process.env.AZURE_KEY_VAULT_URL = 'https://evil.example.com/';
    try {
      await expect(provider.createKey(createParams('org_A'))).rejects.toMatchObject({ code: 'PROVIDER_UNCONFIGURED', status: 503 });
    } finally {
      process.env.AZURE_KEY_VAULT_URL = VAULT;
    }
  });
});

describe('Phase 8: platform Azure Managed HSM provider', () => {
  const HSM = 'https://amaracus-hsm.managedhsm.azure.net/';
  const saved = process.env.AZURE_MANAGED_HSM_URL;
  beforeAll(() => {
    process.env.AZURE_MANAGED_HSM_URL = HSM;
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.AZURE_MANAGED_HSM_URL;
    else process.env.AZURE_MANAGED_HSM_URL = saved;
  });

  it('wraps data keys with A256KW under an oct-HSM key', async () => {
    const vault = fakeVault(HSM);
    const provider = new AzureManagedHsmProvider(vault.factory, fakeCredential);
    const { providerKeyId } = await provider.createKey({
      name: 'records',
      algorithm: 'AES-256-GCM',
      purpose: 'KEY_WRAPPING',
      organizationId: 'org_A',
      projectId: 'p',
      environmentId: 'e',
    });
    expect(vault.calls.find((c) => c.op === 'createKey')!.args.slice(1, 2)).toEqual(['oct-HSM']);

    const data = Buffer.from('medical record');
    const envelope = await provider.encrypt(providerKeyId, data);
    expect(envelope.wrapAlg).toBe('A256KW');
    expect((await provider.decrypt(providerKeyId, envelope)).toString()).toBe('medical record');
    await expect(provider.decrypt(providerKeyId, { ...envelope, wrapAlg: 'RSA-OAEP-256' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });
});

describe('Phase 8: customer (BYOK) Azure provider', () => {
  const VAULT = 'https://contoso-kv.vault.azure.net/';
  const config = (overrides: Record<string, any> = {}) => ({
    name: 'Contoso',
    providerType: 'AZURE_KEY_VAULT' as const,
    ownershipType: 'CUSTOMER_MANAGED' as const,
    vaultUrl: VAULT,
    ...servicePrincipal,
    ...overrides,
  });

  it('refuses non-Azure hosts before building any client or credential', () => {
    const vault = fakeVault(VAULT);
    const keyClientSpy = jest.fn(vault.factory.keyClient);
    for (const vaultUrl of ['https://attacker.example/', 'https://contoso.vault.azure.net.attacker.example/']) {
      expect(() => new CustomerAzureKeyVaultProvider(config({ vaultUrl }), { ...vault.factory, keyClient: keyClientSpy })).toThrow(
        /Azure vault endpoint/
      );
    }
    expect(keyClientSpy).not.toHaveBeenCalled();
  });

  it("requires the customer's own service principal and never falls back to the platform identity", () => {
    const factory = fakeVault(VAULT).factory;
    for (const auth of [
      { authType: 'MANAGED_IDENTITY' },
      { authType: 'WORKLOAD_IDENTITY' },
      { authType: 'ENVIRONMENT' },
      { clientSecret: undefined },
      { tenantId: '' },
      { clientId: '   ' },
    ]) {
      expect(() => new CustomerAzureKeyVaultProvider(config(auth) as any, factory)).toThrow(/service principal|SERVICE_PRINCIPAL/);
    }
  });

  it('signs and verifies EC keys with ES256 over a single SHA-256 digest', async () => {
    const vault = fakeVault(VAULT);
    await vault.factory.keyClient().createKey('signer', 'EC', { curve: 'P-256' });
    const provider = new CustomerAzureKeyVaultProvider(config(), vault.factory);
    const data = Buffer.from('invoice #42');

    const signature = await provider.sign('signer', data);
    expect(vault.calls.find((c) => c.op === 'sign')!.args[0]).toBe('ES256');
    expect(vault.signedDigests[0].equals(crypto.createHash('sha256').update(data).digest())).toBe(true);
    expect(await provider.verify('signer', data, signature)).toBe(true);
    expect(await provider.verify('signer', Buffer.from('invoice #43'), signature)).toBe(false);
  });

  it('wraps with the algorithm the customer key type allows, and checks it on unwrap', async () => {
    const vault = fakeVault(VAULT);
    await vault.factory.keyClient().createKey('kek', 'RSA-HSM');
    const provider = new CustomerAzureKeyVaultProvider(config(), vault.factory);
    const envelope = await provider.encrypt('kek', Buffer.from('payroll'), Buffer.from('ctx'));
    expect(envelope.wrapAlg).toBe('RSA-OAEP-256');
    expect((await provider.decrypt('kek', envelope)).toString()).toBe('payroll');

    // Envelopes from before wrapAlg was recorded were always RSA-OAEP-256.
    const { wrapAlg: _omit, ...legacy } = envelope;
    expect((await provider.decrypt('kek', legacy as any)).toString()).toBe('payroll');
    await expect(provider.decrypt('kek', { ...envelope, wrapAlg: 'RSA1_5' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('Phase 8: BYOK routes take only customer credentials', () => {
  jest.setTimeout(30000);
  let server: http.Server;
  let baseUrl: string;
  let org: any;
  let project: any;
  let env: any;
  let session: any;
  const saved = {
    AZURE_TENANT_ID: process.env.AZURE_TENANT_ID,
    AZURE_CLIENT_ID: process.env.AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET: process.env.AZURE_CLIENT_SECRET,
  };

  beforeAll(async () => {
    // Platform credentials present, as on a host with Azure configured: they must not be used.
    process.env.AZURE_TENANT_ID = 'platform-tenant';
    process.env.AZURE_CLIENT_ID = 'platform-client';
    process.env.AZURE_CLIENT_SECRET = 'platform-secret';
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
    const user = await db.createUser({ email: `phase8_${Date.now()}@amaracus.dev`, passwordHash: 'x', name: 'P8' });
    org = await db.createOrganization({ name: 'Phase 8 Org', slug: `phase8-${Date.now()}` });
    await db.addMember({ organizationId: org.id, userId: user.id, role: 'OWNER' });
    project = await db.createProject({ organizationId: org.id, name: 'P8', slug: 'p8' });
    env = await db.createEnvironment({ projectId: project.id, name: 'Prod', slug: 'prod', type: 'production' });
    session = await db.createSession({ userId: user.id, activeOrgId: org.id, expiresAt: new Date(Date.now() + 86400000) });
  });

  afterAll((done) => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    server.close(done);
  });

  const post = (path: string, body: any) =>
    fetch(`${baseUrl}/v1/organizations/${org.id}/byok${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.sessionToken}` },
      body: JSON.stringify(body),
    });

  it('rejects a connection test without the customer service principal (no platform fallback)', async () => {
    const res = await post('/providers/test', { vaultUrl: 'https://contoso-kv.vault.azure.net/' });
    expect(res.status).toBe(400);
    expect((await res.json()).error.message).toMatch(/service principal/i);
  });

  it('rejects non-Azure endpoints before contacting them', async () => {
    const res = await post('/providers/test', { vaultUrl: 'https://169.254.169.254/', ...servicePrincipal });
    expect(res.status).toBe(400);
    expect((await res.json()).error.message).toMatch(/Azure vault endpoint/);
  });

  it('refuses to save a provider without credentials, and stores a normalized vault origin', async () => {
    const missing = await post('/providers', {
      name: 'No creds',
      projectId: project.id,
      environmentId: env.id,
      vaultUrl: 'https://contoso-kv.vault.azure.net/',
    });
    expect(missing.status).toBe(400);

    const created = await post('/providers', {
      name: 'Contoso',
      projectId: project.id,
      environmentId: env.id,
      vaultUrl: 'https://Contoso-KV.vault.azure.net',
      ...servicePrincipal,
    });
    expect(created.status).toBe(201);
    const body = await created.json();
    const record = await db.findCustomerProviderById(body.data?.id || body.id);
    expect(record!.vaultUrl).toBe('https://contoso-kv.vault.azure.net/');
    expect(record!.encryptedAuthConfig).toMatch(/^v1:/);
  });
});

describe('Phase 8: platform master key sealed by Azure Key Vault', () => {
  const VAULT = 'https://amaracus-test.vault.azure.net/';
  const NAMES = [
    'AMARACUS_LOCAL_MASTER_KEY',
    'AMARACUS_MASTER_KEY_WRAPPED',
    'AMARACUS_MASTER_KEY_KEK_ID',
    'API_SECRET',
    'UNSUBSCRIBE_SECRET',
    'DATABASE_URL',
  ];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = Object.fromEntries(NAMES.map((n) => [n, process.env[n]]));
    for (const n of NAMES) delete process.env[n];
    resetPlatformMasterKeyForTests();
  });
  afterEach(() => {
    for (const n of NAMES) {
      if (saved[n] === undefined) delete process.env[n];
      else process.env[n] = saved[n];
    }
    resetPlatformMasterKeyForTests();
  });

  it('keeps keys wrapped under the plain secret readable after the secret is sealed', async () => {
    const secret = 's'.repeat(48);
    const provider = new LocalDevKeyProvider();
    const params = {
      name: 'k',
      algorithm: 'AES-256-GCM' as const,
      purpose: 'ENCRYPTION' as const,
      organizationId: 'org_A',
      projectId: 'p',
      environmentId: 'e',
    };

    process.env.AMARACUS_LOCAL_MASTER_KEY = secret;
    const created = await provider.createKey(params);
    const version: any = { providerKeyId: created.providerKeyId, encryptedKeyMaterial: created.encryptedKeyMaterial };
    const envelope = await provider.encrypt(created.providerKeyId, Buffer.from('before sealing'), undefined, version);

    const vault = fakeVault(VAULT);
    const kek = await vault.factory.keyClient().createKey('master-kek', 'RSA');
    const sealed = await sealPlatformMasterKey(secret, kek.id, { clients: vault.factory, credential: fakeCredential });

    delete process.env.AMARACUS_LOCAL_MASTER_KEY;
    process.env.AMARACUS_MASTER_KEY_WRAPPED = sealed.wrapped;
    process.env.AMARACUS_MASTER_KEY_KEK_ID = sealed.keyId;
    expect(getPlatformMasterSecret()).toBeUndefined();

    expect(await loadPlatformMasterKey({ clients: vault.factory, credential: fakeCredential })).toBe('sealed');
    expect((await provider.decrypt(created.providerKeyId, envelope, version)).toString()).toBe('before sealing');
  });

  it('refuses an incomplete or mixed configuration', async () => {
    process.env.AMARACUS_MASTER_KEY_WRAPPED = 'abc';
    await expect(loadPlatformMasterKey()).rejects.toThrow(/both/);

    process.env.AMARACUS_MASTER_KEY_KEK_ID = `${VAULT}keys/master-kek/v1`;
    process.env.AMARACUS_LOCAL_MASTER_KEY = 'm'.repeat(40);
    await expect(loadPlatformMasterKey()).rejects.toThrow(/Remove the plain variable/);

    process.env.API_SECRET = 'x'.repeat(40);
    process.env.UNSUBSCRIBE_SECRET = 'y'.repeat(40);
    process.env.DATABASE_URL = 'postgresql://localhost:5432/t';
    process.env.APP_URL = 'https://kms.example.com';
    expect(validateStartupConfig()).toEqual([expect.stringMatching(/AMARACUS_LOCAL_MASTER_KEY must not be set when the current master key is sealed/)]);
    delete process.env.AMARACUS_LOCAL_MASTER_KEY;
    expect(validateStartupConfig()).toEqual([]);
  });

  it('refuses a key id outside Azure or without a version', async () => {
    process.env.AMARACUS_MASTER_KEY_WRAPPED = 'abc';
    process.env.AMARACUS_MASTER_KEY_KEK_ID = `${VAULT}keys/master-kek`;
    await expect(loadPlatformMasterKey({ clients: fakeVault(VAULT).factory, credential: fakeCredential })).rejects.toThrow(/version/);
    process.env.AMARACUS_MASTER_KEY_KEK_ID = 'https://evil.example.com/keys/master-kek/v1';
    await expect(loadPlatformMasterKey({ clients: fakeVault(VAULT).factory, credential: fakeCredential })).rejects.toThrow();
  });
});
