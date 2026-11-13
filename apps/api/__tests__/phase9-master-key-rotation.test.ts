import {
  LocalDevKeyProvider,
  loadPlatformMasterKey,
  resetPlatformMasterKeyForTests,
  deriveMasterKek,
  masterKekId,
} from '@amaracus/crypto-core';
import { validateStartupConfig } from '../src/lib/runtime-config';

const OLD = 'old-master-secret-'.padEnd(48, 'a');
const NEW = 'new-master-secret-'.padEnd(48, 'b');
const ENV = [
  'AMARACUS_LOCAL_MASTER_KEY',
  'AMARACUS_MASTER_KEY_WRAPPED',
  'AMARACUS_MASTER_KEY_KEK_ID',
  'AMARACUS_PREVIOUS_MASTER_KEY',
  'AMARACUS_PREVIOUS_MASTER_KEY_WRAPPED',
  'AMARACUS_PREVIOUS_MASTER_KEY_KEK_ID',
  'API_SECRET',
  'UNSUBSCRIBE_SECRET',
  'DATABASE_URL',
];

describe('Phase 9: platform master key rotation', () => {
  let saved: Record<string, string | undefined>;
  const provider = new LocalDevKeyProvider();
  const params = {
    name: 'k',
    algorithm: 'AES-256-GCM' as const,
    purpose: 'ENCRYPTION' as const,
    organizationId: 'org_A',
    projectId: 'p',
    environmentId: 'e',
  };

  beforeEach(() => {
    saved = Object.fromEntries(ENV.map((n) => [n, process.env[n]]));
    for (const n of ENV) delete process.env[n];
    resetPlatformMasterKeyForTests();
  });
  afterEach(() => {
    for (const n of ENV) {
      if (saved[n] === undefined) delete process.env[n];
      else process.env[n] = saved[n];
    }
    resetPlatformMasterKeyForTests();
  });

  /** A key version and a ciphertext made under whatever master key is current. */
  async function keyWithCiphertext(text: string) {
    const created = await provider.createKey(params);
    const version: any = { providerKeyId: created.providerKeyId, encryptedKeyMaterial: created.encryptedKeyMaterial };
    const envelope = await provider.encrypt(created.providerKeyId, Buffer.from(text), undefined, version);
    return { created, version, envelope };
  }
  const decrypt = async (k: { created: any; envelope: any }, version: any) =>
    (await provider.decrypt(k.created.providerKeyId, k.envelope, version)).toString();

  it('records which master key wrapped each blob', async () => {
    process.env.AMARACUS_LOCAL_MASTER_KEY = OLD;
    const { version } = await keyWithCiphertext('x');
    expect(JSON.parse(version.encryptedKeyMaterial).kid).toBe(masterKekId(deriveMasterKek(OLD)));
  });

  it('rotates: old keys keep working, the rewrap moves them, and the old key can then go', async () => {
    process.env.AMARACUS_LOCAL_MASTER_KEY = OLD;
    const before = await keyWithCiphertext('made under the old key');

    // Step 2: new current key, old one as previous.
    process.env.AMARACUS_LOCAL_MASTER_KEY = NEW;
    process.env.AMARACUS_PREVIOUS_MASTER_KEY = OLD;
    expect(await loadPlatformMasterKey()).toBe('plain');
    expect(await decrypt(before, before.version)).toBe('made under the old key');
    const during = await keyWithCiphertext('made during the rotation');
    expect(JSON.parse(during.version.encryptedKeyMaterial).kid).toBe(masterKekId(deriveMasterKek(NEW)));

    // Step 3: rewrap. Idempotent: a second pass changes nothing.
    const first = provider.rewrapKeyMaterial(before.version.encryptedKeyMaterial);
    expect(first.changed).toBe(true);
    expect(provider.rewrapKeyMaterial(first.blob).changed).toBe(false);
    expect(provider.rewrapKeyMaterial(during.version.encryptedKeyMaterial).changed).toBe(false);

    // Step 4: previous key removed. Rewrapped versions work; an un-rewrapped one names the problem.
    delete process.env.AMARACUS_PREVIOUS_MASTER_KEY;
    expect(await decrypt(before, { ...before.version, encryptedKeyMaterial: first.blob })).toBe('made under the old key');
    await expect(decrypt(before, before.version)).rejects.toThrow(/not configured/);
  });

  it('still reads blobs from before kid existed, under the current or the previous key', async () => {
    process.env.AMARACUS_LOCAL_MASTER_KEY = OLD;
    const k = await keyWithCiphertext('legacy');
    const { kid: _kid, ...legacy } = JSON.parse(k.version.encryptedKeyMaterial);
    const legacyVersion = { ...k.version, encryptedKeyMaterial: JSON.stringify(legacy) };
    expect(await decrypt(k, legacyVersion)).toBe('legacy');

    process.env.AMARACUS_LOCAL_MASTER_KEY = NEW;
    process.env.AMARACUS_PREVIOUS_MASTER_KEY = OLD;
    expect(await decrypt(k, legacyVersion)).toBe('legacy');
    expect(provider.rewrapKeyMaterial(legacyVersion.encryptedKeyMaterial).changed).toBe(true);
  });

  it('refuses to start a rotation where the previous key equals the current one', async () => {
    process.env.AMARACUS_LOCAL_MASTER_KEY = OLD;
    process.env.AMARACUS_PREVIOUS_MASTER_KEY = OLD;
    await expect(loadPlatformMasterKey()).rejects.toThrow(/same as the current/);
  });

  it('checks the previous-key settings at startup', () => {
    process.env.API_SECRET = 'x'.repeat(40);
    process.env.UNSUBSCRIBE_SECRET = 'y'.repeat(40);
    // A self-hosted build also needs its own public URL (the public tree is always self-hosted).
    process.env.APP_URL = 'https://kms.example.com';
    process.env.DATABASE_URL = 'postgresql://localhost:5432/t';
    process.env.AMARACUS_LOCAL_MASTER_KEY = NEW;
    expect(validateStartupConfig()).toEqual([]);

    process.env.AMARACUS_PREVIOUS_MASTER_KEY = OLD;
    expect(validateStartupConfig()).toEqual([]);

    process.env.AMARACUS_PREVIOUS_MASTER_KEY = 'short';
    expect(validateStartupConfig()).toEqual([expect.stringMatching(/AMARACUS_PREVIOUS_MASTER_KEY must be at least/)]);

    delete process.env.AMARACUS_PREVIOUS_MASTER_KEY;
    process.env.AMARACUS_PREVIOUS_MASTER_KEY_WRAPPED = 'abc';
    expect(validateStartupConfig()).toEqual([
      expect.stringMatching(/AMARACUS_PREVIOUS_MASTER_KEY_WRAPPED and AMARACUS_PREVIOUS_MASTER_KEY_KEK_ID must both be set/),
    ]);
  });
});
