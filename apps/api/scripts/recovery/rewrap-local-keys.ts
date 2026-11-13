/**
 * Re-wraps LOCAL_DEV key material from the old master KEK to a new one.
 *
 * Until Phase 1 the LOCAL_DEV provider fell back to a hardcoded master secret
 * that is public in git history. Every wrapped key must move to the new
 * AMARACUS_LOCAL_MASTER_KEY. Blob format matches LocalDevKeyProvider:
 *   {"v":1,"alg":"aes-256-gcm","iv":b64,"tag":b64,"ct":b64}, KEK = SHA-256(secret)
 *
 * Inputs (environment):
 *   LEGACY_AMARACUS_MASTER_KEY  the secret the keys are currently wrapped under
 *   AMARACUS_LOCAL_MASTER_KEY   the new secret (from .env)
 *
 * Dry run by default (unwraps every blob to prove the legacy secret is right);
 * pass --apply to write the re-wrapped blobs to Supabase and the JSON stores.
 *
 *   pnpm --filter api exec ts-node scripts/recovery/rewrap-local-keys.ts [--apply]
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { PrismaClient } from '@amaracus/database';

const repoRoot = path.resolve(__dirname, '..', '..', '..', '..');
const apply = process.argv.includes('--apply');
dotenv.config({ path: path.join(repoRoot, '.env') });

const JSON_STORES = [
  path.join(repoRoot, '.amaracus-local-store.json'),
  path.join(repoRoot, 'apps', 'api', '.amaracus-local-store.json'),
];

function kek(secret: string): Buffer {
  return crypto.createHash('sha256').update(secret).digest();
}

function unwrap(blob: string, key: Buffer): Buffer {
  const parsed = JSON.parse(blob);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parsed.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(parsed.ct, 'base64')), decipher.final()]);
}

function wrap(raw: Buffer, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(raw), cipher.final()]);
  return JSON.stringify({
    v: 1,
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  });
}

interface Outcome {
  rewrapped: number;
  alreadyNew: number;
  plaintext: string[];
  failed: string[];
}

/** Returns the re-wrapped blob, or null when it is already under the new KEK. */
function rewrap(id: string, blob: string, legacy: Buffer, next: Buffer, out: Outcome): string | null {
  // Early versions stored PEM private keys unwrapped. The provider cannot read
  // them, so they are reported for deletion rather than silently wrapped.
  if (blob.startsWith('-----BEGIN')) {
    out.plaintext.push(id);
    return null;
  }
  try {
    unwrap(blob, next);
    out.alreadyNew++;
    return null;
  } catch {
    // not under the new KEK yet
  }
  try {
    const raw = unwrap(blob, legacy);
    out.rewrapped++;
    return wrap(raw, next);
  } catch {
    out.failed.push(id);
    return null;
  }
}

async function rewrapSupabase(legacy: Buffer, next: Buffer): Promise<void> {
  if (!process.env.DATABASE_URL) {
    console.log('[supabase] DATABASE_URL not set; skipping.');
    return;
  }
  const prisma = new PrismaClient();
  const out: Outcome = { rewrapped: 0, alreadyNew: 0, plaintext: [], failed: [] };
  try {
    const versions = await prisma.cryptographicKeyVersion.findMany({
      where: { encryptedKeyMaterial: { not: null } },
      select: { id: true, encryptedKeyMaterial: true },
    });
    const updates: { id: string; blob: string }[] = [];
    for (const v of versions) {
      const blob = rewrap(v.id, v.encryptedKeyMaterial!, legacy, next, out);
      if (blob) updates.push({ id: v.id, blob });
    }
    console.log(`[supabase] versions=${versions.length} rewrap=${out.rewrapped} alreadyNew=${out.alreadyNew} plaintext=${out.plaintext.length} failed=${out.failed.length}`);
    if (out.plaintext.length) console.log(`[supabase] UNENCRYPTED private keys (delete these): ${out.plaintext.join(', ')}`);
    if (out.failed.length) console.log(`[supabase] could not unwrap: ${out.failed.join(', ')}`);
    if (apply && updates.length) {
      await prisma.$transaction(
        updates.map((u) =>
          prisma.cryptographicKeyVersion.update({ where: { id: u.id }, data: { encryptedKeyMaterial: u.blob } })
        )
      );
      console.log(`[supabase] Wrote ${updates.length} re-wrapped versions.`);
    }
  } finally {
    await prisma.$disconnect();
  }
}

function rewrapJsonStore(file: string, legacy: Buffer, next: Buffer): void {
  if (!fs.existsSync(file)) return;
  const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
  const versions: any[] = Array.isArray(data.keyVersions) ? data.keyVersions : [];
  const out: Outcome = { rewrapped: 0, alreadyNew: 0, plaintext: [], failed: [] };
  for (const v of versions) {
    if (!v.encryptedKeyMaterial) continue;
    const blob = rewrap(v.id, v.encryptedKeyMaterial, legacy, next, out);
    if (blob) v.encryptedKeyMaterial = blob;
  }
  const rel = path.relative(repoRoot, file);
  console.log(`[json] ${rel}: rewrap=${out.rewrapped} alreadyNew=${out.alreadyNew} plaintext=${out.plaintext.length} failed=${out.failed.length}`);
  if (apply && out.rewrapped > 0) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
    console.log(`[json] ${rel}: written.`);
  }
}

async function main(): Promise<void> {
  const legacySecret = process.env.LEGACY_AMARACUS_MASTER_KEY;
  const newSecret = process.env.AMARACUS_LOCAL_MASTER_KEY;
  if (!legacySecret || !newSecret) {
    console.error('Set both LEGACY_AMARACUS_MASTER_KEY and AMARACUS_LOCAL_MASTER_KEY.');
    process.exit(1);
  }
  if (legacySecret === newSecret) {
    console.error('The new master key must differ from the legacy one.');
    process.exit(1);
  }
  console.log(apply ? 'Mode: APPLY' : 'Mode: dry run (pass --apply to write)');
  const legacy = kek(legacySecret);
  const next = kek(newSecret);
  await rewrapSupabase(legacy, next);
  for (const file of JSON_STORES) rewrapJsonStore(file, legacy, next);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
