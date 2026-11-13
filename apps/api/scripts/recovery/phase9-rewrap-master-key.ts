/**
 * Phase 9: re-wrap every managed key version under the current platform master key.
 *
 * Rotation, in order:
 *   1. Generate a new master secret (32+ random characters) and keep the old one safe.
 *   2. Set the new secret as the current master key (AMARACUS_LOCAL_MASTER_KEY, or seal it into
 *      AMARACUS_MASTER_KEY_WRAPPED + AMARACUS_MASTER_KEY_KEK_ID), and the old one as the previous
 *      key (AMARACUS_PREVIOUS_MASTER_KEY, or AMARACUS_PREVIOUS_MASTER_KEY_WRAPPED +
 *      AMARACUS_PREVIOUS_MASTER_KEY_KEK_ID). Redeploy: new keys use the new secret, old ones still work.
 *   3. Run this script with the same variables (dry run first, then --apply).
 *   4. When it reports 0 left to re-wrap, remove the previous-key variables and redeploy.
 *
 *   pnpm --filter api exec ts-node --transpile-only scripts/recovery/phase9-rewrap-master-key.ts
 *   pnpm --filter api exec ts-node --transpile-only scripts/recovery/phase9-rewrap-master-key.ts --apply
 *
 * Prints counts and key-version ids only, never key material. Safe to rerun: versions already
 * under the current key are skipped. Take a Supabase backup before --apply.
 */
import path from 'path';
import dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '..', '..', '..', '..', '.env'), quiet: true } as any);

import { prisma } from '@amaracus/database';
import { LocalDevKeyProvider, loadPlatformMasterKey, isMasterKeyRotationInProgress } from '@amaracus/crypto-core';

const BATCH = 200;

async function main() {
  const apply = process.argv.includes('--apply');
  await loadPlatformMasterKey();
  if (!isMasterKeyRotationInProgress()) {
    console.log('No previous master key is configured; nothing to rotate from. Versions are only checked.');
  }

  const provider = new LocalDevKeyProvider();
  let cursor: string | undefined;
  let checked = 0;
  let rewrapped = 0;
  const failed: string[] = [];

  for (;;) {
    const rows = await prisma.cryptographicKeyVersion.findMany({
      where: { encryptedKeyMaterial: { not: null } },
      select: { id: true, encryptedKeyMaterial: true },
      orderBy: { id: 'asc' },
      take: BATCH,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
    });
    if (rows.length === 0) break;
    cursor = rows[rows.length - 1].id;

    for (const row of rows) {
      checked += 1;
      try {
        const { blob, changed } = provider.rewrapKeyMaterial(row.encryptedKeyMaterial!);
        if (!changed) continue;
        rewrapped += 1;
        if (apply) {
          // Only replace the exact blob that was read, in case the row changed meanwhile.
          await prisma.cryptographicKeyVersion.updateMany({
            where: { id: row.id, encryptedKeyMaterial: row.encryptedKeyMaterial },
            data: { encryptedKeyMaterial: blob },
          });
        }
      } catch {
        failed.push(row.id);
      }
    }
  }

  console.log(`Checked ${checked} key version(s).`);
  console.log(`${rewrapped} ${apply ? 're-wrapped' : 'to re-wrap; rerun with --apply to write'}.`);
  if (failed.length) {
    console.log(`${failed.length} could not be unwrapped with the current or previous master key:`);
    for (const id of failed) console.log(`  ${id}`);
    process.exitCode = 1;
  } else if (apply && rewrapped === 0) {
    console.log('Every version is under the current master key. You can remove the previous-key variables.');
  }
}

main()
  .catch((err) => {
    console.error('phase9 rewrap: FAILED -', err?.message || err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
