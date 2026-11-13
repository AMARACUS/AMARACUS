/**
 * Phase 8 one-off: seal the platform master key with an Azure Key Vault (or Managed HSM) key,
 * so Render holds only the wrapped value and the API unwraps it at boot.
 *
 * Prerequisites: an RSA (or oct-HSM) key in the vault whose permissions allow wrapKey and
 * unwrapKey for the identity running this script (e.g. `az login`) AND for the Render service's
 * identity (service principal: AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET on Render).
 *
 *   pnpm --filter api exec ts-node --transpile-only scripts/recovery/phase8-seal-master-key.ts \
 *     https://<vault>.vault.azure.net/keys/<key-name>/<version>
 *
 * It reads AMARACUS_LOCAL_MASTER_KEY from the repo's .env, prints the two values to set on
 * Render (AMARACUS_MASTER_KEY_WRAPPED, AMARACUS_MASTER_KEY_KEK_ID), and never prints the
 * master key. Then remove AMARACUS_LOCAL_MASTER_KEY from Render.
 */
import path from 'path';
import dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '..', '..', '..', '..', '.env'), quiet: true } as any);

import { sealPlatformMasterKey } from '@amaracus/crypto-core';

async function main() {
  const keyId = process.argv[2];
  const secret = process.env.AMARACUS_LOCAL_MASTER_KEY;
  if (!keyId) throw new Error('Pass the vault key id, including its version, as the only argument.');
  if (!secret || secret.length < 32) throw new Error('AMARACUS_LOCAL_MASTER_KEY in .env is missing or shorter than 32 characters.');

  const sealed = await sealPlatformMasterKey(secret, keyId);
  console.log('Set these on Render, then remove AMARACUS_LOCAL_MASTER_KEY there:\n');
  console.log(`AMARACUS_MASTER_KEY_KEK_ID=${sealed.keyId}`);
  console.log(`AMARACUS_MASTER_KEY_WRAPPED=${sealed.wrapped}`);
}

main().catch((err) => {
  console.error('phase8 seal: FAILED -', err?.message || err);
  process.exit(1);
});
