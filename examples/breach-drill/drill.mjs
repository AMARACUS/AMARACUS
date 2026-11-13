#!/usr/bin/env node
/**
 * AMARACUS breach drill.
 *
 *   cd apps/api && npx tsc && cd ../..      # build the API once
 *   node examples/breach-drill/drill.mjs     # run against a private local copy of the API
 *
 * The demo shop stores 50 made-up customers encrypted with AMARACUS, then three drills
 * play out what an attacker could do:
 *   1. Stolen database   - the attacker copies the shop's database file.
 *   2. Stolen API key    - the attacker also gets an AMARACUS API key.
 *   3. AMARACUS outage   - the API cannot be reached.
 *
 * The shop follows the advice in README.md: separate encrypt-only and decrypt-only keys, each
 * limited to the shop server's IP address. The local API trusts X-Forwarded-For (as production
 * does behind Cloudflare), so the drill can play the shop's server (SHOP_IP) and an attacker's
 * machine (ATTACKER_IP) from one computer.
 *
 * Each check prints PASS (the protection held), FAIL (it did not) or INFO (a fact to know).
 * Results are also written to examples/breach-drill/results/.
 * No real customer data and no production system is used.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { startLocalAmaracus } from './local-amaracus.mjs';
import { AmaracusClient, Shop, NaiveShop, fakeCustomers, aadFor } from './shop.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIELDS = ['name', 'email', 'phone', 'address'];
const SHOP_IP = '203.0.113.10'; // the shop's server
const ATTACKER_IP = '198.51.100.66'; // the attacker's own machine
const results = [];
const record = (drill, status, check, detail) => {
  results.push({ drill, status, check, detail });
  console.log(`[${status}] ${drill} | ${check}${detail ? `\n         ${detail}` : ''}`);
};

/** The scopes the console's API Keys page ticks by default (apps/web/src/app/dashboard/api-keys/page.tsx). */
const CONSOLE_DEFAULT_SCOPES = ['crypto:encrypt', 'crypto:read', 'keys:read'];

async function http(baseUrl, method, urlPath, token, orgId, body, sourceIp) {
  const res = await fetch(`${baseUrl}${urlPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(orgId ? { 'X-Organization-Id': orgId } : {}),
      ...(sourceIp ? { 'X-Forwarded-For': sourceIp } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

/** Creates an API key with chosen scopes (and optional allowed IPs), as the console's API Keys page does. */
async function scopedKey(baseUrl, t, name, scopes, allowedIps) {
  const r = await http(baseUrl, 'POST', '/v1/credentials', t.sessionToken, t.orgId, {
    name,
    environmentId: t.environmentId,
    scopes,
    ...(allowedIps ? { allowedIps } : {}),
  });
  if (r.status !== 201) throw new Error(`create API key: ${r.status} ${JSON.stringify(r.json)}`);
  return { id: r.json.data.credential.id, key: r.json.data.apiKey };
}

const errCode = (r) => `HTTP ${r.status} ${r.json?.error?.code || ''}`.trim();

async function main() {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'amaracus-drill-'));
  const amaracus = await startLocalAmaracus(['shop', 'attacker']);
  const { baseUrl, tenants } = amaracus;
  const shopT = tenants.shop;
  const attackerT = tenants.attacker;
  const alertLevel = Number(process.env.DECRYPT_ALERT_PER_HOUR);
  console.log(`Local AMARACUS on ${baseUrl}; shop server ${SHOP_IP}, attacker ${ATTACKER_IP}\n`);

  // --- Setup: the shop's managed key and API keys -------------------------------------
  const created = await http(baseUrl, 'POST', '/v1/keys', shopT.sessionToken, shopT.orgId, {
    name: 'customer-data',
    algorithm: 'AES-256-GCM',
    purpose: 'ENCRYPTION',
  });
  if (created.status !== 201) throw new Error(`create managed key: ${created.status} ${JSON.stringify(created.json)}`);
  const keyId = created.json.data.id;

  const onShopServer = [SHOP_IP];
  const writerKey = await scopedKey(baseUrl, shopT, 'shop-signup-writer', ['crypto:encrypt'], onShopServer);
  const readerKey = await scopedKey(baseUrl, shopT, 'shop-staff-reader', ['crypto:decrypt'], onShopServer);
  const consoleKey = await scopedKey(baseUrl, shopT, 'made-in-console', CONSOLE_DEFAULT_SCOPES);
  const spareKey = await scopedKey(baseUrl, shopT, 'second-reader', ['crypto:decrypt'], onShopServer);

  const writer = new AmaracusClient({ baseUrl, apiKey: writerKey.key, sourceIp: SHOP_IP });
  const reader = new AmaracusClient({ baseUrl, apiKey: readerKey.key, sourceIp: SHOP_IP });

  const shopDbPath = path.join(workDir, 'shop.db');
  const naiveDbPath = path.join(workDir, 'naive-shop.db');
  const shop = new Shop({ dbPath: shopDbPath, keyId, writer, reader });
  const naive = new NaiveShop({ dbPath: naiveDbPath });

  const customers = fakeCustomers(50);
  const ids = [];
  for (const c of customers) {
    ids.push(await shop.addCustomer(c));
    naive.addCustomer(c);
  }
  const roundTrip = await shop.getCustomer(ids[7]);
  record('Setup', roundTrip?.email === customers[7].email ? 'PASS' : 'FAIL',
    'The shop saves 50 customers encrypted (encrypt-only key) and staff read them back (decrypt-only key), both keys limited to the shop server IP',
    `customer 7 email after decrypt: ${roundTrip?.email}`);
  shop.close();
  naive.close();

  // --- Drill 1: stolen database --------------------------------------------------------
  const D1 = 'Drill 1: stolen database';
  const stolenPath = path.join(workDir, 'stolen-copy.db');
  fs.copyFileSync(shopDbPath, stolenPath);
  const stolenBytes = fs.readFileSync(stolenPath).toString('latin1');
  const naiveBytes = fs.readFileSync(naiveDbPath).toString('latin1');
  const secrets = customers.flatMap((c) => FIELDS.map((f) => c[f]));
  const leaked = secrets.filter((s) => stolenBytes.includes(s));
  const naiveLeaked = secrets.filter((s) => naiveBytes.includes(s));
  record(D1, 'INFO', 'Without AMARACUS (plain-text shop): personal values readable in a stolen copy',
    `${naiveLeaked.length} of ${secrets.length}`);
  record(D1, leaked.length === 0 ? 'PASS' : 'FAIL', 'With AMARACUS: personal values readable in a stolen copy',
    `${leaked.length} of ${secrets.length}`);

  const stolen = new DatabaseSync(stolenPath);
  const rows = stolen.prepare('SELECT * FROM customers').all();
  stolen.close();
  try {
    const decoded = JSON.parse(Buffer.from(rows[0].email, 'base64').toString('utf8'));
    const hasPlain = Object.values(decoded).some((v) => typeof v === 'string' && secrets.includes(v));
    record(D1, hasPlain ? 'FAIL' : 'PASS', 'A decoded envelope holds no personal data',
      `fields: ${Object.keys(decoded).join(', ')}; the AAD inside is "${Buffer.from(decoded.aad || '', 'base64url').toString('utf8')}" (record id and field name, readable but not secret)`);
  } catch {
    record(D1, 'INFO', 'Envelope format', `not base64 JSON; starts ${rows[0].email.slice(0, 40)}`);
  }
  const phoneLens = rows.map((r) => r.phone.length);
  const addrLens = rows.map((r) => r.address.length);
  record(D1, 'INFO', 'Envelope length follows value length',
    `phone envelopes ${Math.min(...phoneLens)}-${Math.max(...phoneLens)} chars, address envelopes ${Math.min(...addrLens)}-${Math.max(...addrLens)} chars: an attacker can tell long values from short ones, but not read them`);

  // --- Drill 2: stolen API key -----------------------------------------------------------
  const D2 = 'Drill 2: stolen API key';
  const decryptWith = (apiKey, envelope, sourceIp, extra = {}) =>
    http(baseUrl, 'POST', '/v1/decrypt', apiKey, null, { key: keyId, envelope, ...extra }, sourceIp);

  // 2a. What a key made in the console with its default boxes ticked can do.
  const consoleEnc = await http(baseUrl, 'POST', '/v1/encrypt', consoleKey.key, null, { key: keyId, data: 'x' }, SHOP_IP);
  const consoleDec = await decryptWith(consoleKey.key, rows[0].email, SHOP_IP);
  record(D2, consoleEnc.status === 200 && consoleDec.status === 403 ? 'PASS' : 'FAIL',
    'A key made in the console with its default boxes ticked can encrypt but not decrypt',
    `encrypt: ${errCode(consoleEnc)}; decrypt: ${errCode(consoleDec)}`);

  // 2b. Least privilege: the sign-up server's key can only encrypt.
  const writerTry = await decryptWith(writerKey.key, rows[1].email, SHOP_IP);
  record(D2, writerTry.status === 403 ? 'PASS' : 'FAIL', 'A key with only crypto:encrypt cannot decrypt', errCode(writerTry));

  // 2c. The attacker's own AMARACUS account cannot use the shop's key or data.
  const attackerKey = await scopedKey(baseUrl, attackerT, 'attacker-own-account', ['crypto:execute']);
  const crossTenant = await decryptWith(attackerKey.key, rows[2].email, ATTACKER_IP);
  record(D2, crossTenant.status !== 200 ? 'PASS' : 'FAIL', "An attacker's own AMARACUS account cannot decrypt the shop's data", errCode(crossTenant));
  const crossTenantNoKey = await http(baseUrl, 'POST', '/v1/decrypt', attackerKey.key, null, { envelope: rows[2].email }, ATTACKER_IP);
  record(D2, crossTenantNoKey.status !== 200 ? 'PASS' : 'FAIL', '... nor by sending the envelope without naming the key', errCode(crossTenantNoKey));

  // 2d. Envelope copied into another customer's row.
  const db = new DatabaseSync(shopDbPath);
  const [a, b] = db.prepare('SELECT id, email FROM customers LIMIT 2').all();
  db.prepare('UPDATE customers SET email = ? WHERE id = ?').run(a.email, b.id);
  db.close();
  const apiWithWrongAad = await decryptWith(spareKey.key, a.email, SHOP_IP, { aad: aadFor(b.id, 'email') });
  record(D2, apiWithWrongAad.status !== 200 ? 'PASS' : 'FAIL',
    "The API refuses an envelope whose AAD differs from the one the caller sends",
    apiWithWrongAad.status === 200
      ? 'accepted: /v1/decrypt ignores the "aad" sent with a string envelope and uses the one inside it'
      : errCode(apiWithWrongAad));
  const swappedShop = new Shop({ dbPath: shopDbPath, keyId, writer, reader: new AmaracusClient({ baseUrl, apiKey: spareKey.key, sourceIp: SHOP_IP }) });
  let swapResult;
  try {
    const got = await swappedShop.getCustomer(b.id);
    swapResult = `accepted: showed another customer's email (${got.email})`;
  } catch (e) {
    swapResult = `refused: ${e.message}`;
  }
  swappedShop.close();
  record(D2, swapResult.startsWith('refused') ? 'PASS' : 'FAIL',
    "The demo shop, which checks the envelope's AAD itself, rejects the copied envelope", swapResult);

  // 2e. Revoking a stolen key stops it.
  const beforeRevoke = await decryptWith(spareKey.key, rows[3].email, SHOP_IP);
  const revoke = await http(baseUrl, 'DELETE', `/v1/credentials/${spareKey.id}`, shopT.sessionToken, shopT.orgId);
  const afterRevoke = await decryptWith(spareKey.key, rows[3].email, SHOP_IP);
  record(D2, beforeRevoke.status === 200 && (afterRevoke.status === 401 || afterRevoke.status === 403) ? 'PASS' : 'FAIL',
    'Revoking a stolen key stops it at once',
    `before: ${errCode(beforeRevoke)}; revoke: HTTP ${revoke.status}; after: ${errCode(afterRevoke)}`);

  // 2f. The database AND the staff decrypt key, copied to the attacker's own machine.
  const readAll = async (sourceIp) => {
    let ok = 0;
    const statuses = {};
    for (const r of rows) {
      for (const field of FIELDS) {
        const res = await decryptWith(readerKey.key, r[field], sourceIp);
        const label = `${res.status}${res.json?.error?.code ? ` ${res.json.error.code}` : ''}`;
        statuses[label] = (statuses[label] || 0) + 1;
        if (res.status === 200) ok++;
      }
    }
    return { ok, statuses };
  };
  const offServer = await readAll(ATTACKER_IP);
  record(D2, offServer.ok === 0 ? 'PASS' : 'FAIL',
    "Attacker with the database AND the staff decrypt key, used from the attacker's machine, reads the customer data",
    `${offServer.ok} of ${rows.length * 4} fields decrypted (statuses ${JSON.stringify(offServer.statuses)}): the key only works from the shop server's IP`);

  // 2g. The same theft by someone ON the shop's server (allowed IP): the auto-lock caps it.
  await new Promise((r) => setTimeout(r, 200)); // earlier decrypts are counted after their responses
  const onServer = await readAll(SHOP_IP);
  record(D2, onServer.ok <= alertLevel ? 'PASS' : 'FAIL',
    "A thief on the shop's own server (allowed IP) is cut off at the decrypt alert level",
    `${onServer.ok} of ${rows.length * 4} fields decrypted before the key locked itself (alert level ${alertLevel} decrypts an hour for this drill, counting the shop's own earlier reads; statuses ${JSON.stringify(onServer.statuses)}). Not zero: whoever runs code on the shop's server can read up to the alert level`);

  // 2h. Rate limit, per key.
  const bulkKey = await scopedKey(baseUrl, shopT, 'bulk-writer', ['crypto:encrypt'], onShopServer);
  let sent = 0;
  let first429 = null;
  while (sent < 400 && first429 === null) {
    const res = await http(baseUrl, 'POST', '/v1/encrypt', bulkKey.key, null, { key: keyId, data: 'x' }, SHOP_IP);
    sent++;
    if (res.status === 429) first429 = sent;
  }
  record(D2, first429 ? 'PASS' : 'FAIL', 'One key making a flood of requests runs into the rate limit',
    first429 ? `429 after ${first429} requests by that key in the minute` : 'no 429 within 400 requests');
  const otherKeySameIp = await http(baseUrl, 'POST', '/v1/encrypt', writerKey.key, null, { key: keyId, data: 'x' }, SHOP_IP);
  record(D2, otherKeySameIp.status === 200 ? 'PASS' : 'FAIL',
    "The limit is per key: the shop's other key, from the same IP, still works",
    otherKeySameIp.status === 200
      ? 'HTTP 200. A flooding key is slowed wherever it is used from, and does not lock out the shop'
      : `${errCode(otherKeySameIp)}: the bucket is shared by every key on that IP`);

  // 2i. Does the owner see it, and are they told?
  await new Promise((r) => setTimeout(r, 300)); // audit writes and alerts run after the response
  const getAudit = (query) =>
    http(baseUrl, 'GET', `/v1/organizations/${shopT.orgId}/audit?limit=100${query}`, shopT.sessionToken, shopT.orgId);
  const decryptAudit = await getAudit('&action=crypto.decrypt');
  const decryptEvents = decryptAudit.json?.auditEvents || [];
  const withIp = decryptEvents.filter((e) => e.ipAddress).length;
  record(D2, decryptEvents.length > 0 ? 'PASS' : 'FAIL', "The owner can see the stolen key's decrypt calls in the audit log",
    `${decryptEvents.length} crypto.decrypt events on the first page, ${withIp} with the caller's IP (for example ${decryptEvents[0]?.ipAddress}); ${decryptAudit.json?.nextBefore ? 'older pages available with ?before=' : 'no paging'}`);
  const locked = (await getAudit('&action=security.key_auto_locked')).json?.auditEvents || [];
  record(D2, locked.length > 0 ? 'PASS' : 'FAIL', 'The key locked itself and the owner was told',
    locked.length
      ? `security.key_auto_locked for key ${String(locked[0].actorId).slice(0, 12)}… after ${locked[0].metadata?.decryptsInLastHour} decrypts in an hour; owners and admins are emailed how to enable it again`
      : 'no lock recorded');

  // --- Drill 3: AMARACUS outage ----------------------------------------------------------
  const D3 = 'Drill 3: AMARACUS outage';
  await amaracus.stop();
  const downClient = new AmaracusClient({ baseUrl, apiKey: writerKey.key, timeoutMs: 3000, sourceIp: SHOP_IP });
  const outageShop = new Shop({ dbPath: shopDbPath, keyId, writer: downClient, reader: downClient });
  const before = outageShop.count();
  let signupError = '';
  try {
    await outageShop.addCustomer(customers[0]);
  } catch (e) {
    signupError = e.message;
  }
  const after = outageShop.count();
  record(D3, signupError && after === before ? 'PASS' : 'FAIL', 'New sign-ups fail closed: nothing is stored in plain text',
    `error: "${signupError}"; rows before ${before}, after ${after}`);
  let readError = '';
  try {
    await outageShop.getCustomer(ids[10]);
  } catch (e) {
    readError = e.message;
  }
  record(D3, 'INFO', 'Staff cannot see customer details while AMARACUS is down', `error: "${readError}"`);
  outageShop.close();

  // --- Write results ----------------------------------------------------------------------
  const outDir = path.join(here, 'results');
  fs.mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().slice(0, 10);
  const lines = [
    `# Breach drill results (${stamp}, local copy of the API)`,
    '',
    'Generated by `node examples/breach-drill/drill.mjs`. PASS = the protection held, FAIL = it did not, INFO = a fact to know.',
    '',
    '| Drill | Result | Check | Detail |',
    '|---|---|---|---|',
  ];
  for (const r of results) lines.push(`| ${r.drill} | ${r.status} | ${r.check} | ${String(r.detail || '').replace(/\|/g, '/')} |`);
  fs.writeFileSync(path.join(outDir, `${stamp}-local.md`), lines.join('\n') + '\n');
  const fails = results.filter((r) => r.status === 'FAIL').length;
  console.log(`\n${results.length} checks, ${fails} FAIL. Written to examples/breach-drill/results/${stamp}-local.md`);
  fs.rmSync(workDir, { recursive: true, force: true });
  process.exit(0);
}

main().catch((err) => {
  console.error('Drill aborted:', err);
  process.exit(1);
});
