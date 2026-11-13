/**
 * Starts a private copy of the AMARACUS API for the drill: the real API code from
 * apps/api/dist, in its in-memory mode, on a random local port.
 *
 * It never touches production. Every variable from the project's .env is blanked
 * before the API loads (dotenv does not override variables that already exist), so
 * the API sees no production database, master key, Azure, Polar, Razorpay or email
 * credentials. The master key is a throwaway one. Nothing is written to disk.
 *
 * Build the API first: pnpm --filter @amaracus/api build   (or: cd apps/api && npx tsc)
 */
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const require = createRequire(import.meta.url);

function isolateFromProduction() {
  for (const file of [path.join(root, '.env'), path.join(root, 'apps/api/.env')]) {
    if (!fs.existsSync(file)) continue;
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
      if (m) process.env[m[1]] = '';
    }
  }
  process.env.NODE_ENV = 'test'; // in-memory data store, in-memory rate limits
  process.env.DATABASE_URL = 'postgresql://drill:drill@127.0.0.1:1/no_database';
  process.env.DIRECT_URL = process.env.DATABASE_URL;
  process.env.AUTH_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.API_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.UNSUBSCRIBE_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.AMARACUS_LOCAL_MASTER_KEY = crypto.randomBytes(32).toString('hex'); // throwaway
  process.env.DECRYPT_ALERT_PER_HOUR = '100'; // low, so the drill's bulk read triggers the alert
  // As in production behind Cloudflare: the client IP comes from X-Forwarded-For, which lets the
  // drill play the shop's server and an attacker's machine from one computer.
  process.env.TRUST_PROXY_HOPS = '1';
}

/**
 * Boots the API and creates one organization per name, each with an owner session,
 * a project and a production environment. Returns the base URL and the tenants.
 */
export async function startLocalAmaracus(tenantNames = ['shop', 'attacker']) {
  isolateFromProduction();
  const dist = path.join(root, 'apps/api/dist');
  if (!fs.existsSync(path.join(dist, 'index.js'))) {
    throw new Error('apps/api/dist is missing. Build the API first: cd apps/api && npx tsc');
  }
  const { app } = require(path.join(dist, 'index.js'));
  const { db } = require(path.join(dist, 'lib/data-store.js'));

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const tenants = {};
  for (const name of tenantNames) {
    const tag = crypto.randomUUID().slice(0, 8);
    const org = await db.createOrganization({ name: `${name} org`, slug: `${name}-${tag}` });
    const user = await db.createUser({ email: `owner-${tag}@${name}.example`, name: `${name} owner`, passwordHash: 'unused' });
    await db.addMember({ organizationId: org.id, userId: user.id, role: 'OWNER' });
    const sessionToken = `sess_${crypto.randomUUID()}`;
    await db.createSession({
      sessionToken,
      userId: user.id,
      activeOrgId: org.id,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    const project = await db.createProject({ organizationId: org.id, name: `${name} app`, slug: `${name}-app` });
    const env = await db.createEnvironment({ projectId: project.id, name: 'production', slug: 'production', type: 'PRODUCTION' });
    await db.upsertBillingSubscription({ organizationId: org.id, plan: 'PRO', status: 'ACTIVE' });
    tenants[name] = { orgId: org.id, projectId: project.id, environmentId: env.id, sessionToken };
  }

  return {
    baseUrl,
    tenants,
    stop: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
