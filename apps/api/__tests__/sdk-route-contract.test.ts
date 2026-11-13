/**
 * Phase 6 contract test: the SDKs call routes that exist.
 *
 * 1. Every request path in packages/sdk-ts/src/client.ts and packages/sdk-py/amaracus/client.py
 *    is sent to the real app; none may fall through to Express's "Cannot <METHOD>" 404.
 * 2. The TypeScript SDK methods repaired in Phase 6 are exercised end to end.
 * 3. The Python SDK runs against the same server (skipped when no Python is installed).
 */
import http from 'http';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { spawn, spawnSync } from 'child_process';
import { AddressInfo } from 'net';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey } from '../src/lib/api-keys';
import { Amaracus, AmaracusError } from '@amaracus/sdk';

const ROOT = path.join(__dirname, '../../..');

// Preview features the API deliberately answers with 501 until real implementations exist.
const DISABLED_PREVIEW = /^\/advanced\/(mpc|threshold)\//;

type Call = { sdk: 'ts' | 'py'; method: string; path: string; line: number };

function extractCalls(): Call[] {
  const calls: Call[] = [];
  const ts = fs.readFileSync(path.join(ROOT, 'packages/sdk-ts/src/client.ts'), 'utf8');
  const tsRe = /request(?:<[^(]*?>)?\(\s*'(GET|POST|PUT|PATCH|DELETE)',\s*(`[^`]*`|'[^']*')/g;
  let m: RegExpExecArray | null;
  while ((m = tsRe.exec(ts))) {
    const p = m[2].slice(1, -1).replace(/\/\$\{[^}]+\}/g, '/probe_id').replace(/\$\{[^}]+\}/g, '');
    calls.push({ sdk: 'ts', method: m[1], path: p, line: ts.slice(0, m.index).split('\n').length });
  }
  const py = fs.readFileSync(path.join(ROOT, 'packages/sdk-py/amaracus/client.py'), 'utf8');
  const pyRe = /request\("(GET|POST|PUT|PATCH|DELETE)",\s*f?"([^"]*)"/g;
  while ((m = pyRe.exec(py))) {
    const p = m[2].replace(/\/\{[^}]+\}/g, '/probe_id').replace(/\{[^}]+\}/g, '');
    calls.push({ sdk: 'py', method: m[1], path: p, line: py.slice(0, m.index).split('\n').length });
  }
  return calls;
}

function findPython(): string | null {
  for (const cmd of ['python3', 'python']) {
    const r = spawnSync(cmd, ['--version'], { encoding: 'utf8' });
    if (r.status === 0 && /Python 3/.test(`${r.stdout}${r.stderr}`)) return cmd;
  }
  return null;
}

describe('Phase 6 — SDK ↔ API contract', () => {
  let server: http.Server;
  let baseUrl: string;
  let apiKey: string;
  let projectId: string;
  let environmentId: string;
  let sdk: Amaracus;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
    const suffix = crypto.randomUUID().slice(0, 8);
    const org = await db.createOrganization({ name: 'Contract Org', slug: `contract-${suffix}` });
    const user = await db.createUser({ email: `contract_${suffix}@example.test`, name: 'Contract' });
    await db.addMember({ organizationId: org.id, userId: user.id, role: 'OWNER' });
    const project = await db.createProject({ organizationId: org.id, name: 'Contract', slug: `contract-${suffix}` });
    const env = await db.createEnvironment({ projectId: project.id, name: 'production', slug: 'production', type: 'production' } as any);
    projectId = project.id;
    environmentId = env.id;
    const k = generateAmaracusApiKey('live');
    apiKey = k.fullKey;
    await db.createApiCredential({
      organizationId: org.id,
      projectId,
      environmentId,
      name: 'contract',
      prefix: k.prefix,
      keyHash: k.keyHash,
      scopes: ['*'],
    });
    sdk = new Amaracus({ apiKey, baseUrl: `${baseUrl}/v1`, maxRetries: 0, timeoutMs: 20000 });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('every SDK request path reaches a real route', async () => {
    const calls = extractCalls();
    expect(calls.filter((c) => c.sdk === 'ts').length).toBeGreaterThan(130);
    expect(calls.filter((c) => c.sdk === 'py').length).toBeGreaterThan(30);

    const problems: string[] = [];
    for (const c of calls) {
      const prefix = c.sdk === 'ts' ? '/v1' : '/api/v1';
      const res = await fetch(`${baseUrl}${prefix}${c.path}`, {
        method: c.method,
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: c.method === 'GET' || c.method === 'DELETE' ? undefined : '{}',
      });
      const text = await res.text();
      if (res.status === 404 && /Cannot (GET|POST|PUT|PATCH|DELETE)/.test(text)) {
        problems.push(`${c.sdk}:${c.line} ${c.method} ${c.path} -> no such route`);
      }
      if (res.status === 501 && !DISABLED_PREVIEW.test(c.path)) {
        problems.push(`${c.sdk}:${c.line} ${c.method} ${c.path} -> 501`);
      }
    }
    expect(problems).toEqual([]);
  }, 300000);

  describe('repaired TypeScript SDK methods', () => {
    it('legacy crypto.encrypt/decrypt round-trip through the managed-key endpoints', async () => {
      const key = await sdk.keys.create({ name: 'contract-aes', algorithm: 'AES-256-GCM', purpose: 'ENCRYPT_DECRYPT', projectId, environmentId });
      const enc = await sdk.crypto.encrypt({ key: key.id, data: 'hello contract' });
      expect(enc.envelope).toBeTruthy();
      const dec = await sdk.crypto.decrypt({ key: key.id, envelope: enc.envelope });
      expect(dec.plaintext).toBe('hello contract');
    });

    it('crypto.digest and crypto.mac reach /crypto/hash and /crypto/hmac', async () => {
      const digest = await sdk.crypto.digest({ algorithm: 'SHA-256', data: 'hello' });
      expect(JSON.stringify(digest)).toContain('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
      const mac = await sdk.crypto.mac({ algorithm: 'HMAC-SHA-256', key: '00'.repeat(32), keyEncoding: 'hex', data: 'hello' });
      expect(mac).toBeTruthy();
    });

    it('keys.archive disables, keys.revoke revokes, and a revoked key cannot be re-activated', async () => {
      const key = await sdk.keys.create({ name: 'contract-sign', algorithm: 'ED25519', purpose: 'SIGN_VERIFY', projectId, environmentId });
      expect((await sdk.keys.archive(key.id)).status).toBe('DISABLED');
      expect((await sdk.keys.revoke(key.id)).status).toBe('REVOKED');
      await expect(sdk.keys.update(key.id, { status: 'ACTIVE' })).rejects.toMatchObject({ status: 409 });
    });

    it('certificates: list CAs, issue, get, validate and revoke through /pki', async () => {
      const caRes = await fetch(`${baseUrl}/v1/pki/certificate-authorities`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Contract Root CA',
          projectId,
          environmentId,
          type: 'ROOT_CA',
          subject: 'CN=Contract Root CA, O=Amaracus, C=US',
          keyAlgorithm: 'RSA-2048',
          validityDays: 365,
        }),
      });
      expect(caRes.status).toBe(201);
      const ca = ((await caRes.json()) as any).data;

      const cas = await sdk.certificates.getCas();
      expect(JSON.stringify(cas)).toContain(ca.id);

      const cert = await sdk.certificates.issue({
        authorityId: ca.id,
        projectId,
        environmentId,
        subject: 'CN=sdk.contract.test, O=Amaracus, C=US',
        san: { dns: ['sdk.contract.test'] },
        validityDays: 90,
      });
      expect(cert.certificatePem).toContain('-----BEGIN CERTIFICATE-----');
      expect((await sdk.certificates.get(cert.id)).id).toBe(cert.id);
      expect(JSON.stringify(await sdk.certificates.list())).toContain(cert.id);

      const validation = await sdk.certificates.validate(cert.id);
      expect(validation.isValid).toBe(true);
      expect(validation.chainValid).toBe(true);
      expect(validation.revocationStatus).toBe('GOOD');

      await sdk.certificates.revoke(cert.id, 'KEY_COMPROMISE');
      expect((await sdk.certificates.get(cert.id)).status).toBe('REVOKED');
    });

    it('intelligence scan, findings and CBOM export resolve', async () => {
      await expect(sdk.intelligence.scan()).resolves.toBeDefined();
      await expect(sdk.intelligence.getFindings()).resolves.toBeDefined();
      await expect(sdk.intelligence.exportCbom('cyclonedx')).resolves.toBeDefined();
    });

    it('jobs.cancel reaches POST /jobs/:id/cancel (a missing job is a JSON 404, not a missing route)', async () => {
      const err = await sdk.jobs.cancel('job_does_not_exist').catch((e) => e);
      expect(err).toBeInstanceOf(AmaracusError);
      expect(err.status).toBe(404);
    });
  });

  it('policy routes check roles: a READ_ONLY member can list policies but not create them', async () => {
    const suffix = crypto.randomUUID().slice(0, 8);
    const org = await db.createOrganization({ name: 'Policy Roles', slug: `policy-roles-${suffix}` });
    const owner = await db.createUser({ email: `pol_owner_${suffix}@example.test`, name: 'Owner' });
    const viewer = await db.createUser({ email: `pol_viewer_${suffix}@example.test`, name: 'Viewer' });
    await db.addMember({ organizationId: org.id, userId: owner.id, role: 'OWNER' });
    await db.addMember({ organizationId: org.id, userId: viewer.id, role: 'READ_ONLY' });
    const ownerToken = 'sess_' + crypto.randomUUID();
    const viewerToken = 'sess_' + crypto.randomUUID();
    await db.createSession({ sessionToken: ownerToken, userId: owner.id, activeOrgId: org.id, expiresAt: new Date(Date.now() + 3600000) });
    await db.createSession({ sessionToken: viewerToken, userId: viewer.id, activeOrgId: org.id, expiresAt: new Date(Date.now() + 3600000) });

    const body = JSON.stringify({
      name: 'Baseline',
      enforcementMode: 'AUDIT',
      rules: [{ name: 'Denied', category: 'ALGORITHM_RESTRICTION', effect: 'DENY', enabled: true, condition: { algorithms: ['MD5'] } }],
    });
    const post = (token: string) =>
      fetch(`${baseUrl}/v1/policies`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body,
      });

    expect((await post(viewerToken)).status).toBe(403);
    expect((await post(ownerToken)).status).toBe(201);

    const list = await fetch(`${baseUrl}/v1/policies`, { headers: { Authorization: `Bearer ${viewerToken}` } });
    expect(list.status).toBe(200);
    const policies = ((await list.json()) as any).data;
    expect(policies).toHaveLength(1);
    expect(policies[0].rules[0].condition.algorithms).toEqual(['MD5']);
  });

  it('the Python SDK round-trips against the same server', async () => {
    const python = findPython();
    if (!python) {
      console.warn('[sdk-route-contract] Python 3 not found; Python SDK check skipped.');
      return;
    }
    const script = [
      'import sys, json',
      `sys.path.insert(0, ${JSON.stringify(path.join(ROOT, 'packages/sdk-py'))})`,
      'from amaracus import Amaracus',
      'from amaracus.exceptions import AmaracusNotFoundError',
      'c = Amaracus(api_key=sys.argv[1], base_url=sys.argv[2], max_retries=0)',
      'k = c.keys.create(name="py-contract", project_id=sys.argv[3], environment_id=sys.argv[4], algorithm="AES-256-GCM", purpose="ENCRYPT_DECRYPT")',
      'enc = c.encrypt(k["id"], "hello python", aad="ctx")',
      'dec = c.decrypt(k["id"], envelope=enc["envelope"], aad="ctx")',
      'binary = bytes([0, 255, 1, 128])',
      'enc_b = c.encrypt(k["id"], binary)',
      'dec_b = c.decrypt(k["id"], envelope=enc_b["envelope"])',
      'h = c.hash("hello")',
      'legacy = c.crypto.encrypt("AES-256-GCM", "via key id", key_id=k["id"])',
      'certs = c.certificates.list()',
      'missing_job = False',
      'try:',
      '    c.jobs.cancel("job_does_not_exist")',
      'except AmaracusNotFoundError:',
      '    missing_job = True',
      'revoked = c.keys.revoke(k["id"])',
      'print(json.dumps({"dec": dec.get("plaintext"), "dec_b": dec_b.get("plaintext"), "dec_b_enc": dec_b.get("encoding"),',
      '  "digest": h.get("digest"), "legacy_env": bool(legacy.get("envelope")), "certs": isinstance(certs, list),',
      '  "missing_job": missing_job, "revoked": revoked.get("status")}))',
    ].join('\n');
    // Asynchronous spawn: the API server runs in this process and must keep answering.
    const r = await new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn(python, ['-I', '-c', script, apiKey, `${baseUrl}/api/v1`, projectId, environmentId]);
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (status) => resolve({ status, stdout, stderr }));
    });
    if (r.status !== 0) throw new Error(`Python SDK failed:\n${r.stderr || r.stdout}`);
    const out = JSON.parse(r.stdout.trim().split('\n').pop()!);
    expect(out).toEqual({
      dec: 'hello python',
      dec_b: Buffer.from([0, 255, 1, 128]).toString('base64'),
      dec_b_enc: 'base64',
      digest: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      legacy_env: true,
      certs: true,
      missing_job: true,
      revoked: 'REVOKED',
    });
  }, 180000);
});
