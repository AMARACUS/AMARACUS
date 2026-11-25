/**
 * The MCP server (/mcp) and its OAuth endpoints: discovery, registration, consent, PKCE, single-use
 * codes, refresh rotation and reuse, revocation, scope limits and the tools themselves.
 */
import { itCloud } from './helpers/edition';
import 'reflect-metadata';
import http from 'http';
import { AddressInfo } from 'net';
import crypto from 'crypto';
import { app } from '../src/index';
import { db } from '../src/lib/data-store';
import { generateAmaracusApiKey, hashApiKey } from '../src/lib/api-keys';
import { MCP_TOOLS } from '../src/mcp/tools';
import { mcpBaseUrl, mcpResourceUrl, MCP_SCOPE_IDS } from '../src/mcp/config';
import { isAllowedRedirectUri, redirectUriMatches } from '../src/mcp/redirect-uris';
import { seal, unseal } from '../src/mcp/sealed-token';
import { GUIDE_TOPICS, integrationGuide } from '../src/mcp/integration-guide';

jest.setTimeout(120000);

let server: http.Server;
let baseUrl: string;

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      resolve();
    });
  });
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

async function tenant(plan = 'PRO', role: any = 'OWNER') {
  const tag = crypto.randomUUID().slice(0, 8);
  const org = await db.createOrganization({ name: `m ${tag}`, slug: `m-${tag}` });
  const project = await db.createProject({ organizationId: org.id, name: 'p', slug: `p-${tag}` });
  const env = await db.createEnvironment({ projectId: project.id, name: 'prod', slug: 'prod', type: 'PRODUCTION' });
  await db.upsertBillingSubscription({ organizationId: org.id, plan, status: 'ACTIVE' });
  const user = await db.createUser({ email: `u-${tag}@mcp.example`, name: 'U', passwordHash: 'x' });
  await db.addMember({ organizationId: org.id, userId: user.id, role });
  const session = `sess_${crypto.randomUUID()}`;
  await db.createSession({ sessionToken: session, userId: user.id, activeOrgId: org.id, expiresAt: new Date(Date.now() + 3600_000) });
  return { org, project, env, user, session };
}

async function apiKey(t: Awaited<ReturnType<typeof tenant>>, scopes: string[], extra: any = {}) {
  const gen = generateAmaracusApiKey('live');
  const cred = await db.createApiCredential({
    organizationId: t.org.id,
    projectId: t.project.id,
    environmentId: t.env.id,
    name: 'agent key',
    prefix: gen.prefix,
    keyHash: gen.keyHash,
    scopes,
    ...extra,
  });
  return { key: gen.fullKey, id: cred.id };
}

async function rpc(token: string | null, method: string, params: any = {}, headers: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const text = await res.text();
  const json = text.startsWith('event:') || text.startsWith('data:') || text.includes('\ndata:')
    ? JSON.parse(text.split('\n').find((l) => l.startsWith('data:'))!.slice(5))
    : text
      ? JSON.parse(text)
      : {};
  return { status: res.status, headers: res.headers, body: json as any };
}

async function tool(token: string, name: string, args: any = {}) {
  const r = await rpc(token, 'tools/call', { name, arguments: args });
  return { ...r, result: r.body.result, data: r.body.result?.structuredContent, text: r.body.result?.content?.[0]?.text as string };
}

const post = (path: string, body: any, headers: Record<string, string> = {}) =>
  fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
const form = (path: string, body: Record<string, string>) =>
  fetch(`${baseUrl}${path}`, { method: 'POST', body: new URLSearchParams(body) });

const REDIRECT = 'https://client.example/callback';

async function register(uris = [REDIRECT], name = 'Test Client') {
  const res = await post('/oauth/register', { client_name: name, redirect_uris: uris, token_endpoint_auth_method: 'none' });
  return { status: res.status, body: (await res.json()) as any };
}

async function authorize(clientId: string, over: Record<string, string | undefined> = {}) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const query: Record<string, string | undefined> = {
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: 'st-123',
    scope: 'keys:read keys:create crypto:encrypt crypto:decrypt',
    resource: mcpResourceUrl(),
    ...over,
  };
  const qs = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined) as [string, string][]);
  const res = await fetch(`${baseUrl}/oauth/authorize?${qs}`, { redirect: 'manual' });
  const location = res.headers.get('location');
  return { status: res.status, location: location ? new URL(location) : null, verifier, res };
}

async function approve(t: Awaited<ReturnType<typeof tenant>>, request: string, scopes: string[], over: any = {}) {
  const res = await post(
    '/v1/mcp-connect/approve',
    { request, environmentId: t.env.id, scopes, ...over },
    { Authorization: `Bearer ${t.session}`, 'X-Organization-Id': t.org.id }
  );
  return { status: res.status, body: (await res.json()) as any };
}

async function connect(t: Awaited<ReturnType<typeof tenant>>, scopes = ['keys:read', 'keys:create', 'crypto:encrypt', 'crypto:decrypt']) {
  const clientId = (await register()).body.client_id as string;
  const a = await authorize(clientId);
  const request = a.location!.searchParams.get('request')!;
  const approved = await approve(t, request, scopes);
  const to = new URL(approved.body.data.redirectTo);
  const code = to.searchParams.get('code')!;
  const exchange = (over: Record<string, string> = {}) =>
    form('/oauth/token', {
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      code_verifier: a.verifier,
      redirect_uri: REDIRECT,
      resource: mcpResourceUrl(),
      ...over,
    });
  return { clientId, code, to, exchange };
}

describe('discovery', () => {
  it('serves protected resource and authorization server metadata to any origin', async () => {
    for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const res = await fetch(`${baseUrl}${path}`, { headers: { Origin: 'https://inspector.example' } });
      expect(res.status).toBe(200);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      const doc = (await res.json()) as any;
      expect(doc.resource).toBe(mcpResourceUrl());
      expect(doc.authorization_servers).toEqual([mcpBaseUrl()]);
    }
    const as = (await (await fetch(`${baseUrl}/.well-known/oauth-authorization-server`)).json()) as any;
    expect(as.issuer).toBe(mcpBaseUrl());
    expect(as.code_challenge_methods_supported).toEqual(['S256']);
    expect(as.token_endpoint_auth_methods_supported).toEqual(['none']);
    expect(as.registration_endpoint).toBe(`${mcpBaseUrl()}/oauth/register`);
  });

  it('answers an unauthenticated call with 401 and a pointer to the metadata', async () => {
    const r = await rpc(null, 'initialize', {});
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain(`resource_metadata="${mcpBaseUrl()}/.well-known/oauth-protected-resource/mcp"`);
  });

  it('refuses console sessions, cookies and unknown tokens', async () => {
    const t = await tenant();
    expect((await rpc(t.session, 'ping')).status).toBe(401);
    expect((await rpc(null, 'ping', {}, { Cookie: `sessionToken=${t.session}` })).status).toBe(401);
    const unknown = await rpc('am_live_nope', 'ping');
    expect(unknown.status).toBe(401);
    expect(unknown.headers.get('www-authenticate')).toContain('invalid_token');
    expect((await fetch(`${baseUrl}/mcp`)).status).toBe(401);
  });
});

describe('protocol and tools', () => {
  it('initializes and lists annotated tools', async () => {
    const t = await tenant();
    const { key } = await apiKey(t, ['keys:read']);
    const init = await rpc(key, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
    expect(init.status).toBe(200);
    expect(init.body.result.serverInfo.name).toBe('amaracus');
    const list = await rpc(key, 'tools/list');
    expect(list.body.result.tools.map((x: any) => x.name).sort()).toEqual(MCP_TOOLS.map((x) => x.name).sort());
    for (const x of list.body.result.tools) {
      expect(x.title).toBeTruthy();
      expect(x.name.length).toBeLessThanOrEqual(64);
      expect(x.inputSchema.type).toBe('object');
      for (const hint of ['readOnlyHint', 'destructiveHint', 'openWorldHint', 'idempotentHint']) {
        expect(typeof x.annotations[hint]).toBe('boolean');
      }
    }
  });

  it('never exposes a tool that deletes keys or manages API keys', () => {
    expect(MCP_TOOLS.map((x) => x.name).join(' ')).not.toMatch(/delete|destroy|revoke|credential|api_key/);
    expect(MCP_SCOPE_IDS).not.toEqual(expect.arrayContaining(['keys:delete']));
    expect(MCP_SCOPE_IDS.join(' ')).not.toMatch(/credentials|\*/);
  });

  it('creates, uses, rotates, disables and enables a key without returning key material', async () => {
    const t = await tenant();
    const { key } = await apiKey(t, MCP_SCOPE_IDS);
    const created = await tool(key, 'create_key', { name: 'customer-data' });
    expect(created.result.isError).toBeFalsy();
    const id = created.data.id;
    const enc = await tool(key, 'encrypt_data', { key_id: id, data: 'héllo <b>"x"</b>', context: 'c:1' });
    expect(enc.data.envelope).toBeTruthy();
    expect((await tool(key, 'rotate_key', { key_id: id })).data.currentVersion).toBe(2);
    expect((await tool(key, 'decrypt_data', { key_id: id, envelope: enc.data.envelope, context: 'c:1' })).data.text).toBe('héllo <b>"x"</b>');
    const wrong = await tool(key, 'decrypt_data', { key_id: id, envelope: enc.data.envelope, context: 'c:2' });
    expect(wrong.result.isError).toBe(true);
    expect(wrong.text).toContain('AAD_MISMATCH');
    expect((await tool(key, 'disable_key', { key_id: id })).data.status).toBe('DISABLED');
    expect((await tool(key, 'encrypt_data', { key_id: id, data: 'x' })).result.isError).toBe(true);
    expect((await tool(key, 'enable_key', { key_id: id })).data.status).toBe('ACTIVE');
    const listed = await tool(key, 'list_keys', { status: 'ACTIVE' });
    expect(listed.data.keys.map((k: any) => k.id)).toEqual([id]);
    const details = await tool(key, 'get_key', { key_id: id });
    expect(details.data.versions).toHaveLength(2);
    expect(JSON.stringify([created.data, listed.data, details.data])).not.toMatch(/encryptedKeyMaterial|providerKeyId/);
  });

  it('hashes, lists algorithms and reports usage and permissions', async () => {
    const t = await tenant();
    const { key } = await apiKey(t, ['crypto:hash', 'usage:read']);
    const hash = await tool(key, 'hash_data', { data: 'abc' });
    expect(hash.data.digest).toBe(crypto.createHash('sha256').update('abc').digest('hex'));
    expect((await tool(key, 'list_algorithms', { category: 'hash' })).data.algorithms.length).toBeGreaterThan(3);
    expect((await tool(key, 'get_usage')).data).toHaveProperty('totalRequests');
    expect((await tool(key, 'get_connection')).data).toEqual({ connection: 'agent key', permissions: ['crypto:hash', 'usage:read'] });
    for (const topic of GUIDE_TOPICS) {
      expect((await tool(key, 'get_integration_guide', { topic })).text).toBe(integrationGuide(topic, mcpBaseUrl()));
    }
  });

  it('enforces scopes, and rejects arguments outside the schema', async () => {
    const t = await tenant();
    const { key } = await apiKey(t, ['keys:read']);
    const denied = await tool(key, 'create_key', { name: 'x' });
    expect(denied.result.isError).toBe(true);
    expect(denied.text).toContain('keys:create');
    const bad = await tool(key, 'get_key', { key_id: 5 });
    expect(bad.body.error || bad.result.isError).toBeTruthy();
    const traversal = await tool(key, 'get_key', { key_id: '../credentials' });
    expect(traversal.result.isError).toBe(true);
    expect(traversal.text).toContain('KEY_NOT_FOUND');
  });

  it('keeps organizations apart', async () => {
    const a = await tenant();
    const b = await tenant();
    const created = await tool((await apiKey(a, MCP_SCOPE_IDS)).key, 'create_key', { name: 'a-key' });
    const other = await apiKey(b, MCP_SCOPE_IDS);
    expect((await tool(other.key, 'get_key', { key_id: created.data.id })).result.isError).toBe(true);
    expect((await tool(other.key, 'list_keys')).data.keys).toEqual([]);
    expect((await tool(other.key, 'encrypt_data', { key_id: created.data.id, data: 'x' })).result.isError).toBe(true);
  });

  it('applies the IP allowlist of an API key', async () => {
    const t = await tenant();
    const { key } = await apiKey(t, ['keys:read'], { allowedIps: ['203.0.113.7'] });
    expect((await rpc(key, 'tools/list')).status).toBe(403);
    const local = await apiKey(t, ['keys:read'], { allowedIps: ['127.0.0.1'] });
    expect((await tool(local.key, 'list_keys')).result.isError).toBeFalsy();
  });

  itCloud('explains a missing plan without linking to a checkout', async () => {
    const t = await tenant('FREE');
    const { key } = await apiKey(t, MCP_SCOPE_IDS);
    const r = await tool(key, 'create_key', { name: 'x' });
    expect(r.result.isError).toBe(true);
    expect(r.text).toContain('no active AMARACUS plan');
    expect(r.text).not.toMatch(/billing|checkout|upgrade/i);
  });
});

describe('OAuth', () => {
  it('registers https, loopback and editor redirects only', async () => {
    for (const uri of ['https://chatgpt.com/connector_platform_oauth_redirect', 'http://localhost:3118/callback', 'http://127.0.0.1/cb', 'cursor://anysphere.cursor-mcp/oauth/callback']) {
      expect((await register([uri])).status).toBe(201);
    }
    for (const uri of ['http://evil.example/cb', 'javascript:alert(1)', 'data:text/html,x', 'myapp://cb', 'https://user:pw@x.example/', 'https://x.example/#f', 'http://localhost.evil.example/cb']) {
      expect((await register([uri])).status).toBe(400);
    }
    expect((await register([])).status).toBe(400);
    expect(isAllowedRedirectUri(5)).toBe(false);
    expect(redirectUriMatches(['http://localhost/callback'], 'http://localhost:51234/callback')).toBe(true);
    expect(redirectUriMatches(['http://localhost/callback'], 'http://localhost:51234/other')).toBe(false);
    expect(redirectUriMatches(['https://a.example/cb'], 'https://a.example:444/cb')).toBe(false);
  });

  it('binds sealed values to one purpose and to their expiry', () => {
    const value = seal('client', { a: 1 });
    expect(unseal('client', value)).toEqual({ a: 1 });
    expect(unseal('refresh', value)).toBeNull();
    expect(unseal('client', value.slice(0, -2) + (value.endsWith('AA') ? 'BB' : 'AA'))).toBeNull();
    expect(unseal('code', seal('code', { a: 1 }, -5))).toBeNull();
    expect(unseal('client', undefined)).toBeNull();
  });

  it('never redirects to an unregistered URI, and requires PKCE S256 and the right resource', async () => {
    const clientId = (await register()).body.client_id;
    const evil = await authorize(clientId, { redirect_uri: 'https://evil.example/cb' });
    expect(evil.status).toBe(400);
    expect(evil.location).toBeNull();
    expect((await authorize('forged-client-id-forged-client-id-forged-client-id')).status).toBe(400);
    const plain = await authorize(clientId, { code_challenge_method: 'plain' });
    expect(plain.location!.searchParams.get('error')).toBe('invalid_request');
    expect(plain.location!.searchParams.get('state')).toBe('st-123');
    expect((await authorize(clientId, { code_challenge: undefined })).location!.searchParams.get('error')).toBe('invalid_request');
    expect((await authorize(clientId, { resource: 'https://other.example/mcp' })).location!.searchParams.get('error')).toBe('invalid_target');
    expect((await authorize(clientId, { response_type: 'token' })).location!.searchParams.get('error')).toBe('unsupported_response_type');
  });

  it('runs the whole flow: consent, code, token, tool call', async () => {
    const t = await tenant();
    const clientId = (await register([REDIRECT], 'Test <b>Client</b>')).body.client_id;
    const a = await authorize(clientId);
    expect(a.status).toBe(302);
    expect(a.location!.pathname).toBe('/connect/');
    const request = a.location!.searchParams.get('request')!;

    const shown = (await (await post('/v1/mcp-connect/request', { request })).json()) as any;
    expect(shown.data.destination).toBe('client.example');
    expect(shown.data.clientName).not.toMatch(/[<>]/);
    expect(shown.data.scopes.map((s: any) => s.id)).toEqual(['keys:read', 'crypto:encrypt', 'keys:create', 'crypto:decrypt']);
    expect(shown.data.scopes.find((s: any) => s.id === 'crypto:decrypt').preselected).toBe(false);

    const approved = await approve(t, request, ['keys:read', 'keys:create']);
    expect(approved.status).toBe(200);
    const to = new URL(approved.body.data.redirectTo);
    expect(to.origin + to.pathname).toBe(REDIRECT);
    expect(to.searchParams.get('state')).toBe('st-123');
    expect(to.searchParams.get('iss')).toBe(mcpBaseUrl());

    const res = await form('/oauth/token', {
      grant_type: 'authorization_code',
      client_id: clientId,
      code: to.searchParams.get('code')!,
      code_verifier: a.verifier,
      redirect_uri: REDIRECT,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const tokens = (await res.json()) as any;
    expect(tokens.token_type).toBe('Bearer');
    expect(tokens.scope).toBe('keys:read keys:create');

    expect((await tool(tokens.access_token, 'create_key', { name: 'via-oauth' })).result.isError).toBeFalsy();
    // Not granted, although the client asked for it.
    expect((await tool(tokens.access_token, 'encrypt_data', { key_id: 'x', data: 'x' })).text).toContain('crypto:encrypt');
    // The connection shows up as an API credential, with the secret stored only as a hash.
    const cred = await db.findCredentialByHash(hashApiKey(tokens.access_token));
    expect(cred!.name).toMatch(/^MCP: Test/);
    expect(cred!.scopes).toEqual(['keys:read', 'keys:create']);
  });

  it('accepts a code once, only with its verifier, client and redirect URI', async () => {
    const t = await tenant();
    const c = await connect(t);
    const other = (await register(['https://other.example/cb'])).body.client_id;
    expect((await c.exchange({ code_verifier: crypto.randomBytes(32).toString('base64url') })).status).toBe(400);
    expect((await c.exchange({ client_id: other })).status).toBe(400);
    expect((await c.exchange({ redirect_uri: 'https://client.example/else' })).status).toBe(400);
    expect((await c.exchange({ resource: 'https://other.example' })).status).toBe(400);
    expect((await c.exchange()).status).toBe(200);
    const again = await c.exchange();
    expect(again.status).toBe(400);
    expect(((await again.json()) as any).error).toBe('invalid_grant');
  });

  it('lets only a signed-in member with the right role approve, within their own organization', async () => {
    const t = await tenant();
    const stranger = await tenant();
    const clientId = (await register()).body.client_id;
    const request = (await authorize(clientId)).location!.searchParams.get('request')!;
    const { key } = await apiKey(t, ['*']);
    const withKey = await post('/v1/mcp-connect/approve', { request, environmentId: t.env.id, scopes: ['keys:read'] }, { Authorization: `Bearer ${key}` });
    expect(withKey.status).toBe(403);
    expect((await post('/v1/mcp-connect/approve', { request, environmentId: t.env.id, scopes: ['keys:read'] })).status).toBe(401);
    expect((await approve(stranger, request, ['keys:read'], { environmentId: t.env.id })).status).toBe(404);
    expect((await approve(t, request, ['keys:rotate'])).status).toBe(400); // the client did not ask for it
    expect((await approve(t, request, [])).status).toBe(400);
    const auditor = await tenant('PRO', 'READ_ONLY');
    expect((await approve(auditor, request, ['keys:read'])).status).toBe(403);
    expect((await approve(t, 'x'.repeat(60), ['keys:read'])).status).toBe(400);
  });

  itCloud('needs an active plan to connect', async () => {
    const t = await tenant('FREE');
    const clientId = (await register()).body.client_id;
    const request = (await authorize(clientId)).location!.searchParams.get('request')!;
    expect((await approve(t, request, ['keys:read'])).status).toBe(402);
  });

  it('reports a declined request to the client', async () => {
    const clientId = (await register()).body.client_id;
    const request = (await authorize(clientId)).location!.searchParams.get('request')!;
    const r = (await (await post('/v1/mcp-connect/deny', { request })).json()) as any;
    expect(new URL(r.data.redirectTo).searchParams.get('error')).toBe('access_denied');
  });

  it('rotates refresh tokens, and ends the connection when an old one comes back', async () => {
    const t = await tenant();
    const c = await connect(t);
    const first = (await (await c.exchange()).json()) as any;
    const refresh = (token: string, clientId = c.clientId) => form('/oauth/token', { grant_type: 'refresh_token', client_id: clientId, refresh_token: token });

    expect((await refresh(first.refresh_token, (await register()).body.client_id)).status).toBe(400);
    const second = (await (await refresh(first.refresh_token)).json()) as any;
    expect(second.access_token).not.toBe(first.access_token);
    expect((await rpc(first.access_token, 'tools/list')).status).toBe(401);
    expect((await rpc(second.access_token, 'tools/list')).status).toBe(200);

    // A quick replay (a client race) is refused but does not end the connection.
    expect((await refresh(first.refresh_token)).status).toBe(400);
    expect((await rpc(second.access_token, 'tools/list')).status).toBe(200);

    // Later, it does.
    const cred = (await db.findCredentialByHash(hashApiKey(second.access_token)))!;
    const secret = { prefix: cred.prefix, keyHash: cred.keyHash };
    await db.rotateCredentialIfCurrent(cred.id, cred.keyHash, { ...secret, expiresAt: new Date(Date.now() + 30 * 60_000) });
    expect((await refresh(first.refresh_token)).status).toBe(400);
    expect((await rpc(second.access_token, 'tools/list')).status).toBe(401);
    expect((await refresh(second.refresh_token)).status).toBe(400);
  });

  it('lets only one of two concurrent refreshes win', async () => {
    const t = await tenant();
    const c = await connect(t);
    const tokens = (await (await c.exchange()).json()) as any;
    const go = () => form('/oauth/token', { grant_type: 'refresh_token', client_id: c.clientId, refresh_token: tokens.refresh_token });
    const statuses = (await Promise.all([go(), go(), go()])).map((r) => r.status).sort();
    expect(statuses).toEqual([200, 400, 400]);
  });

  it('refreshes an expired access token, but not for someone who left the organization', async () => {
    const t = await tenant();
    const c = await connect(t);
    const tokens = (await (await c.exchange()).json()) as any;
    const cred = (await db.findCredentialByHash(hashApiKey(tokens.access_token)))!;
    await db.rotateCredentialIfCurrent(cred.id, cred.keyHash, { prefix: cred.prefix, keyHash: cred.keyHash, expiresAt: new Date(Date.now() - 1000) });
    expect((await rpc(tokens.access_token, 'tools/list')).status).toBe(401);
    const spy = jest.spyOn(db, 'getMember');
    const go = (token: string) => form('/oauth/token', { grant_type: 'refresh_token', client_id: c.clientId, refresh_token: token });
    const fresh = (await (await go(tokens.refresh_token)).json()) as any;
    expect((await rpc(fresh.access_token, 'tools/list')).status).toBe(200);
    spy.mockResolvedValue(null);
    expect((await go(fresh.refresh_token)).status).toBe(400);
    spy.mockRestore();
    expect((await rpc(fresh.access_token, 'tools/list')).status).toBe(401);
  });

  it('honours revocation from the console and from the client', async () => {
    const t = await tenant();
    const c = await connect(t);
    const tokens = (await (await c.exchange()).json()) as any;
    const cred = (await db.findCredentialByHash(hashApiKey(tokens.access_token)))!;
    await db.revokeCredential(cred.id);
    expect((await rpc(tokens.access_token, 'tools/list')).status).toBe(401);
    expect((await form('/oauth/token', { grant_type: 'refresh_token', client_id: c.clientId, refresh_token: tokens.refresh_token })).status).toBe(400);

    const c2 = await connect(t);
    const tokens2 = (await (await c2.exchange()).json()) as any;
    expect((await form('/oauth/revoke', { token: tokens2.refresh_token })).status).toBe(200);
    expect((await rpc(tokens2.access_token, 'tools/list')).status).toBe(401);

    // An ordinary API key cannot be revoked through the OAuth endpoint.
    const { key } = await apiKey(t, ['keys:read']);
    expect((await form('/oauth/revoke', { token: key })).status).toBe(200);
    expect((await rpc(key, 'tools/list')).status).toBe(200);
  });
});

describe('domain verification', () => {
  it('serves the ChatGPT directory challenge only when configured', async () => {
    const path = '/.well-known/openai-apps-challenge';
    expect((await fetch(`${baseUrl}${path}`)).status).toBe(404);
    process.env.OPENAI_APPS_CHALLENGE = 'token-abc';
    try {
      const res = await fetch(`${baseUrl}${path}`);
      expect(await res.text()).toBe('token-abc');
      expect(res.headers.get('content-type')).toContain('text/plain');
    } finally {
      delete process.env.OPENAI_APPS_CHALLENGE;
    }
  });
});
