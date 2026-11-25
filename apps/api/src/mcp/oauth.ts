import crypto from 'crypto';
import express, { NextFunction, Request, Response, Router } from 'express';
import { db } from '../lib/data-store';
import { hashApiKey } from '../lib/api-keys';
import { roleHasScope } from '../lib/permissions';
import { requireAuth, requireOrgMember } from '../middleware/auth';
import { requirePaidPlan } from '../middleware/billing-guard';
import { consumeOnce, createRateLimiter } from '../middleware/rate-limiter';
import { sendCaughtError } from '../middleware/response-formatter';
import { consentPageUrl, MCP_SCOPES, MCP_SCOPE_IDS, mcpBaseUrl, mcpResourceUrl } from './config';
import { isAllowedRedirectUri, isLoopbackRedirect, redirectDestination, redirectUriMatches } from './redirect-uris';
import { seal, unseal } from './sealed-token';

/**
 * OAuth 2.1 authorization server for the MCP endpoint: authorization code with PKCE (S256),
 * dynamic client registration (RFC 7591), refresh token rotation and revocation (RFC 7009).
 * All clients are public clients.
 *
 * A granted connection is an ordinary API credential: it is limited to the scopes the user ticked
 * and to one environment, its access token is that credential's secret, and the user can see and
 * revoke it on the console's API Keys page like any other key.
 */
export const ACCESS_TOKEN_SECONDS = 60 * 60;
export const REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60;
export const MCP_TOKEN_PREFIX = 'am_mcp_';
const REQUEST_SECONDS = 15 * 60;
const CODE_SECONDS = 120;
const REUSE_GRACE_MS = 60_000;

interface ClientPayload {
  name: string;
  uris: string[];
}
interface RequestPayload {
  clientId: string;
  clientName: string;
  redirectUri: string;
  challenge: string;
  scopes: string[];
  state?: string;
}
interface CodePayload extends Omit<RequestPayload, 'state'> {
  jti: string;
  userId: string;
  organizationId: string;
  projectId: string;
  environmentId: string;
}
interface RefreshPayload {
  credentialId: string;
  clientId: string;
  /** Hash of the access token this refresh token was issued with; changes at every rotation. */
  keyHash: string;
}

export function generateMcpAccessToken(): { token: string; prefix: string; keyHash: string } {
  const entropy = crypto.randomBytes(32).toString('hex');
  const prefix = `${MCP_TOKEN_PREFIX}${entropy.slice(0, 8)}`;
  const token = `${prefix}_${entropy.slice(8)}`;
  return { token, prefix, keyHash: hashApiKey(token) };
}

/** Client IDs are long sealed strings; tokens and codes carry only their digest. */
function clientDigest(clientId: unknown): string {
  return crypto.createHash('sha256').update(String(clientId)).digest('base64url');
}

function cleanName(value: unknown): string {
  const name = typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩<>]/g, '').trim().slice(0, 80) : '';
  return name || 'Unnamed app';
}

function oauthError(res: Response, status: number, error: string, description: string) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json({ error, error_description: description });
}

function single(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** Accepts the MCP endpoint, with or without a trailing slash, and the API origin itself. */
function isKnownResource(resource: string): boolean {
  const r = resource.replace(/\/+$/, '');
  return r === mcpResourceUrl() || r === mcpBaseUrl();
}

function requestedScopes(raw: string | undefined): string[] {
  const asked = (raw || '').split(/\s+/).filter((s) => MCP_SCOPE_IDS.includes(s));
  return asked.length ? [...new Set(asked)] : [...MCP_SCOPE_IDS];
}

export function authorizationServerMetadata() {
  const base = mcpBaseUrl();
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    revocation_endpoint: `${base}/oauth/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    scopes_supported: [...MCP_SCOPE_IDS, 'offline_access'],
    authorization_response_iss_parameter_supported: true,
  };
}

export function protectedResourceMetadata() {
  return {
    resource: mcpResourceUrl(),
    resource_name: 'AMARACUS',
    authorization_servers: [mcpBaseUrl()],
    scopes_supported: MCP_SCOPE_IDS,
    bearer_methods_supported: ['header'],
  };
}

async function audit(
  req: Request,
  action: string,
  organizationId: string | null | undefined,
  userId: string | null | undefined,
  resourceId: string,
  metadata: Record<string, unknown>
) {
  await db.createAuditEvent({
    organizationId: organizationId || undefined,
    userId: userId || undefined,
    action,
    resourceType: 'ApiCredential',
    resourceId,
    metadata,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });
}

function sendTokens(res: Response, token: string, refreshPayload: RefreshPayload, scopes: string[]) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  return res.status(200).json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_SECONDS,
    refresh_token: seal('refresh', refreshPayload, REFRESH_TOKEN_SECONDS),
    scope: scopes.join(' '),
  });
}

/** The person who approved the connection must still be a member whose role allows it. */
async function grantStillAllowed(userId: string, organizationId: string, scopes: string[]): Promise<boolean> {
  const member = await db.getMember(organizationId, userId);
  return !!member && roleHasScope(member.role, 'credentials:manage') && scopes.every((s) => roleHasScope(member.role, s));
}

function accessExpiry(): Date {
  return new Date(Date.now() + ACCESS_TOKEN_SECONDS * 1000);
}

async function exchangeCode(req: Request, res: Response, body: any) {
  const invalid = () => oauthError(res, 400, 'invalid_grant', 'The authorization code is invalid, expired or already used.');
  const code = unseal<CodePayload>('code', body.code);
  if (!code || code.clientId !== clientDigest(body.client_id)) return invalid();
  if (body.redirect_uri !== undefined && body.redirect_uri !== code.redirectUri) return invalid();
  const verifier = single(body.code_verifier);
  if (!verifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return invalid();
  const computed = Buffer.from(crypto.createHash('sha256').update(verifier).digest('base64url'));
  const expected = Buffer.from(code.challenge);
  if (computed.length !== expected.length || !crypto.timingSafeEqual(computed, expected)) return invalid();
  if (!(await consumeOnce(`mcp-code:${code.jti}`, 60 * 60 * 1000))) return invalid();
  if (!(await grantStillAllowed(code.userId, code.organizationId, code.scopes))) return invalid();

  const { token, prefix, keyHash } = generateMcpAccessToken();
  const credential = await db.createApiCredential({
    organizationId: code.organizationId,
    projectId: code.projectId,
    environmentId: code.environmentId,
    name: `MCP: ${code.clientName}`,
    prefix,
    keyHash,
    scopes: code.scopes,
    status: 'ACTIVE',
    createdBy: code.userId,
    expiresAt: accessExpiry(),
  });
  await audit(req, 'mcp_connection.create', code.organizationId, code.userId, credential.id, {
    client: code.clientName,
    prefix,
    environmentId: code.environmentId,
    scopes: code.scopes,
  });
  return sendTokens(res, token, { credentialId: credential.id, clientId: code.clientId, keyHash }, code.scopes);
}

async function refresh(req: Request, res: Response, body: any) {
  const invalid = () => oauthError(res, 400, 'invalid_grant', 'The refresh token is invalid, expired or already used. Connect again.');
  const payload = unseal<RefreshPayload>('refresh', body.refresh_token);
  if (!payload || payload.clientId !== clientDigest(body.client_id)) return invalid();
  const credential = await db.findCredentialById(payload.credentialId);
  // A key the user revoked, disabled or rotated by hand in the console stays that way.
  if (!credential || !credential.prefix.startsWith(MCP_TOKEN_PREFIX)) return invalid();
  if (credential.status !== 'ACTIVE' || credential.revokedAt) return invalid();

  if (credential.keyHash !== payload.keyHash) {
    // A used refresh token came back. Within a minute of the rotation it is a client race; later it
    // means the token leaked, so the whole connection ends.
    const rotatedAt = credential.expiresAt ? new Date(credential.expiresAt).getTime() - ACCESS_TOKEN_SECONDS * 1000 : 0;
    if (Date.now() - rotatedAt > REUSE_GRACE_MS) {
      await db.revokeCredential(credential.id);
      await audit(req, 'mcp_connection.revoke', credential.organizationId, credential.createdBy, credential.id, { by: 'refresh_token_reuse' });
    }
    return invalid();
  }

  const scopes = credential.scopes || [];
  if (!credential.createdBy || !credential.organizationId || !(await grantStillAllowed(credential.createdBy, credential.organizationId, scopes))) {
    await db.revokeCredential(credential.id);
    await audit(req, 'mcp_connection.revoke', credential.organizationId, credential.createdBy, credential.id, { by: 'member_access_changed' });
    return invalid();
  }

  const next = generateMcpAccessToken();
  const rotated = await db.rotateCredentialIfCurrent(credential.id, payload.keyHash, {
    prefix: next.prefix,
    keyHash: next.keyHash,
    expiresAt: accessExpiry(),
  });
  if (!rotated) return invalid();
  return sendTokens(res, next.token, { credentialId: credential.id, clientId: payload.clientId, keyHash: next.keyHash }, scopes);
}

const byIp = (name: string) => (req: Request) => `mcp-oauth:${name}:${req.ip || 'unknown'}`;

/** /oauth/*: called by MCP clients; /oauth/authorize is opened in the user's browser. */
export function createOAuthRouter(): Router {
  const router = Router();
  router.use(express.json({ limit: '32kb' }));
  router.use(express.urlencoded({ limit: '32kb', extended: false }));

  // Dynamic client registration. Stateless: the client ID is the sealed registration itself.
  router.post('/register', createRateLimiter({ limit: 120, keyGenerator: byIp('register') }), (req: Request, res: Response) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every(isAllowedRedirectUri)) {
      return oauthError(
        res,
        400,
        'invalid_redirect_uri',
        'redirect_uris must list 1 to 10 URIs that use https, http on localhost, or a supported editor scheme.'
      );
    }
    const client: ClientPayload = { name: cleanName(body.client_name), uris };
    const clientId = seal('client', client);
    if (clientId.length > 4096) return oauthError(res, 400, 'invalid_client_metadata', 'The registration is too large.');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(201).json({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: client.name,
      redirect_uris: uris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: MCP_SCOPE_IDS.join(' '),
    });
  });

  // Authorization endpoint. Validates the request, then hands over to the console's consent page.
  router.get('/authorize', createRateLimiter({ limit: 60, keyGenerator: byIp('authorize') }), (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const clientId = single(req.query.client_id);
    const client = unseal<ClientPayload>('client', clientId);
    // Until the client and redirect URI are verified, errors are shown here and never redirected.
    if (!client) {
      return oauthError(res, 400, 'invalid_client', 'Unknown client_id. Remove the connection in your app and add it again.');
    }
    const redirectUri = single(req.query.redirect_uri) || (client.uris.length === 1 ? client.uris[0] : undefined);
    if (!redirectUri || !isAllowedRedirectUri(redirectUri) || !redirectUriMatches(client.uris, redirectUri)) {
      return oauthError(res, 400, 'invalid_request', 'redirect_uri does not match the registered client.');
    }

    const state = single(req.query.state);
    const fail = (error: string, description: string) => {
      const to = new URL(redirectUri);
      to.searchParams.set('error', error);
      to.searchParams.set('error_description', description);
      if (state !== undefined) to.searchParams.set('state', state);
      to.searchParams.set('iss', mcpBaseUrl());
      return res.redirect(302, to.toString());
    };
    if (state !== undefined && state.length > 2048) return fail('invalid_request', 'state is too long.');
    if (req.query.response_type !== 'code') return fail('unsupported_response_type', 'Only response_type=code is supported.');
    const challenge = single(req.query.code_challenge);
    if (!challenge || !/^[A-Za-z0-9_-]{43}$/.test(challenge) || req.query.code_challenge_method !== 'S256') {
      return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required.');
    }
    const resource = req.query.resource;
    if (resource !== undefined && (typeof resource !== 'string' || !isKnownResource(resource))) {
      return fail('invalid_target', 'Unknown resource.');
    }

    const request: RequestPayload = {
      clientId: clientDigest(clientId),
      clientName: client.name,
      redirectUri,
      challenge,
      scopes: requestedScopes(single(req.query.scope)),
      ...(state === undefined ? {} : { state }),
    };
    return res.redirect(302, consentPageUrl(seal('request', request, REQUEST_SECONDS)));
  });

  router.post('/token', createRateLimiter({ limit: 300, keyGenerator: byIp('token') }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body && typeof req.body === 'object' ? req.body : {};
      if (body.resource !== undefined && (typeof body.resource !== 'string' || !isKnownResource(body.resource))) {
        return oauthError(res, 400, 'invalid_target', 'Unknown resource.');
      }
      if (body.grant_type === 'authorization_code') return await exchangeCode(req, res, body);
      if (body.grant_type === 'refresh_token') return await refresh(req, res, body);
      return oauthError(res, 400, 'unsupported_grant_type', 'Use authorization_code or refresh_token.');
    } catch (err) {
      return next(err);
    }
  });

  // Revocation (RFC 7009): answers 200 whether or not the token was known.
  router.post('/revoke', createRateLimiter({ limit: 120, keyGenerator: byIp('revoke') }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = single(req.body?.token);
      const payload = unseal<RefreshPayload>('refresh', token);
      const credential = payload
        ? await db.findCredentialById(payload.credentialId)
        : token?.startsWith(MCP_TOKEN_PREFIX)
          ? await db.findCredentialByHash(hashApiKey(token))
          : null;
      if (
        credential &&
        credential.prefix.startsWith(MCP_TOKEN_PREFIX) &&
        credential.status !== 'REVOKED' &&
        (!payload || payload.keyHash === credential.keyHash)
      ) {
        await db.revokeCredential(credential.id);
        await audit(req, 'mcp_connection.revoke', credential.organizationId, credential.createdBy, credential.id, { by: 'client' });
      }
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json({});
    } catch (err) {
      return next(err);
    }
  });

  return router;
}

/** /v1/mcp-connect: used by the console's consent page. Approving needs the user's own session. */
export function createConsentRouter(): Router {
  const router = Router();
  const limiter = createRateLimiter({ limit: 60 });

  // An API key must never be able to approve a new connection for itself.
  const sessionOnly = (req: Request, res: Response, next: NextFunction) => {
    if (req.apiKey || !req.user) {
      res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Sign in to the console to approve a connection.' } });
      return;
    }
    next();
  };

  const readRequest = (req: Request, res: Response): RequestPayload | null => {
    const request = unseal<RequestPayload>('request', req.body?.request);
    if (!request) {
      res.status(400).json({
        error: { code: 'REQUEST_EXPIRED', message: 'This connection request is invalid or has expired. Start again from your app.' },
      });
    }
    return request;
  };

  const back = (request: RequestPayload, params: Record<string, string>) => {
    const to = new URL(request.redirectUri);
    for (const [k, v] of Object.entries(params)) to.searchParams.set(k, v);
    if (request.state !== undefined) to.searchParams.set('state', request.state);
    to.searchParams.set('iss', mcpBaseUrl());
    return to.toString();
  };

  // What is being asked for. Shown before sign-in.
  router.post('/request', limiter, (req: Request, res: Response) => {
    const request = readRequest(req, res);
    if (!request) return;
    res.json({
      data: {
        clientName: request.clientName,
        destination: redirectDestination(request.redirectUri),
        isLocalApp: isLoopbackRedirect(request.redirectUri),
        scopes: MCP_SCOPES.filter((s) => request.scopes.includes(s.id)),
      },
    });
  });

  router.post('/deny', limiter, (req: Request, res: Response) => {
    const request = readRequest(req, res);
    if (!request) return;
    res.json({ data: { redirectTo: back(request, { error: 'access_denied', error_description: 'The user declined.' }) } });
  });

  router.post('/approve', limiter, requireAuth, sessionOnly, requireOrgMember, requirePaidPlan(), async (req: Request, res: Response) => {
    try {
      const request = readRequest(req, res);
      if (!request) return;
      const { environmentId, scopes } = req.body;
      if (!Array.isArray(scopes) || scopes.length === 0 || !scopes.every((s) => request.scopes.includes(s))) {
        return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Choose at least one of the requested permissions.' } });
      }
      const missing = ['credentials:manage', ...scopes].filter((s) => !roleHasScope(req.orgRole, s));
      if (missing.length) {
        return res.status(403).json({
          error: { code: 'FORBIDDEN', message: `Your role in this organization does not allow: ${missing.join(', ')}.` },
        });
      }
      const environment = typeof environmentId === 'string' ? await db.getEnvironmentById(environmentId) : null;
      const project = environment ? await db.getProjectById(environment.projectId) : null;
      if (!environment || !project || project.organizationId !== req.organizationId) {
        return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Environment not found in this organization.' } });
      }
      const { state: _state, ...rest } = request;
      const code: CodePayload = {
        ...rest,
        scopes: [...new Set(scopes as string[])],
        jti: crypto.randomUUID(),
        userId: req.user!.id,
        organizationId: req.organizationId!,
        projectId: project.id,
        environmentId: environment.id,
      };
      res.setHeader('Cache-Control', 'no-store');
      return res.json({ data: { redirectTo: back(request, { code: seal('code', code, CODE_SECONDS) }) } });
    } catch (err) {
      return sendCaughtError(res, err, 'INTERNAL_ERROR', 'Could not approve the connection.');
    }
  });

  return router;
}
