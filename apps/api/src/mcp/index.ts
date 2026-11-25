/// <reference path="../types/express.d.ts" />
import { Readable } from 'stream';
import type { ReadableStream as NodeReadableStream } from 'stream/web';
import cors from 'cors';
import express, { Express, NextFunction, Request, Response } from 'express';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { requireAuth } from '../middleware/auth';
import { createRateLimiter, defaultCallerKey } from '../middleware/rate-limiter';
import { mcpResourceUrl, protectedResourceMetadataUrl } from './config';
import { dispatchInProcess } from './in-process';
import { authorizationServerMetadata, createOAuthRouter, protectedResourceMetadata } from './oauth';
import { ApiCall, buildMcpServer, McpCaller } from './tools';

/**
 * The AMARACUS MCP server: Streamable HTTP at /mcp, stateless, JSON responses.
 *
 * Callers authenticate with a Bearer token only: an access token from the OAuth flow in ./oauth, or
 * an ordinary AMARACUS API key. Cookies and console sessions are never accepted, which is why any
 * Origin may call these routes. Tools run as requests against this same API with the caller's token,
 * so scopes, plans, rate limits, IP allowlists, audit and usage apply exactly as for a direct call.
 */

/** Runs a request through the Express app in-process, from the same client address. */
function apiCallAs(app: Express, req: Request): ApiCall {
  return async (method, path, body) => {
    const headers: Record<string, string> = {
      authorization: req.headers.authorization as string,
      accept: 'application/json',
      'user-agent': `amaracus-mcp (${String(req.headers['user-agent'] || 'unknown').slice(0, 200)})`,
    };
    // Keep the proxy chain so the API sees the real client IP (rate limits, IP allowlists, audit).
    for (const name of ['x-forwarded-for', 'x-forwarded-proto', 'x-request-id']) {
      const value = req.headers[name];
      if (typeof value === 'string') headers[name] = value;
    }
    const res = await dispatchInProcess(app, { method, path, headers, body, remoteAddress: req.socket.remoteAddress });
    let parsed: any = {};
    try {
      parsed = JSON.parse(res.body);
    } catch {
      // An empty or non-JSON answer is handled by its status code.
    }
    return { status: res.status, body: parsed };
  };
}

function challenge(res: Response): void {
  res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${protectedResourceMetadataUrl()}"`);
}

function bearerOnly(req: Request, res: Response, next: NextFunction): void {
  const token = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization || '')?.[1];
  if (!token || !(token.startsWith('am_') || token.startsWith('amk_'))) {
    challenge(res);
    res.status(401).json({
      error: { code: 'UNAUTHENTICATED', message: 'Connect AMARACUS with OAuth, or send an AMARACUS API key as a Bearer token.' },
    });
    return;
  }
  req.headers.authorization = `Bearer ${token}`;
  // requireAuth answers 401 for an unknown, expired or revoked token; clients then need the challenge.
  const json = res.json.bind(res);
  res.json = ((body: any) => {
    if (res.statusCode === 401) {
      res.setHeader(
        'WWW-Authenticate',
        `Bearer error="invalid_token", resource_metadata="${protectedResourceMetadataUrl()}"`
      );
    }
    return json(body);
  }) as Response['json'];
  next();
}

async function sendWebResponse(webRes: globalThis.Response, res: Response): Promise<void> {
  res.status(webRes.status);
  webRes.headers.forEach((value, name) => {
    if (name !== 'content-length' && name !== 'transfer-encoding') res.setHeader(name, value);
  });
  if (!webRes.body) {
    res.end();
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const stream = Readable.fromWeb(webRes.body as unknown as NodeReadableStream);
    res.on('close', () => {
      stream.destroy();
      resolve();
    });
    stream.on('error', reject);
    stream.pipe(res);
  });
}

const mcpHandler = createMcpHandler(
  (ctx) => buildMcpServer(ctx.authInfo!.extra!.caller as McpCaller),
  { responseMode: 'json', maxSubscriptions: 0, onerror: (err) => console.error('[MCP]', err?.message || err) }
);

/** Mount before the API's own CORS, body parsing and sanitizing middleware. */
export function mountMcp(app: Express): void {
  const openCors = cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Mcp-Session-Id', 'Mcp-Protocol-Version', 'Last-Event-ID', 'Mcp-Method', 'Mcp-Name'],
    exposedHeaders: ['WWW-Authenticate', 'Mcp-Session-Id', 'Mcp-Protocol-Version'],
    maxAge: 86400,
  });

  const metadata = (document: () => object) => (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json(document());
  };
  app.use('/.well-known', openCors);
  app.get('/.well-known/oauth-protected-resource', metadata(protectedResourceMetadata));
  app.get('/.well-known/oauth-protected-resource/mcp', metadata(protectedResourceMetadata));
  app.get('/.well-known/oauth-authorization-server', metadata(authorizationServerMetadata));
  app.get('/.well-known/oauth-authorization-server/mcp', metadata(authorizationServerMetadata));
  // Domain verification for the ChatGPT plugin directory; 404 until a token is configured.
  app.get('/.well-known/openai-apps-challenge', (_req, res) => {
    const token = process.env.OPENAI_APPS_CHALLENGE?.trim();
    if (!token) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found.' } });
    res.setHeader('Cache-Control', 'no-store');
    return res.type('text/plain').send(token);
  });

  app.use('/oauth', openCors, createOAuthRouter());

  app.options('/mcp', openCors);
  // Stateless server: there is no session to stream from (GET) or to end (DELETE).
  app.all('/mcp', openCors, (req: Request, res: Response, next: NextFunction) => {
    if (req.method === 'POST') return next();
    if (req.method === 'GET' && /text\/html/.test(req.headers.accept || '') && !req.headers.authorization) {
      return res.status(405).type('text/plain').send(`This is an MCP endpoint. Add ${mcpResourceUrl()} to your MCP client.`);
    }
    if (!req.headers.authorization) challenge(res);
    res.setHeader('Allow', 'POST, OPTIONS');
    return res
      .status(req.headers.authorization ? 405 : 401)
      .json({ jsonrpc: '2.0', error: { code: -32000, message: 'Use POST.' }, id: null });
  });
  app.post(
    '/mcp',
    createRateLimiter({ limit: 600, keyGenerator: (req) => `mcp-ip:${req.ip || 'unknown'}` }),
    bearerOnly,
    requireAuth,
    createRateLimiter({ limit: 300, keyGenerator: (req) => `mcp:${defaultCallerKey(req)}` }),
    express.json({ limit: '1mb' }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const caller: McpCaller = {
          call: apiCallAs(app, req),
          scopes: req.apiKey!.scopes || [],
          connectionName: req.apiKey!.name,
        };
        const headers = new Headers();
        for (const [name, value] of Object.entries(req.headers)) {
          if (typeof value === 'string' && name !== 'cookie' && name !== 'content-length' && name !== 'host') headers.set(name, value);
        }
        const request = new globalThis.Request(mcpResourceUrl(), { method: 'POST', headers, body: JSON.stringify(req.body) });
        const token = req.headers.authorization!.slice('Bearer '.length);
        const response = await mcpHandler.fetch(request, {
          parsedBody: req.body,
          authInfo: { token, clientId: req.apiKey!.id, scopes: caller.scopes, extra: { caller } },
        });
        res.setHeader('Cache-Control', 'no-store');
        await sendWebResponse(response, res);
      } catch (err) {
        next(err);
      }
    }
  );
}
