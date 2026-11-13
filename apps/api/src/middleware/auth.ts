/// <reference path="../types/express.d.ts" />
import { Request, Response, NextFunction } from 'express';
import { db } from '../lib/data-store';
import { hasPermission, Permission, Role, roleHasScope } from '../lib/permissions';
import { hashApiKey, hasRequiredScope } from '../lib/api-keys';
import { sessionExpiryFrom, shouldExtendSession } from '../lib/session-policy';
import { isIpAllowed } from '../lib/ip-allowlist';
import { isKeyAutoLocked } from '../lib/decrypt-alerts';
import { currentRequestContext } from '../lib/request-context';

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const requestId = (req as any).requestId;
  let token: string | undefined;

  // 1. Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  }

  // 2. Fallback to session cookie
  if (!token && req.cookies) {
    token = req.cookies.sessionToken || req.cookies['better-auth.session_token'];
  }

  if (!token) {
    res.status(401).json({
      error: {
        code: 'UNAUTHENTICATED',
        message: 'Authentication required. Please provide a valid Bearer token or API key.',
        requestId,
      },
    });
    return;
  }

  // Check if token is an API key (am_... or amk_...)
  if (token.startsWith('am_') || token.startsWith('amk_')) {
    const keyHash = hashApiKey(token);
    const credential = await db.findCredentialByHash(keyHash);

    if (!credential) {
      res.status(401).json({
        error: {
          code: 'INVALID_API_KEY',
          message: 'The provided API key is invalid or does not exist.',
          requestId,
        },
      });
      return;
    }

    if (credential.status === 'REVOKED' || credential.revokedAt) {
      res.status(401).json({
        error: {
          code: 'API_KEY_REVOKED',
          message: 'The provided API key has been revoked and can no longer be used.',
          requestId,
        },
      });
      return;
    }

    if (credential.status === 'DISABLED' || isKeyAutoLocked(credential.id)) {
      res.status(401).json({
        error: {
          code: 'API_KEY_DISABLED',
          message: 'The provided API key is currently disabled.',
          requestId,
        },
      });
      return;
    }

    if (credential.expiresAt && new Date(credential.expiresAt) < new Date()) {
      res.status(401).json({
        error: {
          code: 'API_KEY_EXPIRED',
          message: 'The provided API key has expired.',
          requestId,
        },
      });
      return;
    }

    // Optional IP allowlist: a key copied off its server is refused from anywhere else.
    if (!isIpAllowed(req.ip, credential.allowedIps)) {
      res.status(403).json({
        error: {
          code: 'IP_NOT_ALLOWED',
          message: 'This API key cannot be used from your IP address. Add it to the key\'s allowed IPs in the console (API Keys).',
          requestId,
        },
      });
      return;
    }

    // Set credential context on request
    req.apiKey = credential;
    currentRequestContext().apiKeyId = credential.id;
    req.organizationId = credential.organizationId || undefined;
    req.projectId = credential.projectId || undefined;
    req.environmentId = credential.environmentId;
    // API keys carry no organization role: they are authorized only by their stored scopes.
    req.orgRole = undefined;

    // Asynchronously record lastUsedAt
    db.updateCredentialLastUsed(credential.id).catch(() => {});

    next();
    return;
  }

  // Fallback: User session token
  const session = await db.findSessionByToken(token);
  if (!session) {
    res.status(401).json({
      error: {
        code: 'UNAUTHENTICATED',
        message: 'Invalid or expired session.',
        requestId,
      },
    });
    return;
  }

  const user = await db.findUserById(session.userId);
  if (!user) {
    res.status(401).json({
      error: {
        code: 'UNAUTHENTICATED',
        message: 'User associated with session not found.',
        requestId,
      },
    });
    return;
  }

  // Sliding idle window: activity keeps the session alive for another 30 days.
  if (shouldExtendSession(session.expiresAt)) {
    const expiresAt = sessionExpiryFrom();
    try {
      await db.extendSession(token, expiresAt);
      session.expiresAt = expiresAt;
      if (req.cookies?.sessionToken === token) {
        res.cookie('sessionToken', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          expires: expiresAt,
        });
      }
    } catch (err) {
      // Not extending is safe: the session still works until its current expiry.
      console.warn('[Auth] Could not extend session expiry:', (err as Error)?.message);
    }
  }

  req.user = user;
  req.session = session;
  req.organizationId = session.activeOrgId || undefined;
  next();
}

export async function requireOrgMember(req: Request, res: Response, next: NextFunction): Promise<void> {
  const requestId = (req as any).requestId;

  // If request is authenticated via API Key:
  if (req.apiKey) {
    const credOrgId = req.apiKey.organizationId;
    // Check if URL or header specifies a target orgId
    const requestedOrgId =
      (req.params.orgId as string) ||
      (req.headers['x-organization-id'] as string) ||
      (req.query.orgId as string) ||
      (req.query.organizationId as string);

    if (!credOrgId || (requestedOrgId && requestedOrgId !== credOrgId)) {
      res.status(403).json({
        error: {
          code: 'TENANT_ACCESS_DENIED',
          message: 'API key is not authorized for the requested organization.',
          requestId,
        },
      });
      return;
    }

    req.organizationId = credOrgId;
    req.orgRole = undefined;
    next();
    return;
  }

  // User session authentication
  if (!req.user) {
    res.status(401).json({
      error: { code: 'UNAUTHENTICATED', message: 'Authentication required', requestId },
    });
    return;
  }

  // Extract organizationId from params, header, query, body, or provider lookup
  let orgId =
    (req.params.orgId as string) ||
    (req.headers['x-organization-id'] as string) ||
    (req.query.orgId as string) ||
    (req.query.organizationId as string) ||
    (req.body && req.body.organizationId) ||
    req.session?.activeOrgId;

  if (!orgId && (req.params.providerId || req.params.id)) {
    const provId = (req.params.providerId || req.params.id) as string;
    try {
      const provider = await db.findCustomerProviderById(provId);
      if (provider) {
        orgId = provider.organizationId;
      }
    } catch {}
  }

  if (!orgId) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',
        message: 'Organization ID is required in URL path, x-organization-id header, query, or active session.',
        requestId,
      },
    });
    return;
  }

  const org = await db.findOrgById(orgId);
  if (!org) {
    res.status(404).json({
      error: { code: 'RESOURCE_NOT_FOUND', message: 'Organization not found', requestId },
    });
    return;
  }

  const membership = await db.getMember(orgId, req.user.id);
  if (!membership) {
    res.status(403).json({
      error: {
        code: 'FORBIDDEN',
        message: 'You are not a member of this organization.',
        requestId,
      },
    });
    return;
  }

  req.organizationId = orgId;
  req.orgRole = membership.role as Role;
  req.membership = membership;
  next();
}

export function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const requestId = (req as any).requestId;

    // If authenticated with API Key:
    if (req.apiKey) {
      if (!hasRequiredScope(req.apiKey.scopes, scope)) {
        res.status(403).json({
          error: {
            code: 'INSUFFICIENT_SCOPE',
            message: `API credential lacks required scope '${scope}'. Granted scopes: [${(req.apiKey.scopes || []).join(', ')}]`,
            requestId,
          },
        });
        return;
      }
      next();
      return;
    }

    // If authenticated with user session: the organization role must grant the scope
    if (req.user) {
      if (!roleHasScope(req.orgRole, scope)) {
        res.status(403).json({
          error: {
            code: 'FORBIDDEN',
            message: `Role '${req.orgRole}' is not permitted to perform '${scope}'.`,
            requestId,
          },
        });
        return;
      }
      next();
      return;
    }

    res.status(401).json({
      error: {
        code: 'UNAUTHENTICATED',
        message: 'Authentication required to evaluate scope permissions.',
        requestId,
      },
    });
  };
}

export function requireOrgPermission(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.apiKey) {
      if (!hasRequiredScope(req.apiKey.scopes, permission)) {
        res.status(403).json({
          error: {
            code: 'INSUFFICIENT_SCOPE',
            message: `API credential lacks required scope '${permission}'. Granted scopes: [${(req.apiKey.scopes || []).join(', ')}]`,
            requestId: (req as any).requestId,
          },
        });
        return;
      }
      next();
      return;
    }

    if (!req.orgRole) {
      res.status(403).json({
        error: { code: 'FORBIDDEN', message: 'Organization role context missing' },
      });
      return;
    }

    if (!hasPermission(req.orgRole, permission)) {
      res.status(403).json({
        error: {
          code: 'FORBIDDEN',
          message: `Insufficient permissions. Role '${req.orgRole}' lacks '${permission}'.`,
        },
      });
      return;
    }

    next();
  };
}

export async function validateOwnershipChain(req: Request, res: Response, next: NextFunction): Promise<void> {
  const { orgId, projectId, envId } = req.params;

  if (projectId) {
    const project = await db.getProjectById(projectId);
    if (!project || (orgId && project.organizationId !== orgId)) {
      res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'Project not found within this organization.',
        },
      });
      return;
    }
    req.project = project;
  }

  if (envId) {
    const env = await db.getEnvironmentById(envId);
    if (!env || (req.project && env.projectId !== req.project.id)) {
      res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'Environment not found within this project.',
        },
      });
      return;
    }
    req.environment = env;
  }

  next();
}
