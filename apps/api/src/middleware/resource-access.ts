import { Request, Response, NextFunction } from 'express';
import { db } from '../lib/data-store';
import { hasPermission, Permission, Role } from '../lib/permissions';

export function requireResourceAccess(requiredPermission: Permission | string) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const requestId = (req as any).requestId || `req_${Date.now()}`;

    // 1. Resolve the target organization. An org named in the URL, header or query
    //    is the one the handler will act on, so it takes precedence over the
    //    caller's own context and is what membership is checked against.
    const explicitOrgId =
      (req.params.orgId as string) ||
      (req.headers['x-organization-id'] as string) ||
      (req.query.orgId as string) ||
      (req.query.organizationId as string) ||
      undefined;

    let orgId: string | undefined;
    if (req.apiKey) {
      const keyOrgId = req.apiKey.organizationId || undefined;
      if (!keyOrgId || (explicitOrgId && explicitOrgId !== keyOrgId)) {
        res.status(403).json({
          error: {
            code: 'TENANT_ACCESS_DENIED',
            message: 'API key is not authorized for the requested organization.',
            requestId,
          },
        });
        return;
      }
      orgId = keyOrgId;
    } else {
      orgId = explicitOrgId || req.session?.activeOrgId || undefined;
    }

    if (!orgId) {
      res.status(401).json({
        error: {
          code: 'UNAUTHENTICATED',
          message: 'Organization context required.',
          requestId,
        },
      });
      return;
    }

    req.organizationId = orgId;

    // 2. Permission check based on Role or API Key scopes
    if (req.apiKey) {
      const scopes = (req.apiKey.scopes as string[]) || [];
      const hasDirectScope = scopes.includes(requiredPermission) || scopes.includes('*');
      const hasNormalizedScope = hasPermission('OWNER', requiredPermission) && (scopes.includes('admin') || scopes.includes('*'));

      if (!hasDirectScope && !hasNormalizedScope) {
        res.status(403).json({
          error: {
            code: 'INSUFFICIENT_SCOPE',
            message: `API credential lacks required permission '${requiredPermission}'. Granted scopes: [${scopes.join(', ')}]`,
            requestId,
          },
        });
        return;
      }

      // Check project scoping on API key
      const targetProjectId = (req.params.projectId || req.query.projectId || req.body?.projectId) as string | undefined;
      if (req.apiKey.projectId && targetProjectId && req.apiKey.projectId !== targetProjectId) {
        res.status(403).json({
          error: {
            code: 'CROSS_PROJECT_ACCESS_DENIED',
            message: `API key is scoped to project '${req.apiKey.projectId}' and cannot access project '${targetProjectId}'.`,
            requestId,
          },
        });
        return;
      }

      // Check environment scoping on API key
      const targetEnvId = (req.params.envId || req.params.environmentId || req.query.environmentId || req.body?.environmentId) as
        | string
        | undefined;
      if (req.apiKey.environmentId && targetEnvId && req.apiKey.environmentId !== targetEnvId) {
        res.status(403).json({
          error: {
            code: 'CROSS_ENVIRONMENT_ACCESS_DENIED',
            message: `API key is scoped to environment '${req.apiKey.environmentId}' and cannot access environment '${targetEnvId}'.`,
            requestId,
          },
        });
        return;
      }
    } else if (req.user) {
      // User session authorization: verify membership and role
      const membership = await db.getMember(orgId, req.user.id);
      if (!membership) {
        res.status(403).json({
          error: {
            code: 'FORBIDDEN',
            message: `You are not a member of organization '${orgId}'.`,
            requestId,
          },
        });
        return;
      }

      const userRole = (membership.role || 'MEMBER') as Role;
      req.orgRole = userRole;
      req.membership = membership;

      if (!hasPermission(userRole, requiredPermission)) {
        res.status(403).json({
          error: {
            code: 'FORBIDDEN',
            message: `Insufficient permissions. Role '${userRole}' lacks permission '${requiredPermission}'.`,
            requestId,
          },
        });
        return;
      }
    } else {
      res.status(401).json({
        error: {
          code: 'UNAUTHENTICATED',
          message: 'Authentication required to evaluate resource access.',
          requestId,
        },
      });
      return;
    }

    // 3. Ownership Chain & IDOR Defense
    const targetProjectId = (req.params.projectId || req.query.projectId || req.body?.projectId) as string | undefined;
    if (targetProjectId) {
      const project = await db.getProjectById(targetProjectId);
      if (!project || project.organizationId !== orgId) {
        res.status(404).json({
          error: {
            code: 'PROJECT_NOT_FOUND',
            message: `Project '${targetProjectId}' not found within organization '${orgId}'.`,
            requestId,
          },
        });
        return;
      }
      (req as any).project = project;
    }

    const targetEnvId = (req.params.envId || req.params.environmentId || req.query.environmentId || req.body?.environmentId) as
      | string
      | undefined;
    if (targetEnvId) {
      const env = await db.getEnvironmentById(targetEnvId);
      if (!env) {
        res.status(404).json({
          error: {
            code: 'ENVIRONMENT_NOT_FOUND',
            message: `Environment '${targetEnvId}' not found.`,
            requestId,
          },
        });
        return;
      }
      if ((req as any).project && env.projectId !== (req as any).project.id) {
        res.status(404).json({
          error: {
            code: 'ENVIRONMENT_NOT_FOUND',
            message: `Environment '${targetEnvId}' does not belong to project '${(req as any).project.id}'.`,
            requestId,
          },
        });
        return;
      }
      (req as any).environment = env;
    }

    next();
  };
}
