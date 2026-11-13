import { Request, Response, NextFunction } from 'express';
import { db } from '../lib/data-store';

/**
 * Middleware that asynchronously records API usage telemetry.
 * Captures request counts, latencies, status codes, and scopes without recording private payload data or secrets.
 */
export function usageTracker(req: Request, res: Response, next: NextFunction): void {
  // Skip internal health check and static assets
  if (req.path === '/health' || req.path.startsWith('/docs') || req.path.endsWith('.ico')) {
    return next();
  }

  const startTime = Date.now();

  res.on('finish', () => {
    const durationMs = Date.now() - startTime;
    const orgId = req.organizationId || req.apiKey?.organizationId;

    if (orgId) {
      db.recordApiUsage({
        organizationId: orgId,
        projectId: req.projectId || req.apiKey?.projectId,
        environmentId: req.environmentId || req.apiKey?.environmentId,
        credentialId: req.apiKey?.id,
        endpoint: req.baseUrl + req.path,
        method: req.method,
        statusCode: res.statusCode,
        durationMs,
        ipAddress: (req.ip || (req.headers['x-forwarded-for'] as string) || '').split(',')[0].trim(),
        userAgent: req.headers['user-agent'] as string,
      }).catch(() => {
        // Silently swallow telemetry write errors
      });
    }
  });

  next();
}
