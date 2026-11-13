import { Request, Response, NextFunction } from 'express';
import { getPlatformAdminEmails } from '../lib/runtime-config';

/**
 * Platform-wide administration (cross-tenant exports, moderation, agent dispatch).
 * Organization roles never grant this: the caller must be a signed-in user whose
 * email is listed in PLATFORM_ADMIN_EMAILS. Accounts only exist after OTP email
 * verification, so the listed address is proven. API keys are always rejected.
 * Must run after requireAuth.
 */
export function requirePlatformAdmin(req: Request, res: Response, next: NextFunction): void {
  const requestId = (req as any).requestId;
  const user = req.user as any;

  if (req.apiKey || !user) {
    res.status(403).json({
      error: { code: 'PLATFORM_ADMIN_REQUIRED', message: 'Platform administrator session required.', requestId },
    });
    return;
  }

  const email = String(user.email || '').toLowerCase();
  if (!email || !getPlatformAdminEmails().has(email)) {
    res.status(403).json({
      error: { code: 'PLATFORM_ADMIN_REQUIRED', message: 'Platform administrator privileges required.', requestId },
    });
    return;
  }

  next();
}
