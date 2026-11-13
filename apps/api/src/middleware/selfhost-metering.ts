import { Request, Response, NextFunction } from 'express';
import { isSelfHosted } from '../lib/edition';
import { usageMeter } from '../lib/usage-meter';
import { requestOperationName } from '../lib/selfhost-license';
import { selfHostGateBlocks } from './billing-guard';

/**
 * Self-hosted only; no effect on AMARACUS Cloud, whose billing for these routes is unchanged.
 *
 * Some routes perform billable operations (AMARACUS Additional Commercial Terms, section 5) that
 * the Cloud meter has never counted: operations with a managed key under /keys/:keyId, PKI
 * authority creation, certificate renewal and CSR signing, and BYOK operations. On a self-hosted
 * installation these two middlewares put them under the licence gate and into the usage ledger.
 */
export function selfHostGate() {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!isSelfHosted()) return next();
    try {
      if (await selfHostGateBlocks(req, res, 1, true)) return;
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Records one billable operation when the response succeeds (2xx). */
export function selfHostMeterOnSuccess(operationType?: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isSelfHosted()) return next();
    const type = (operationType || requestOperationName(req) || 'OPERATION').toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    res.on('finish', () => {
      const orgId = (req as any).organizationId || (req as any).apiKey?.organizationId;
      if (!orgId || res.statusCode < 200 || res.statusCode >= 300) return;
      usageMeter
        .recordOperation({
          organizationId: orgId,
          operationType: type,
          quantity: 1,
          operationId: (req.headers['idempotency-key'] as string) || (req as any).requestId,
          keyId: req.params?.keyId,
        })
        .catch((err) => console.warn('[Usage Ledger] Could not record operation:', err?.message || err));
    });
    next();
  };
}
