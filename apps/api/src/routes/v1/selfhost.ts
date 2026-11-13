import { Router, Request, Response, NextFunction } from 'express';
import { requireAuth } from '../../middleware/auth';
import { sendSuccess } from '../../middleware/response-formatter';
import { getPlatformAdminEmails } from '../../lib/runtime-config';
import { db } from '../../lib/data-store';
import {
  LicenseError,
  addLicenseKey,
  getAcceptance,
  getLicenseDocuments,
  getSelfHostUsage,
  isActivated,
  listLicenseKeys,
  recordAcceptance,
} from '../../lib/selfhost-license';
import { getLedgerHead, listLedgerEntries, verifyLedger } from '../../lib/usage-ledger';

/**
 * Self-hosted edition only (mounted at /v1/selfhost when AMARACUS_EDITION is selfhosted):
 * licence acceptance ("activation"), licence keys, and the local usage ledger.
 *
 * Nothing here talks to AMARACUS. Licence keys are verified offline; the ledger stays in the
 * customer's own database and is exported only when the customer downloads it.
 */
const router = Router();

function fail(res: Response, err: any) {
  const requestId = (res.req as any)?.requestId;
  if (err instanceof LicenseError) {
    return res.status(err.status).json({ error: { code: err.code, message: err.message, requestId } });
  }
  // Prisma cannot reach Postgres: say so instead of a generic 500.
  const name = String(err?.name || err?.constructor?.name || '');
  if (name === 'DatabaseUnavailableError' || name.startsWith('PrismaClientInitialization') || err?.code === 'P1001') {
    return res.status(503).json({ error: { code: 'DATABASE_UNAVAILABLE', message: 'The database is not reachable.', requestId } });
  }
  console.error('[SelfHost] Request failed:', err);
  return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred', requestId } });
}

/** Runs requireAuth without letting it answer: a missing or expired session is not an error here. */
async function tryAuth(req: Request): Promise<boolean> {
  const hasCredential = Boolean(req.headers.authorization || req.cookies?.sessionToken || req.cookies?.['better-auth.session_token']);
  if (!hasCredential) return false;
  let passed = false;
  const probe: any = {
    req,
    status: () => probe,
    json: () => probe,
    send: () => probe,
    end: () => probe,
    setHeader: () => probe,
    cookie: () => probe,
    clearCookie: () => probe,
  };
  try {
    await requireAuth(req, probe as Response, () => {
      passed = true;
    });
  } catch {
    passed = false;
  }
  return passed;
}

/**
 * Accepting licences and adding licence keys binds the organization that runs the
 * installation, so it needs a signed-in person, not an API key. When PLATFORM_ADMIN_EMAILS
 * is set, only those people may do it.
 */
function requireInstallationAdmin(req: Request, res: Response, next: NextFunction): void {
  const requestId = (req as any).requestId;
  const user = req.user as any;
  if (req.apiKey || !user) {
    res.status(403).json({
      error: { code: 'USER_SESSION_REQUIRED', message: 'Sign in to the console as a person; API keys cannot do this.', requestId },
    });
    return;
  }
  const admins = getPlatformAdminEmails();
  if (admins.size > 0 && !admins.has(String(user.email || '').toLowerCase())) {
    res.status(403).json({
      error: {
        code: 'INSTALLATION_ADMIN_REQUIRED',
        message: 'Only the administrators listed in PLATFORM_ADMIN_EMAILS can do this on this installation.',
        requestId,
      },
    });
    return;
  }
  next();
}

async function buildStatus(includePrivate: boolean) {
  const docs = getLicenseDocuments();
  const acceptance = await getAcceptance();
  const activated = await isActivated();
  const status: any = {
    edition: 'selfhosted',
    activated,
    licenses: {
      shield: { title: docs.shield.title, sha256: docs.shield.sha256 },
      commercial: { title: docs.commercial.title, version: docs.commercial.version, sha256: docs.commercial.sha256 },
    },
    acceptance: null,
    telemetry: 'none',
  };
  if (includePrivate) {
    status.acceptance = acceptance
      ? {
          acceptedAt: acceptance.acceptedAt,
          acceptedByEmail: acceptance.acceptedByEmail,
          licensee: acceptance.licensee,
          commercialVersion: acceptance.commercialVersion,
          current: activated,
        }
      : null;
    status.usage = await getSelfHostUsage();
    status.licenseKeys = (await listLicenseKeys()).map((k) => ({
      licenseId: k.licenseId,
      licensee: k.licensee,
      operations: k.operations,
      issuedAt: k.issuedAt,
      expiresAt: k.expiresAt,
      addedAt: k.addedAt,
    }));
  }
  return status;
}

// GET /v1/selfhost/status : public part for everyone, usage and keys for signed-in callers.
router.get('/status', async (req: Request, res: Response) => {
  try {
    return sendSuccess(res, await buildStatus(await tryAuth(req)));
  } catch (err) {
    return fail(res, err);
  }
});

// GET /v1/selfhost/licenses : the two licence texts shipped with this installation.
router.get('/licenses', (_req: Request, res: Response) => {
  try {
    const docs = getLicenseDocuments();
    return sendSuccess(res, { shield: docs.shield, commercial: docs.commercial });
  } catch (err) {
    return fail(res, err);
  }
});

// POST /v1/selfhost/accept : click-to-accept both licences; activates the installation.
router.post('/accept', requireAuth, requireInstallationAdmin, async (req: Request, res: Response) => {
  try {
    const user = req.user as any;
    const acceptance = await recordAcceptance({
      acceptShield: req.body?.acceptShield,
      acceptCommercialTerms: req.body?.acceptCommercialTerms,
      licensee: req.body?.licensee,
      shieldSha256: req.body?.shieldSha256,
      commercialSha256: req.body?.commercialSha256,
      userId: user.id,
      userEmail: user.email,
      ipAddress: req.ip || null,
    });
    await db
      .createAuditEvent({
        organizationId: (req as any).organizationId || null,
        userId: user.id,
        ipAddress: req.ip || null,
        userAgent: (req.headers['user-agent'] as string) || null,
        action: 'selfhost.licenses_accepted',
        resourceType: 'SelfHostLicense',
        resourceId: acceptance.commercialVersion,
        metadata: {
          licensee: acceptance.licensee,
          shieldSha256: acceptance.shieldSha256,
          commercialSha256: acceptance.commercialSha256,
          commercialVersion: acceptance.commercialVersion,
        },
      })
      .catch((err: any) => console.warn('[SelfHost] Could not write the acceptance audit event:', err?.message || err));
    return sendSuccess(res, await buildStatus(true));
  } catch (err) {
    return fail(res, err);
  }
});

// POST /v1/selfhost/license-keys : add a licence key bought from AMARACUS (verified offline).
router.post('/license-keys', requireAuth, requireInstallationAdmin, async (req: Request, res: Response) => {
  try {
    if (!(await isActivated())) {
      throw new LicenseError('LICENSE_ACCEPTANCE_REQUIRED', 'Accept the licences before adding a licence key.', 403);
    }
    const key = typeof req.body?.key === 'string' ? req.body.key : '';
    const stored = await addLicenseKey(key);
    const user = req.user as any;
    await db
      .createAuditEvent({
        organizationId: (req as any).organizationId || null,
        userId: user.id,
        ipAddress: req.ip || null,
        userAgent: (req.headers['user-agent'] as string) || null,
        action: 'selfhost.license_key_added',
        resourceType: 'SelfHostLicenseKey',
        resourceId: stored.licenseId,
        metadata: { licensee: stored.licensee, operations: stored.operations },
      })
      .catch((err: any) => console.warn('[SelfHost] Could not write the licence key audit event:', err?.message || err));
    return sendSuccess(res, await buildStatus(true));
  } catch (err) {
    return fail(res, err);
  }
});

// GET /v1/selfhost/ledger?afterSeq=0&limit=50
router.get('/ledger', requireAuth, requireInstallationAdmin, async (req: Request, res: Response) => {
  try {
    const afterSeq = Math.max(0, parseInt(String(req.query.afterSeq || '0'), 10) || 0);
    const limit = Math.min(1000, Math.max(1, parseInt(String(req.query.limit || '50'), 10) || 50));
    const [entries, head] = await Promise.all([listLedgerEntries(afterSeq, limit), getLedgerHead()]);
    return sendSuccess(res, {
      entries,
      head: head ? { seq: head.seq, cumulativeTotal: head.cumulativeTotal, entryHash: head.entryHash } : null,
    });
  } catch (err) {
    return fail(res, err);
  }
});

// GET /v1/selfhost/ledger/verify : recompute the hash chain.
router.get('/ledger/verify', requireAuth, requireInstallationAdmin, async (_req: Request, res: Response) => {
  try {
    return sendSuccess(res, await verifyLedger());
  } catch (err) {
    return fail(res, err);
  }
});

// GET /v1/selfhost/ledger/export : the whole ledger as JSON Lines, for the customer's records
// or for an audit. The file is produced for the caller; it is not sent anywhere else.
router.get('/ledger/export', requireAuth, requireInstallationAdmin, async (_req: Request, res: Response) => {
  try {
    const acceptance = await getAcceptance();
    const usage = await getSelfHostUsage();
    const verification = await verifyLedger();
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="amaracus-usage-ledger-${new Date().toISOString().slice(0, 10)}.jsonl"`);
    res.write(
      JSON.stringify({
        type: 'header',
        format: 'amaracus-usage-ledger/1',
        exportedAt: new Date().toISOString(),
        licensee: acceptance?.licensee || null,
        usage,
        verification,
      }) + '\n'
    );
    let afterSeq = 0;
    for (;;) {
      const page = await listLedgerEntries(afterSeq, 5000);
      if (page.length === 0) break;
      for (const e of page) res.write(JSON.stringify({ type: 'entry', ...e }) + '\n');
      afterSeq = page[page.length - 1].seq;
    }
    res.end();
  } catch (err) {
    if (res.headersSent) {
      res.end();
      return;
    }
    return fail(res, err);
  }
});

export default router;
