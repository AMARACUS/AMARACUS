import { appUrl, site } from '../../lib/site-config';
import { Router, Request, Response } from 'express';
import {
  verifyUnsubscribeToken,
  addToSuppressionList,
  removeFromSuppressionList,
  isEmailSuppressed,
  EMAIL_CATEGORY_METADATA,
  EmailCategory,
} from '../../lib/email-service';
import { db } from '../../lib/data-store';
import { setUserPreferences } from '../../lib/user-preferences';
import { sendSuccess, sendError } from '../../middleware/response-formatter';
import { requireAuth } from '../../middleware/auth';
import { requirePlatformAdmin } from '../../middleware/platform-admin';

const router = Router();

function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain) return email;
  const visible = local.length <= 2 ? local[0] : `${local.substring(0, 2)}***`;
  return `${visible}@${domain}`;
}

/**
 * GET /api/v1/email/categories
 * Returns the formal classification taxonomy of all emails sent by AMARACUS,
 * their legal bases, whether they are essential, and unsubscribe requirements.
 */
router.get('/categories', (_req: Request, res: Response) => {
  return sendSuccess(res, {
    categories: EMAIL_CATEGORY_METADATA,
    standardsCompliance: {
      rfc8058OneClick: true,
      canSpamAct15USC7701: true,
      gdprArticle7_3: true,
      dpdpa2023Section6: true,
    },
  });
});

/**
 * GET /api/v1/email/unsubscribe
 * Web 1-click frictionless unsubscribe endpoint accessed from email footers.
 * Validates cryptographically signed HMAC-SHA256 token.
 */
router.get('/unsubscribe', async (req: Request, res: Response) => {
  try {
    const token = (req.query.token as string) || (req.query.t as string);
    if (!token) {
      return sendError(
        res,
        400,
        'MISSING_TOKEN',
        'Unsubscribe token is required. Please click the link directly from your email.'
      );
    }

    const verification = verifyUnsubscribeToken(token);
    if (!verification.valid || !verification.email) {
      if (verification.expired) {
        return sendError(
          res,
          400,
          'TOKEN_EXPIRED',
          `This unsubscribe link has expired. Please use the communication settings in your dashboard or contact ${site('privacyEmail')}.`
        );
      }
      return sendError(
        res,
        400,
        'INVALID_TOKEN',
        'Invalid or tampered unsubscribe token. The cryptographic signature does not match.'
      );
    }

    const email = verification.email;
    const category = verification.category || 'ALL_MARKETING';

    // 1. Immediately record in suppression list
    const suppressionRecord = await addToSuppressionList({
      email,
      category,
      source: 'UNSUBSCRIBE_LINK',
      reason: 'Frictionless 1-click unsubscribe via web link',
    });

    // 2. Synchronize with database user preferences if account exists
    let syncedWithAccount = false;
    try {
      const existingUser = await db.findUserByEmail(email);
      if (existingUser) {
        await setUserPreferences(existingUser.id, { marketingEmails: false });
        syncedWithAccount = true;

        await db.createAuditEvent({
          organizationId: null,
          userId: existingUser.id,
          action: 'privacy.marketing_consent_withdrawn',
          resourceType: 'User',
          resourceId: existingUser.id,
          metadata: {
            email,
            source: 'EMAIL_UNSUBSCRIBE_LINK',
            category,
            timestamp: new Date().toISOString(),
            legalBases: ['DPDPA_2023_SEC_6', 'GDPR_ART_7_3', 'CAN_SPAM_ACT'],
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
      }
    } catch (dbErr) {
      console.warn('[EMAIL UNSUBSCRIBE] Could not sync with user account:', dbErr);
    }

    // 3. Return structured response (also compatible with HTML renderers)
    return sendSuccess(res, {
      unsubscribed: true,
      maskedEmail: maskEmail(email),
      category,
      syncedWithAccount,
      suppressedAt: suppressionRecord.suppressedAt,
      message: 'You have been successfully unsubscribed from AMARACUS marketing communications.',
      essentialNoticesNotice:
        'Essential security and account notices (such as verification codes and security incident alerts) will continue to be delivered for your account security under GDPR Art. 6(1)(b) and DPDPA 2023.',
    });
  } catch (error: any) {
    return sendError(res, 500, 'INTERNAL_ERROR', 'Failed to process unsubscribe request.', error.message);
  }
});

/**
 * POST /api/v1/email/unsubscribe
 * RFC 8058 One-Click Unsubscribe Endpoint used by automated mail clients (e.g. Gmail, Yahoo).
 * Expects List-Unsubscribe=One-Click in POST body or token in query/body.
 */
router.post('/unsubscribe', async (req: Request, res: Response) => {
  try {
    const token =
      (req.query.token as string) ||
      (req.body && req.body.token) ||
      (req.query.t as string);

    if (!token) {
      return sendError(res, 400, 'MISSING_TOKEN', 'Unsubscribe token is required for RFC 8058 processing.');
    }

    const verification = verifyUnsubscribeToken(token);
    if (!verification.valid || !verification.email) {
      return sendError(
        res,
        400,
        verification.expired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
        verification.error || 'Invalid token for RFC 8058 unsubscribe.'
      );
    }

    const email = verification.email;
    const category = verification.category || 'ALL_MARKETING';

    // 1. Immediately record in suppression list with RFC 8058 audit source
    await addToSuppressionList({
      email,
      category,
      source: 'ONE_CLICK_POST',
      reason: 'RFC 8058 Mail-Client One-Click Header Trigger',
    });

    // 2. Synchronize user profile preferences if registered
    try {
      const existingUser = await db.findUserByEmail(email);
      if (existingUser) {
        await setUserPreferences(existingUser.id, { marketingEmails: false });

        await db.createAuditEvent({
          organizationId: null,
          userId: existingUser.id,
          action: 'privacy.marketing_consent_withdrawn',
          resourceType: 'User',
          resourceId: existingUser.id,
          metadata: {
            email,
            source: 'RFC_8058_ONE_CLICK_POST',
            category,
            timestamp: new Date().toISOString(),
            legalBases: ['DPDPA_2023_SEC_6', 'GDPR_ART_7_3', 'RFC_8058'],
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
      }
    } catch (err) {
      console.warn('[EMAIL UNSUBSCRIBE RFC 8058] DB sync error:', err);
    }

    // RFC 8058 requires a prompt HTTP 200 response
    return sendSuccess(res, {
      unsubscribed: true,
      standard: 'RFC_8058',
      maskedEmail: maskEmail(email),
      category,
      message: 'Unsubscribed successfully via RFC 8058 one-click protocol.',
    });
  } catch (error: any) {
    return sendError(res, 500, 'INTERNAL_ERROR', 'Failed to process RFC 8058 unsubscribe.', error.message);
  }
});

/**
 * POST /api/v1/email/resubscribe
 * Opts user back into technical updates if they unsubscribed by accident. Requires the signed
 * token from the unsubscribe link: a typed address would let anyone opt anyone in, and record
 * it as consent.
 */
router.post('/resubscribe', async (req: Request, res: Response) => {
  try {
    const token = req.body?.token;
    if (!token || typeof token !== 'string') {
      return sendError(res, 400, 'MISSING_TOKEN', 'Re-subscribing needs the token from your unsubscribe link.');
    }
    const verification = verifyUnsubscribeToken(token);
    if (!verification.valid || !verification.email) {
      return sendError(res, 400, 'INVALID_TOKEN', verification.error || 'Invalid or expired unsubscribe token.');
    }

    const normalizedEmail = verification.email.toLowerCase().trim();
    await removeFromSuppressionList(normalizedEmail);

    let syncedWithAccount = false;
    const existingUser = await db.findUserByEmail(normalizedEmail);
    if (existingUser) {
      await setUserPreferences(existingUser.id, { marketingEmails: true });
      syncedWithAccount = true;

      await db.createAuditEvent({
        organizationId: null,
        userId: existingUser.id,
        action: 'privacy.marketing_consent_granted',
        resourceType: 'User',
        resourceId: existingUser.id,
        metadata: {
          email: normalizedEmail,
          source: 'RESUBSCRIBE_FORM',
          timestamp: new Date().toISOString(),
          legalBases: ['DPDPA_2023_SEC_6', 'GDPR_ART_6_1_A'],
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
    }

    return sendSuccess(res, {
      resubscribed: true,
      maskedEmail: maskEmail(normalizedEmail),
      syncedWithAccount,
      message: 'You have been successfully opted back in to AMARACUS technical updates.',
    });
  } catch (error: any) {
    return sendError(res, 500, 'INTERNAL_ERROR', 'Failed to process re-subscription.', error.message);
  }
});

/**
 * GET /api/v1/email/suppression-status
 * Checks suppression status for a given email address. Platform admins only: for anyone else
 * it would reveal which addresses have unsubscribed.
 */
router.get('/suppression-status', requireAuth, requirePlatformAdmin, async (req: Request, res: Response) => {
  const email = req.query.email as string;
  if (!email || typeof email !== 'string') {
    return sendError(res, 400, 'INVALID_EMAIL', 'Email query parameter is required.');
  }

  const suppressed = await isEmailSuppressed(email, 'MARKETING_ANNOUNCEMENT');
  return sendSuccess(res, {
    email: maskEmail(email),
    suppressed,
  });
});

export default router;
