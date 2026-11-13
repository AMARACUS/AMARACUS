import { appUrl, site } from '../lib/site-config';
/// <reference path="../types/express.d.ts" />
import { Router, Request, Response } from 'express';
import { db } from '../lib/data-store';
import { requireAuth } from '../middleware/auth';
import { verifyAccountPassword } from '../lib/crypto-security';
import { TERMS_VERSION, PRIVACY_POLICY_VERSION, COOKIE_POLICY_VERSION } from '../lib/legal-versions';
import { createRateLimiter } from '../middleware/rate-limiter';
import { getUserPreferences, setUserPreferences, clearUserPreferences } from '../lib/user-preferences';
import { addToSuppressionList, removeFromSuppressionList } from '../lib/email-service';
import { sendCaughtError } from '../middleware/response-formatter';

const router = Router();

const exportRateLimiter = createRateLimiter({
  limit: 10,
  windowMs: 60 * 60 * 1000, // 10 exports per hour
  message: 'Data export limit reached (10 requests per hour). Please try again later.',
  keyGenerator: (req) => `user_export:${req.user?.id || req.ip}`,
});

// Consent records come from anonymous visitors too; each one writes an audit row.
const consentRateLimiter = createRateLimiter({
  limit: 30,
  windowMs: 15 * 60 * 1000,
  message: 'Too many consent updates. Please try again later.',
  keyGenerator: (req) => `consent:${req.ip || 'unknown'}`,
});

const deleteAccountRateLimiter = createRateLimiter({
  limit: 5,
  windowMs: 60 * 60 * 1000, // 5 attempts per hour
  message: 'Account deletion rate limit reached. Please wait before attempting again.',
  keyGenerator: (req) => `user_del:${req.user?.id || req.ip}`,
});

/**
 * GET /v1/user/privacy-status
 * Returns current statutory compliance status, DPO contact, and data retention schedules.
 */
router.get('/privacy-status', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    return res.status(200).json({
      userId: user.id,
      email: user.email,
      termsVersion: TERMS_VERSION,
      privacyPolicyVersion: PRIVACY_POLICY_VERSION,
      consentRecorded: true,
      applicableFrameworks: [
        'Digital Personal Data Protection Act, 2023 (DPDPA - India)',
        'Information Technology Act, 2000 (Section 43A / SPDI - India)',
        'General Data Protection Regulation (GDPR - EU 2016/679)',
        'CERT-In Cyber Security Directions (April 2022)',
      ],
      grievanceOfficer: {
        name: '[GRIEVANCE OFFICER NAME]',
        designation: 'Data Protection Officer & Resident Grievance Officer',
        email: site('grievanceEmail'),
        turnaroundTime: '24-48 hours acknowledgment; 15-30 days resolution',
      },
      retentionSchedules: {
        auditLogsDays: 180,
        taxAndBillingYears: 7,
        authOtpsMinutes: 10,
        tempUploadsHours: 24,
      },
    });
  } catch (error: any) {
    console.error('Privacy status error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to retrieve privacy status.');
  }
});

/**
 * GET /v1/user/export-data
 * Self-service Data Portability endpoint under DPDPA Section 11 & GDPR Article 20.
 * Exports a structured JSON file containing the user profile, memberships,
 * credential metadata (excluding secrets), cryptographic asset metadata, and audit events.
 */
router.get('/export-data', requireAuth, exportRateLimiter, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    const orgs = await db.getUserOrganizations(user.id);

    // Aggregate credentials and keys for user's organizations
    const organizationsData = [];
    for (const orgEntry of orgs) {
      const orgId = orgEntry.organization.id;
      const rawCreds = await db.getCredentialsByOrg(orgId);
      // Redact sensitive hashes for the export
      const safeCreds = rawCreds.map((c) => ({
        id: c.id,
        name: c.name,
        prefix: c.prefix,
        status: c.status,
        scopes: c.scopes,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
        revokedAt: c.revokedAt,
      }));

      const keys = await db.listKeys({ organizationId: orgId });
      const safeKeys = keys.map((k) => ({
        id: k.id,
        name: k.name,
        algorithm: k.algorithm,
        purpose: k.purpose,
        status: k.status,
        currentVersion: k.currentVersion,
        createdAt: k.createdAt,
      }));

      const certs = await db.listCertificates({ organizationId: orgId });
      const safeCerts = certs.map((c) => ({
        id: c.id,
        subject: c.subject,
        serialNumber: c.serialNumber,
        status: c.status,
        notBefore: c.notBefore,
        notAfter: c.notAfter,
        createdAt: c.createdAt,
      }));

      organizationsData.push({
        organization: orgEntry.organization,
        role: orgEntry.role,
        credentials: safeCreds,
        cryptographicKeys: safeKeys,
        certificates: safeCerts,
      });
    }

    // Retrieve recent user audit events
    const primaryOrgId = orgs[0]?.organization.id || null;
    let userAuditEvents: any[] = [];
    if (primaryOrgId) {
      const auditResult = await db.listAuditEvents({
        organizationId: primaryOrgId,
        actorId: user.id,
        limit: 100,
      });
      userAuditEvents = auditResult.events;
    }

    const exportPayload = {
      exportMetadata: {
        exportDate: new Date().toISOString(),
        exportFormat: 'JSON',
        formatVersion: '1.0.0',
        platform: 'Amaracus Cryptographic Operating System',
        complianceStatement: 'Generated pursuant to DPDPA 2023 Sec 11 and GDPR Art 20',
      },
      userProfile: {
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
      organizations: organizationsData,
      auditHistory: userAuditEvents,
    };

    // Log the data export event in the audit trail
    if (primaryOrgId) {
      await db.createAuditEvent({
        organizationId: primaryOrgId,
        userId: user.id,
        action: 'privacy.data_exported',
        resourceType: 'User',
        resourceId: user.id,
        metadata: {
          email: user.email,
          exportTimestamp: new Date().toISOString(),
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="amaracus-data-export-${user.id}.json"`
    );
    return res.status(200).json(exportPayload);
  } catch (error: any) {
    console.error('Data export error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to generate data export.');
  }
});

/**
 * POST /v1/user/delete-account
 * Self-service Account Erasure endpoint under DPDPA Section 12 & GDPR Article 17.
 * Permanently removes user account, revokes sessions, and destroys personal records.
 */
router.post('/delete-account', requireAuth, deleteAccountRateLimiter, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    const { confirm, password } = req.body;

    if (!confirm) {
      return res.status(400).json({
        error: {
          code: 'CONFIRMATION_REQUIRED',
          message: 'Explicit confirmation is required to delete your account.',
        },
      });
    }

    if (!password || typeof password !== 'string') {
      return res.status(400).json({
        error: {
          code: 'PASSWORD_REQUIRED',
          message: 'Password confirmation is required to verify account ownership.',
        },
      });
    }

    // Verify user password
    const { valid: isPasswordValid } = await verifyAccountPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Incorrect password. Account deletion aborted.',
        },
      });
    }

    const orgs = await db.getUserOrganizations(user.id);
    const primaryOrgId = orgs[0]?.organization.id || null;

    // Record deletion event in audit trail before unlinking
    if (primaryOrgId) {
      await db.createAuditEvent({
        organizationId: primaryOrgId,
        userId: user.id,
        action: 'privacy.account_deleted',
        resourceType: 'User',
        resourceId: user.id,
        metadata: {
          email: user.email,
          deletedAt: new Date().toISOString(),
          mechanism: 'self_service_erasure',
        },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
    }

    // Clear stored preferences
    await clearUserPreferences(user.id);

    // Execute user deletion in database
    await db.deleteUser(user.id);

    // Clear session cookie
    res.clearCookie('sessionToken');

    return res.status(200).json({
      success: true,
      message: 'Your account and personal data have been permanently erased.',
    });
  } catch (error: any) {
    console.error('Account deletion error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to delete account.');
  }
});

/**
 * GET /v1/user/sessions
 * Returns all active authenticated sessions for the user.
 */
router.get('/sessions', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    const currentSessionId = req.session?.id;
    const sessions = await db.getUserSessions(user.id);

    return res.status(200).json({
      sessions: sessions.map((s) => ({
        id: s.id,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        isCurrent: s.id === currentSessionId,
      })),
    });
  } catch (error: any) {
    console.error('List sessions error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to list active sessions.');
  }
});

/**
 * DELETE /v1/user/sessions/:sessionId
 * Revokes a specific authenticated session for the user.
 */
router.delete('/sessions/:sessionId', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    const { sessionId } = req.params;

    const revoked = await db.deleteSessionById(user.id, sessionId);
    if (!revoked) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: 'Session not found or already revoked.' },
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Session revoked successfully.',
    });
  } catch (error: any) {
    console.error('Revoke session error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to revoke session.');
  }
});

/**
 * GET /v1/user/preferences
 * Returns user privacy and communication preferences.
 */
router.get('/preferences', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    const preferences = await getUserPreferences(user.id);
    return res.status(200).json({ preferences });
  } catch (error: any) {
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to retrieve preferences.');
  }
});

/**
 * PUT /v1/user/preferences
 * Updates user privacy and communication preferences.
 * Records immutable audit events when consent is granted or withdrawn.
 */
router.put('/preferences', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    const { marketingEmails, securityAlertsOnly, telemetryOptIn } = req.body;
    const current = await getUserPreferences(user.id);

    const newMarketing = marketingEmails !== undefined ? Boolean(marketingEmails) : current.marketingEmails;
    const marketingChanged = newMarketing !== current.marketingEmails;

    const updated = await setUserPreferences(user.id, {
      marketingEmails: newMarketing,
      securityAlertsOnly: true, // Non-derogable for essential service delivery
      telemetryOptIn: telemetryOptIn !== undefined ? Boolean(telemetryOptIn) : current.telemetryOptIn,
    });

    if (marketingChanged) {
      // The signed-in owner of the address decides here, so keep the unsubscribe list in step.
      if (newMarketing) {
        await removeFromSuppressionList(user.email);
      } else {
        await addToSuppressionList({ email: user.email, source: 'USER_SETTINGS', reason: 'Turned off marketing email in Settings' });
      }
      if (newMarketing) {
        await db.createAuditEvent({
          organizationId: req.organizationId || null,
          userId: user.id,
          action: 'privacy.marketing_consent_granted',
          resourceType: 'User',
          resourceId: user.id,
          metadata: {
            email: user.email,
            category: 'MARKETING_UPDATES',
            consentGranted: true,
            timestamp: new Date().toISOString(),
            legalBases: ['DPDPA_2023_SEC_6', 'GDPR_ART_6_1_A'],
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
      } else {
        await db.createAuditEvent({
          organizationId: req.organizationId || null,
          userId: user.id,
          action: 'privacy.marketing_consent_withdrawn',
          resourceType: 'User',
          resourceId: user.id,
          metadata: {
            email: user.email,
            category: 'MARKETING_UPDATES',
            consentGranted: false,
            timestamp: new Date().toISOString(),
            legalBases: ['DPDPA_2023_SEC_6', 'GDPR_ART_7_3'],
          },
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
      }
    }

    return res.status(200).json({
      success: true,
      preferences: updated,
    });
  } catch (error: any) {
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to update preferences.');
  }
});

/**
 * POST /v1/user/accept-terms
 * Records an immutable, auditable acceptance of a specific Terms of Service version.
 * Stores timestamp, IP address, user agent, and legal bases in the tamper-evident audit log.
 */
router.post('/accept-terms', requireAuth, async (req: Request, res: Response) => {
  try {
    const user = req.user!;
    const { termsVersion, privacyPolicyVersion } = req.body;

    const effectiveTermsVersion = termsVersion && typeof termsVersion === 'string' ? termsVersion : TERMS_VERSION;
    const effectivePrivacyVersion = privacyPolicyVersion && typeof privacyPolicyVersion === 'string' ? privacyPolicyVersion : PRIVACY_POLICY_VERSION;
    const acceptedAt = new Date().toISOString();

    const auditEvent = await db.createAuditEvent({
      organizationId: req.organizationId || null,
      userId: user.id,
      action: 'legal.terms_accepted',
      resourceType: 'TermsOfService',
      resourceId: effectiveTermsVersion,
      metadata: {
        email: user.email,
        termsVersion: effectiveTermsVersion,
        privacyPolicyVersion: effectivePrivacyVersion,
        acceptedAt,
        legalBases: ['CONTRACTUAL_NECESSITY', 'DPDPA_2023_SEC_6', 'GDPR_ART_6_1_B'],
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      message: `Terms of Service version ${effectiveTermsVersion} accepted successfully.`,
      record: {
        auditId: auditEvent.id,
        termsVersion: effectiveTermsVersion,
        privacyPolicyVersion: effectivePrivacyVersion,
        acceptedAt,
      },
    });
  } catch (error: any) {
    console.error('Record terms acceptance error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to record terms acceptance.');
  }
});

/**
 * POST /v1/user/cookie-consent
 * Persists and cryptographically logs cookie consent records.
 * Can be called authenticated or unauthenticated (with IP/User-Agent).
 */
router.post('/cookie-consent', consentRateLimiter, async (req: Request, res: Response) => {
  try {
    const { status, categories, consentVersion } = req.body;

    if (!status || !['accepted', 'rejected', 'custom', 'withdrawn'].includes(status)) {
      return res.status(400).json({
        error: { code: 'INVALID_STATUS', message: 'Status must be one of: accepted, rejected, custom, withdrawn.' },
      });
    }

    const effectiveVersion = consentVersion && typeof consentVersion === 'string' ? consentVersion : COOKIE_POLICY_VERSION;
    const effectiveCategories = {
      necessary: true,
      functional: Boolean(categories?.functional),
      analytics: Boolean(categories?.analytics),
      marketing: false, // strictly not used
    };
    const recordedAt = new Date().toISOString();

    const auditEvent = await db.createAuditEvent({
      organizationId: req.organizationId || null,
      userId: req.user?.id || null,
      action: 'privacy.cookie_consent_recorded',
      resourceType: 'CookieConsent',
      resourceId: effectiveVersion,
      metadata: {
        status,
        categories: effectiveCategories,
        consentVersion: effectiveVersion,
        recordedAt,
        legalBases: ['EPRIVACY_DIR_ART_5_3', 'GDPR_ART_6_1_A', 'DPDPA_2023_SEC_6'],
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      message: `Cookie consent (${status}) recorded successfully.`,
      record: {
        auditId: auditEvent.id,
        status,
        categories: effectiveCategories,
        consentVersion: effectiveVersion,
        recordedAt,
      },
    });
  } catch (error: any) {
    console.error('Cookie consent recording error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to record cookie consent.');
  }
});

export default router;
