import { appUrl, site } from '../lib/site-config';
/// <reference path="../types/express.d.ts" />
import crypto from 'crypto';
import { Router, Request, Response } from 'express';
import { db } from '../lib/data-store';
import { hashPassword, verifyAccountPassword } from '../lib/crypto-security';
import { TERMS_VERSION, PRIVACY_POLICY_VERSION } from '../lib/legal-versions';
import { requireAuth } from '../middleware/auth';
import { isTestEnv } from '../lib/runtime-config';
import { sessionExpiryFrom } from '../lib/session-policy';
import { setUserPreferences } from '../lib/user-preferences';

const router = Router();

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'default';
}

import { 
  generateOtp, 
  sendOtpEmail, 
  sendPasswordResetEmail,
  savePendingSignup, 
  verifyAndConsumeOtp, 
  canResendOtp,
  getPendingSignup,
  discardPendingSignup,
} from '../lib/email-service';
import { createRateLimiter } from '../middleware/rate-limiter';
import { sendCaughtError } from '../middleware/response-formatter';

const EMAIL_UNAVAILABLE_BODY = {
  error: {
    code: 'EMAIL_UNAVAILABLE',
    message: `We could not send the verification email right now. Please try again in a few minutes or contact ${site('supportEmail')}.`,
  },
};

// General auth rate limiter: 100 requests per 15 minutes per IP
const authLimiter = createRateLimiter({
  limit: 100,
  windowMs: 15 * 60 * 1000,
  message: 'Too many authentication requests from this IP. Please try again after 15 minutes.',
  keyGenerator: (req) => `auth_ip:${req.ip || 'unknown'}`,
});

// Strict brute-force limiter: 20 attempts per 15 minutes per IP + action
const bruteForceLimiter = createRateLimiter({
  limit: 20,
  windowMs: 15 * 60 * 1000,
  message: 'Too many authentication attempts. Please wait 15 minutes before trying again.',
  keyGenerator: (req) => `auth_brute:${req.ip || 'unknown'}:${req.path}`,
});

router.use(authLimiter);

// Helper to provision user, organization, project, environments, session, and audit logs
async function completeUserRegistration(params: {
  email: string;
  name: string | null;
  passwordHash: string;
  organizationName?: string;
  marketingOptIn?: boolean;
  req: Request;
  res: Response;
}) {
  const { email, name, passwordHash, organizationName, marketingOptIn, req, res } = params;

  const user = await db.createUser({
    email,
    name: name?.trim() || undefined,
    passwordHash,
  });

  // Create default organization
  const orgName = organizationName?.trim() || (name ? `${name}'s Organization` : 'My Organization');
  let orgSlug = slugify(orgName);
  const existingOrg = await db.findOrgBySlug(orgSlug);
  if (existingOrg) {
    orgSlug = `${orgSlug}-${Math.floor(1000 + Math.random() * 9000)}`;
  }

  const org = await db.createOrganization({
    name: orgName,
    slug: orgSlug,
  });

  // Assign as OWNER
  await db.addMember({
    organizationId: org.id,
    userId: user.id,
    role: 'OWNER',
  });

  // Create default project & environments
  const project = await db.createProject({
    organizationId: org.id,
    name: 'Default Project',
    slug: 'default-project',
    description: 'Default project provisioned for your cryptographic infrastructure.',
  });

  await db.createEnvironment({ projectId: project.id, name: 'Production', slug: 'production', type: 'production' });
  await db.createEnvironment({ projectId: project.id, name: 'Staging', slug: 'staging', type: 'staging' });
  await db.createEnvironment({ projectId: project.id, name: 'Development', slug: 'development', type: 'development' });

  // Sliding 30-day idle session (extended on use by the auth middleware)
  const expiresAt = sessionExpiryFrom();
  const session = await db.createSession({
    userId: user.id,
    activeOrgId: org.id,
    expiresAt,
  });

  res.cookie('sessionToken', session.sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    expires: expiresAt,
  });

  await db.createAuditEvent({
    organizationId: org.id,
    userId: user.id,
    action: 'auth.signup',
    resourceType: 'User',
    resourceId: user.id,
    metadata: { email: user.email, orgId: org.id },
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });

  await db.createAuditEvent({
    organizationId: org.id,
    userId: user.id,
    action: 'privacy.consent_recorded',
    resourceType: 'User',
    resourceId: user.id,
    metadata: {
      email: user.email,
      termsVersion: TERMS_VERSION,
      privacyPolicyVersion: PRIVACY_POLICY_VERSION,
      consentTimestamp: new Date().toISOString(),
      legalBases: ['DPDPA_2023_SEC_6', 'GDPR_ART_6_1_B'],
    },
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });

  await db.createAuditEvent({
    organizationId: org.id,
    userId: user.id,
    action: 'auth.universal_terms_agreed',
    resourceType: 'User',
    resourceId: user.id,
    metadata: {
      email: user.email,
      termsVersion: TERMS_VERSION,
      agreementTimestamp: new Date().toISOString(),
      statutoryFrameworks: ['DPDPA_2023_SEC_6', 'GDPR_ART_6_1_B', 'EULA_V1'],
      scope: 'UNIVERSAL_TERMS_AND_CONDITIONS',
    },
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });

  await db.createAuditEvent({
    organizationId: org.id,
    userId: user.id,
    action: 'auth.age_capacity_attested',
    resourceType: 'User',
    resourceId: user.id,
    metadata: {
      email: user.email,
      minimumAgeRequirement: 13,
      legalCapacityStandard: 'AGE_13_PLUS_STUDENT_ELIGIBLE',
      attestationConfirmed: true,
      timestamp: new Date().toISOString(),
      statutoryFrameworks: [
        'DPDPA_2023_SEC_9',
        'GDPR_ART_8',
        'COPPA_15_USC_6501',
      ],
      noticeScope: 'DEVELOPER_STUDENT_ELIGIBLE',
    },
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });

  // The choice is also in the audit log below. A failed preference save must not block signup
  // (for example before migration 4_email_preferences is applied); marketing then stays off.
  await setUserPreferences(user.id, { marketingEmails: Boolean(marketingOptIn) }).catch((err) =>
    console.error('[Auth] Saving marketing preference failed; marketing email stays off:', err?.message || err)
  );

  if (marketingOptIn) {
    await db.createAuditEvent({
      organizationId: org.id,
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
      organizationId: org.id,
      userId: user.id,
      action: 'privacy.marketing_consent_withheld',
      resourceType: 'User',
      resourceId: user.id,
      metadata: {
        email: user.email,
        category: 'MARKETING_UPDATES',
        consentGranted: false,
        timestamp: new Date().toISOString(),
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });
  }

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    session: {
      token: session.sessionToken,
      expiresAt: session.expiresAt,
    },
    activeOrganization: {
      id: org.id,
      name: org.name,
      slug: org.slug,
      role: 'OWNER',
    },
  };
}

// POST /v1/auth/signup/send-otp
// Step 1 of OTP Signup: Validates info, generates OTP, sends email, stores pending registration
router.post('/signup/send-otp', bruteForceLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password, name, organizationName, termsAccepted, marketingOptIn, ageAttested } = req.body;

    if (termsAccepted !== true && termsAccepted !== 'true') {
      return res.status(400).json({
        error: {
          code: 'TERMS_REQUIRED',
          message: 'You must review and accept the AMARACUS Universal Terms and Conditions to create an account.',
        },
      });
    }

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'A valid email address is required.' },
      });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Password must be at least 8 characters long.' },
      });
    }

    if (ageAttested === false || ageAttested === 'false') {
      return res.status(403).json({
        error: {
          code: 'UNDERAGE_NOT_PERMITTED',
          message: 'Registration is strictly prohibited for children under 13 years of age.',
        },
      });
    }

    if (ageAttested !== undefined && ageAttested !== true && ageAttested !== 'true') {
      return res.status(400).json({
        error: {
          code: 'AGE_ATTESTATION_REQUIRED',
          message: 'You must certify that you are at least 13 years of age to create an AMARACUS account.',
        },
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await db.findUserByEmail(normalizedEmail);
    if (existingUser) {
      return res.status(409).json({
        error: { code: 'CONFLICT', message: 'An account with this email already exists.' },
      });
    }

    // Check rate limit cooldown
    const rateCheck = await canResendOtp(normalizedEmail);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: `Please wait ${rateCheck.waitSeconds} seconds before requesting another verification code.`,
        },
      });
    }

    const passwordHash = await hashPassword(password);
    const otp = generateOtp();

    await savePendingSignup({
      email: normalizedEmail,
      name: name?.trim() || null,
      organizationName: organizationName?.trim() || (name ? `${name}'s Organization` : 'My Organization'),
      passwordHash,
      otp,
      termsAccepted: true,
      marketingOptIn: Boolean(marketingOptIn),
      ageAttested: ageAttested === true || ageAttested === 'true' || true,
    });

    const emailResult = await sendOtpEmail(normalizedEmail, otp, name?.trim());

    if (!emailResult.success) {
      await discardPendingSignup(normalizedEmail);
      return res.status(503).json(EMAIL_UNAVAILABLE_BODY);
    }

    return res.status(200).json({
      success: true,
      message: 'Verification code sent to your email address.',
      email: normalizedEmail,
      expiresInSeconds: 600,
      simulated: isTestEnv() && emailResult.simulated,
      devOtp: isTestEnv() ? otp : undefined,
    });
  } catch (error: any) {
    console.error('Send OTP error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to dispatch verification code.');
  }
});

// POST /v1/auth/signup/resend-otp
router.post('/signup/resend-otp', bruteForceLimiter, async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Email address is required.' },
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const pending = await getPendingSignup(normalizedEmail);
    if (!pending) {
      return res.status(400).json({
        error: { code: 'NOT_FOUND', message: 'No pending registration found for this email. Please fill out the signup form.' },
      });
    }

    const rateCheck = await canResendOtp(normalizedEmail);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: `Please wait ${rateCheck.waitSeconds} seconds before requesting a new code.`,
        },
      });
    }

    // Send before saving: a failed send leaves the previous code valid and the cooldown untouched.
    const newOtp = generateOtp();
    const emailResult = await sendOtpEmail(normalizedEmail, newOtp, pending.name);

    if (!emailResult.success) {
      return res.status(503).json(EMAIL_UNAVAILABLE_BODY);
    }

    await savePendingSignup({
      email: normalizedEmail,
      name: pending.name,
      organizationName: pending.organizationName,
      passwordHash: pending.passwordHash,
      otp: newOtp,
      termsAccepted: pending.termsAccepted,
      marketingOptIn: pending.marketingOptIn,
      ageAttested: pending.ageAttested,
    });

    return res.status(200).json({
      success: true,
      message: 'A fresh verification code has been sent.',
      email: normalizedEmail,
      expiresInSeconds: 600,
      simulated: isTestEnv() && emailResult.simulated,
      devOtp: isTestEnv() ? newOtp : undefined,
    });
  } catch (error: any) {
    console.error('Resend OTP error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to resend verification code.');
  }
});

// POST /v1/auth/signup/verify-otp
// Step 2 of OTP Signup: Validates OTP code, finalizes account, issues session
router.post('/signup/verify-otp', bruteForceLimiter, async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp || typeof otp !== 'string') {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Email and 6-digit verification code are required.' },
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const verifyResult = await verifyAndConsumeOtp(normalizedEmail, otp.trim());

    if (!verifyResult.success || !verifyResult.pendingData) {
      return res.status(400).json({
        error: { code: 'INVALID_OTP', message: verifyResult.error || 'Invalid verification code.' },
      });
    }

    const pending = verifyResult.pendingData;

    // Check if user was registered in the meantime
    const existing = await db.findUserByEmail(normalizedEmail);
    if (existing) {
      return res.status(409).json({
        error: { code: 'CONFLICT', message: 'An account with this email was already activated.' },
      });
    }

    const result = await completeUserRegistration({
      email: normalizedEmail,
      name: pending.name,
      passwordHash: pending.passwordHash,
      organizationName: pending.organizationName,
      marketingOptIn: pending.marketingOptIn,
      req,
      res,
    });

    return res.status(201).json(result);
  } catch (error: any) {
    console.error('Verify OTP error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to verify code and finalize account.');
  }
});

// POST /v1/auth/signup (Direct account creation without email verification: Jest runner only)
router.post('/signup', bruteForceLimiter, async (req: Request, res: Response) => {
  if (!isTestEnv()) {
    return res.status(404).json({
      error: { code: 'NOT_FOUND', message: 'Use /v1/auth/signup/send-otp and /v1/auth/signup/verify-otp to create an account.' },
    });
  }
  try {
    const { email, password, name, organizationName, termsAccepted, marketingOptIn, ageAttested } = req.body;

    if (termsAccepted === false || termsAccepted === 'false' || (process.env.NODE_ENV === 'production' && termsAccepted !== true && termsAccepted !== 'true')) {
      return res.status(400).json({
        error: {
          code: 'TERMS_REQUIRED',
          message: 'You must review and accept the AMARACUS Universal Terms and Conditions to create an account.',
        },
      });
    }

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'A valid email address is required.' },
      });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Password must be at least 8 characters long.' },
      });
    }

    if (ageAttested === false || ageAttested === 'false') {
      return res.status(403).json({
        error: {
          code: 'UNDERAGE_NOT_PERMITTED',
          message: 'Registration is strictly prohibited for children under 13 years of age.',
        },
      });
    }

    if (ageAttested !== undefined && ageAttested !== true && ageAttested !== 'true') {
      return res.status(400).json({
        error: {
          code: 'AGE_ATTESTATION_REQUIRED',
          message: 'You must certify that you are at least 13 years of age to create an AMARACUS account.',
        },
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await db.findUserByEmail(normalizedEmail);
    if (existingUser) {
      return res.status(409).json({
        error: { code: 'CONFLICT', message: 'An account with this email already exists.' },
      });
    }

    const passwordHash = await hashPassword(password);
    const result = await completeUserRegistration({
      email: normalizedEmail,
      name,
      passwordHash,
      organizationName,
      marketingOptIn: Boolean(marketingOptIn),
      req,
      res,
    });

    return res.status(201).json(result);
  } catch (error: any) {
    console.error('Signup error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to complete registration.');
  }
});

// POST /v1/auth/signin
router.post('/signin', bruteForceLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Email and password are required.' },
      });
    }

    const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : '';
    const user = await db.findUserByEmail(normalizedEmail);
    if (!user) {
      await db.createAuditEvent({
        action: 'auth.failed_signin',
        resourceType: 'User',
        resourceId: normalizedEmail,
        metadata: { email: normalizedEmail, reason: 'user_not_found' },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' },
      });
    }

    const { valid: isValid, legacy } = await verifyAccountPassword(password, user.passwordHash);
    if (!isValid) {
      await db.createAuditEvent({
        action: 'auth.failed_signin',
        userId: user.id,
        resourceType: 'User',
        resourceId: user.id,
        metadata: { email: normalizedEmail, reason: 'invalid_password' },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' },
      });
    }
    if (legacy) {
      // Hash created while the sanitizer HTML-escaped passwords; store the password as typed.
      await db.updateUserPassword(user.id, await hashPassword(password));
    }

    const orgs = await db.getUserOrganizations(user.id);
    const activeOrg = orgs[0]?.organization || null;
    const activeRole = orgs[0]?.role || null;

    const expiresAt = sessionExpiryFrom();
    const session = await db.createSession({
      userId: user.id,
      activeOrgId: activeOrg?.id || null,
      expiresAt,
    });

    res.cookie('sessionToken', session.sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: expiresAt,
    });

    await db.createAuditEvent({
      organizationId: activeOrg?.id || null,
      userId: user.id,
      action: 'auth.signin',
      resourceType: 'Session',
      resourceId: session.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      session: {
        token: session.sessionToken,
        expiresAt: session.expiresAt,
      },
      activeOrganization: activeOrg ? { ...activeOrg, role: activeRole } : null,
      organizations: orgs.map((o) => ({ ...o.organization, role: o.role })),
    });
  } catch (error: any) {
    console.error('Signin error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Authentication failed.');
  }
});

// POST /v1/auth/signout
router.post('/signout', async (req: Request, res: Response) => {
  try {
    let token = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.substring(7).trim()
      : req.cookies?.sessionToken;

    if (token) {
      await db.deleteSession(token);
    }
    res.clearCookie('sessionToken');
    return res.json({ success: true });
  } catch (error: any) {
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Signout failed.');
  }
});

// GET /v1/auth/me
router.get('/me', requireAuth, async (req: Request, res: Response) => {
  try {
    if (req.apiKey) {
      return res.status(200).json({
        data: {
          type: 'API_CREDENTIAL',
          id: req.apiKey.id,
          name: req.apiKey.name,
          prefix: req.apiKey.prefix,
          scopes: req.apiKey.scopes,
          organizationId: req.apiKey.organizationId,
          projectId: req.apiKey.projectId,
          environmentId: req.apiKey.environmentId,
          status: req.apiKey.status || 'ACTIVE',
        },
      });
    }

    const user = req.user!;
    let orgs = await db.getUserOrganizations(user.id);

    if (orgs.length === 0) {
      const orgName = `${user.name || user.email.split('@')[0]}'s Workspace`;
      let orgSlug = slugify(orgName);
      const existingOrg = await db.findOrgBySlug(orgSlug);
      if (existingOrg) {
        orgSlug = `${orgSlug}-${Math.floor(1000 + Math.random() * 9000)}`;
      }

      const org = await db.createOrganization({
        name: orgName,
        slug: orgSlug,
      });

      await db.addMember({
        organizationId: org.id,
        userId: user.id,
        role: 'OWNER',
      });

      const project = await db.createProject({
        organizationId: org.id,
        name: 'Default Project',
        slug: 'default-project',
        description: 'Default project provisioned for your cryptographic infrastructure.',
      });

      await db.createEnvironment({ projectId: project.id, name: 'Production', slug: 'production', type: 'production' });
      await db.createEnvironment({ projectId: project.id, name: 'Staging', slug: 'staging', type: 'staging' });
      await db.createEnvironment({ projectId: project.id, name: 'Development', slug: 'development', type: 'development' });

      if (req.session?.sessionToken) {
        await db.updateSessionActiveOrg(req.session.sessionToken, org.id);
      }

      orgs = await db.getUserOrganizations(user.id);
    }

    const activeOrgId = req.session?.activeOrgId || orgs[0]?.organization.id;
    const activeEntry = orgs.find((o) => o.organization.id === activeOrgId) || orgs[0];

    return res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      session: {
        id: req.session!.id,
        expiresAt: req.session!.expiresAt,
        activeOrgId: activeEntry?.organization.id || null,
      },
      activeOrganization: activeEntry
        ? {
            ...activeEntry.organization,
            role: activeEntry.role,
          }
        : null,
      role: activeEntry?.role || null,
      organizations: orgs.map((o) => ({
        ...o.organization,
        role: o.role,
      })),
    });
  } catch (error: any) {
    console.error('Auth me error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to fetch identity.');
  }
});

// Pending password resets live in the `verification` table with a 1-hour expiry.
// Only a SHA-256 of the (256-bit random) token is stored.
const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000;

function passwordResetIdentifier(email: string): string {
  return `amaracus-password-reset:${email.toLowerCase().trim()}`;
}

function hashResetToken(token: string): string {
  return crypto.createHash('sha256').update(token.trim()).digest('hex');
}

async function savePendingPasswordReset(email: string, token: string): Promise<void> {
  await db.saveVerification({
    identifier: passwordResetIdentifier(email),
    value: hashResetToken(token),
    expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL_MS),
  });
}

async function verifyAndConsumePasswordReset(email: string, token: string): Promise<boolean> {
  const identifier = passwordResetIdentifier(email);
  const pending = await db.getVerification(identifier);
  if (!pending) return false;
  if (Date.now() > pending.expiresAt.getTime()) {
    await db.deleteVerification(identifier);
    return false;
  }
  const expected = Buffer.from(pending.value, 'hex');
  const actual = Buffer.from(hashResetToken(token), 'hex');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    return false;
  }
  await db.deleteVerification(identifier);
  return true;
}

// POST /v1/auth/forgot-password
router.post('/forgot-password', bruteForceLimiter, async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'A valid email address is required.' },
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await db.findUserByEmail(normalizedEmail);

    if (!user) {
      // Return success to avoid email account enumeration
      return res.status(200).json({
        success: true,
        message: 'If an account exists for this email, password reset instructions have been sent.',
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    await savePendingPasswordReset(normalizedEmail, resetToken);

    const baseUrl = appUrl();
    const resetLink = `${baseUrl}/reset-password?token=${resetToken}&email=${encodeURIComponent(normalizedEmail)}`;

    const emailResult = await sendPasswordResetEmail({
      toEmail: normalizedEmail,
      resetLink,
      recipientName: user.name,
    });


    await db.createAuditEvent({
      action: 'auth.forgot_password_requested',
      resourceType: 'User',
      resourceId: user.id,
      metadata: { email: normalizedEmail, delivered: emailResult.success, simulated: emailResult.simulated },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    if (!emailResult.success) {
      console.error('[Auth] Password reset email could not be delivered for user', user.id);
    }

    // Same response whether or not the account exists or delivery succeeded.
    // The reset link is only ever exposed to the Jest runner.
    return res.status(200).json({
      success: true,
      message: 'If an account exists for this email, password reset instructions have been sent.',
      resetLink: isTestEnv() ? resetLink : undefined,
    });
  } catch (error: any) {
    console.error('Forgot password error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to process password reset request.');
  }
});

// POST /v1/auth/reset-password
router.post('/reset-password', bruteForceLimiter, async (req: Request, res: Response) => {
  try {
    const { email, token, code, newPassword } = req.body;
    const resetToken = (token || code)?.toString().trim();

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'A valid email address is required.' },
      });
    }

    if (!resetToken) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'A valid password reset token is required.' },
      });
    }

    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'New password must be at least 8 characters long.' },
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const isValid = await verifyAndConsumePasswordReset(normalizedEmail, resetToken);

    if (!isValid) {
      return res.status(400).json({
        error: { code: 'INVALID_TOKEN', message: 'Invalid or expired password reset link. Please request a new link.' },
      });
    }

    const user = await db.findUserByEmail(normalizedEmail);
    if (!user) {
      return res.status(404).json({
        error: { code: 'USER_NOT_FOUND', message: 'No account associated with this email address.' },
      });
    }

    const passwordHash = await hashPassword(newPassword);
    await db.updateUserPassword(user.id, passwordHash);
    await db.deleteSessionsByUserId(user.id);

    await db.createAuditEvent({
      action: 'auth.password_reset_completed',
      resourceType: 'User',
      resourceId: user.id,
      metadata: { email: normalizedEmail },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.status(200).json({
      success: true,
      message: 'Your password has been successfully reset. You may now sign in with your new password.',
    });
  } catch (error: any) {
    console.error('Reset password error:', error);
    return sendCaughtError(res, error, 'INTERNAL_ERROR', 'Failed to reset password.');
  }
});

export default router;
