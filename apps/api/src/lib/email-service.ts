import nodemailer, { Transporter } from 'nodemailer';
import crypto from 'crypto';
import { prisma } from '@amaracus/database';
import { escapeHtml } from './sanitize';
import { getUserPreferences } from './user-preferences';
import { getRequiredSecret, isTestEnv } from './runtime-config';
import { db } from './data-store';
import { appUrl, site } from './site-config';

/**
 * --------------------------------------------------------------------------
 * EMAIL CLASSIFICATION TAXONOMY
 * --------------------------------------------------------------------------
 * Rigorous categorization of all outbound communications to satisfy:
 * - CAN-SPAM Act (15 U.S.C. 7701)
 * - EU GDPR (Regulation 2016/679) Articles 6(1)(a), 6(1)(b), 7(3)
 * - Indian DPDPA 2023 Section 6 (Consent & Withdrawal) & Section 4
 * - Google & Yahoo 2024 Bulk Sender Requirements (RFC 8058 One-Click)
 */
export type EmailCategory =
  | 'SECURITY_OTP'
  | 'SECURITY_ALERT'
  | 'SECURITY_INCIDENT'
  | 'ACCOUNT_TRANSACTIONAL'
  | 'BILLING_TRANSACTIONAL'
  | 'HACKATHON_RECEIPT'
  | 'MARKETING_ANNOUNCEMENT'
  | 'MARKETING_NEWSLETTER'
  | 'MARKETING_PROMOTION';

export interface EmailCategoryMetadata {
  category: EmailCategory;
  isEssential: boolean;
  requiresUnsubscribeHeaders: boolean;
  requiresUnsubscribeFooter: boolean;
  senderProfile: 'SECURITY' | 'TRANSACTIONAL' | 'MARKETING';
  legalBasis: string;
  description: string;
}

export const EMAIL_CATEGORY_METADATA: Record<EmailCategory, EmailCategoryMetadata> = {
  SECURITY_OTP: {
    category: 'SECURITY_OTP',
    isEssential: true,
    requiresUnsubscribeHeaders: false,
    requiresUnsubscribeFooter: false,
    senderProfile: 'SECURITY',
    legalBasis: 'Contractual & Identity Authentication (GDPR Art. 6(1)(b) / DPDPA Sec. 4)',
    description: 'One-time registration and login authentication codes.',
  },
  SECURITY_ALERT: {
    category: 'SECURITY_ALERT',
    isEssential: true,
    requiresUnsubscribeHeaders: false,
    requiresUnsubscribeFooter: false,
    senderProfile: 'SECURITY',
    legalBasis: 'Security & Contractual Necessity (GDPR Art. 6(1)(b) / DPDPA Sec. 4)',
    description: 'Cryptographic key lifecycle warnings, suspicious login anomalies, and policy enforcement notices.',
  },
  SECURITY_INCIDENT: {
    category: 'SECURITY_INCIDENT',
    isEssential: true,
    requiresUnsubscribeHeaders: false,
    requiresUnsubscribeFooter: false,
    senderProfile: 'SECURITY',
    legalBasis: 'Statutory Compliance (CERT-In 2022 Directions / GDPR Art. 33/34)',
    description: 'Mandatory statutory security incident and breach notifications.',
  },
  ACCOUNT_TRANSACTIONAL: {
    category: 'ACCOUNT_TRANSACTIONAL',
    isEssential: true,
    requiresUnsubscribeHeaders: false,
    requiresUnsubscribeFooter: false,
    senderProfile: 'TRANSACTIONAL',
    legalBasis: 'Contractual Performance (GDPR Art. 6(1)(b) / DPDPA Sec. 4)',
    description: 'Team invitations, password reset confirmations, and account lifecycle events.',
  },
  BILLING_TRANSACTIONAL: {
    category: 'BILLING_TRANSACTIONAL',
    isEssential: true,
    requiresUnsubscribeHeaders: false,
    requiresUnsubscribeFooter: false,
    senderProfile: 'TRANSACTIONAL',
    legalBasis: 'Contractual & Commercial Accounting (GDPR Art. 6(1)(b) / DPDPA Sec. 4)',
    description: 'Payment receipts, subscription activations, invoices via Polar.sh (Merchant of Record) or Razorpay (INR), and notices that a plan is near its limit.',
  },
  HACKATHON_RECEIPT: {
    category: 'HACKATHON_RECEIPT',
    isEssential: true,
    requiresUnsubscribeHeaders: false,
    requiresUnsubscribeFooter: false,
    senderProfile: 'TRANSACTIONAL',
    legalBasis: 'Competition Contract & Mathematical Proof (GDPR Art. 6(1)(b))',
    description: 'Cryptographic receipt token and SHA-256 submission verification.',
  },
  MARKETING_ANNOUNCEMENT: {
    category: 'MARKETING_ANNOUNCEMENT',
    isEssential: false,
    requiresUnsubscribeHeaders: true,
    requiresUnsubscribeFooter: true,
    senderProfile: 'MARKETING',
    legalBasis: 'Freely Given Consent (GDPR Art. 6(1)(a) / DPDPA Sec. 6)',
    description: 'Post-quantum cryptographic feature announcements and major SDK updates.',
  },
  MARKETING_NEWSLETTER: {
    category: 'MARKETING_NEWSLETTER',
    isEssential: false,
    requiresUnsubscribeHeaders: true,
    requiresUnsubscribeFooter: true,
    senderProfile: 'MARKETING',
    legalBasis: 'Freely Given Consent (GDPR Art. 6(1)(a) / DPDPA Sec. 6)',
    description: 'Cryptographic engineering digests, benchmarks, and research articles.',
  },
  MARKETING_PROMOTION: {
    category: 'MARKETING_PROMOTION',
    isEssential: false,
    requiresUnsubscribeHeaders: true,
    requiresUnsubscribeFooter: true,
    senderProfile: 'MARKETING',
    legalBasis: 'Freely Given Consent (GDPR Art. 6(1)(a) / DPDPA Sec. 6)',
    description: 'Commercial promotions, hackathon invitation drives, and enterprise plan offers.',
  },
};

/**
 * --------------------------------------------------------------------------
 * SENDER PROFILES & STATUTORY IDENTIFICATION
 * --------------------------------------------------------------------------
 */
export const SENDER_PROFILES = {
  SECURITY: {
    from: process.env.SMTP_FROM_SECURITY || site('fromSecurity'),
    replyTo: site('securityEmail'),
  },
  TRANSACTIONAL: {
    from: process.env.SMTP_FROM_NOTIFICATIONS || site('fromNotifications'),
    replyTo: site('supportEmail'),
  },
  MARKETING: {
    from: process.env.SMTP_FROM_MARKETING || site('fromMarketing'),
    replyTo: site('supportEmail'),
  },
};

export const SENDER_LEGAL_ENTITY = {
  company: site('legalCompany'),
  physicalAddress: site('legalAddress'),
  supportEmail: site('supportEmail'),
  privacyEmail: site('privacyEmail'),
  grievanceEmail: site('grievanceEmail'),
  dpoEmail: site('privacyEmail'),
};

/**
 * --------------------------------------------------------------------------
 * SUPPRESSION LIST SYSTEM
 * --------------------------------------------------------------------------
 */
export interface SuppressionRecord {
  email: string;
  category: EmailCategory | 'ALL_MARKETING';
  suppressedAt: string;
  source: 'ONE_CLICK_POST' | 'UNSUBSCRIBE_LINK' | 'USER_SETTINGS' | 'ADMIN' | 'BOUNCE';
  reason: string;
}

/**
 * Outside tests the list is the email_suppression table, so an unsubscribe survives restarts and
 * deploys. The test suite has no database and uses this map instead.
 */
const memorySuppressionList = new Map<string, SuppressionRecord>();

function toRecord(row: { email: string; category: string; source: string; reason: string; suppressedAt: Date }): SuppressionRecord {
  return {
    email: row.email,
    category: row.category as SuppressionRecord['category'],
    source: row.source as SuppressionRecord['source'],
    reason: row.reason,
    suppressedAt: row.suppressedAt.toISOString(),
  };
}

async function findSuppression(normalizedEmail: string): Promise<SuppressionRecord | null> {
  if (isTestEnv()) return memorySuppressionList.get(normalizedEmail) || null;
  const row = await prisma.emailSuppression.findUnique({ where: { email: normalizedEmail } });
  return row ? toRecord(row) : null;
}

export async function addToSuppressionList(entry: {
  email: string;
  category?: EmailCategory | 'ALL_MARKETING';
  source: 'ONE_CLICK_POST' | 'UNSUBSCRIBE_LINK' | 'USER_SETTINGS' | 'ADMIN' | 'BOUNCE';
  reason?: string;
}): Promise<SuppressionRecord> {
  const normalizedEmail = entry.email.toLowerCase().trim();
  const existing = await findSuppression(normalizedEmail);
  let category: SuppressionRecord['category'] = entry.category || 'ALL_MARKETING';
  // One row per address: never narrow an opt-out. Two different categories become all marketing.
  if (existing && existing.category !== category) category = 'ALL_MARKETING';

  const record: SuppressionRecord = {
    email: normalizedEmail,
    category,
    suppressedAt: new Date().toISOString(),
    source: entry.source,
    reason: entry.reason || 'User requested unsubscribe',
  };
  if (isTestEnv()) {
    memorySuppressionList.set(normalizedEmail, record);
    return record;
  }
  const data = { category: record.category, source: record.source, reason: record.reason };
  const row = await prisma.emailSuppression.upsert({
    where: { email: normalizedEmail },
    create: { email: normalizedEmail, ...data },
    update: data,
  });
  return toRecord(row);
}

export async function isEmailSuppressed(email: string, category: EmailCategory): Promise<boolean> {
  const metadata = EMAIL_CATEGORY_METADATA[category];
  // Essential messages (security, transactional OTP, hackathon receipts) can never be suppressed
  if (metadata && metadata.isEssential) {
    return false;
  }

  const existing = await findSuppression(email.toLowerCase().trim());
  if (!existing) return false;

  return existing.category === 'ALL_MARKETING' || existing.category === category;
}

export async function removeFromSuppressionList(email: string): Promise<boolean> {
  const normalizedEmail = email.toLowerCase().trim();
  if (isTestEnv()) return memorySuppressionList.delete(normalizedEmail);
  const { count } = await prisma.emailSuppression.deleteMany({ where: { email: normalizedEmail } });
  return count > 0;
}

export async function getSuppressionList(): Promise<SuppressionRecord[]> {
  if (isTestEnv()) return Array.from(memorySuppressionList.values());
  const rows = await prisma.emailSuppression.findMany({ orderBy: { suppressedAt: 'desc' } });
  return rows.map(toRecord);
}

/** Test helper: empties the in-memory list. */
export function clearSuppressionList(): void {
  memorySuppressionList.clear();
}

/**
 * Marketing email needs the recipient's opt-in. Only account holders can opt in (at signup or in
 * Settings), so an address without an account, or one that never opted in, gets no marketing.
 */
export async function hasMarketingConsent(email: string): Promise<boolean> {
  try {
    const user = await db.findUserByEmail(email.toLowerCase().trim());
    if (!user) return false;
    return (await getUserPreferences(user.id)).marketingEmails === true;
  } catch (err: any) {
    // Fail closed: if consent cannot be read, no marketing email goes out.
    console.error('[EMAIL DISPATCH] Reading marketing consent failed; not sending:', err?.message || err);
    return false;
  }
}

/**
 * --------------------------------------------------------------------------
 * HMAC-SHA256 UNSUBSCRIBE TOKEN ENGINE
 * --------------------------------------------------------------------------
 * Protects recipient privacy: contains zero exposed plaintext passwords,
 * user IDs, or unauthenticated parameters. Cryptographically signed and
 * verifiable with 30-day expiration window.
 */
function getUnsubscribeSecret(): string {
  return getRequiredSecret('UNSUBSCRIBE_SECRET');
}

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export function generateUnsubscribeToken(
  email: string,
  category: EmailCategory | 'ALL_MARKETING' = 'ALL_MARKETING'
): string {
  const normalizedEmail = email.toLowerCase().trim();
  const timestamp = Date.now();
  const payload = `${normalizedEmail}|${category}|${timestamp}`;
  const hmac = crypto.createHmac('sha256', getUnsubscribeSecret()).update(payload).digest('hex');
  const encodedPayload = Buffer.from(payload, 'utf8').toString('base64url');
  return `${encodedPayload}.${hmac}`;
}

export function verifyUnsubscribeToken(token: string): {
  valid: boolean;
  email?: string;
  category?: EmailCategory | 'ALL_MARKETING';
  expired?: boolean;
  error?: string;
} {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Missing or invalid token format.' };
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return { valid: false, error: 'Malformed token structure.' };
  }

  const [encodedPayload, providedSignature] = parts;

  let payloadString: string;
  try {
    payloadString = Buffer.from(encodedPayload, 'base64url').toString('utf8');
  } catch {
    return { valid: false, error: 'Invalid base64 payload.' };
  }

  const expectedSignature = crypto
    .createHmac('sha256', getUnsubscribeSecret())
    .update(payloadString)
    .digest('hex');

  // Constant-time comparison to prevent timing attacks
  const expectedBuf = Buffer.from(expectedSignature, 'utf8');
  const providedBuf = Buffer.from(providedSignature, 'utf8');

  if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return { valid: false, error: 'Invalid cryptographic signature or tampered token.' };
  }

  const [email, category, timestampStr] = payloadString.split('|');
  const timestamp = parseInt(timestampStr, 10);

  if (isNaN(timestamp)) {
    return { valid: false, error: 'Invalid token timestamp.' };
  }

  if (Date.now() - timestamp > TOKEN_TTL_MS) {
    return { valid: false, expired: true, error: 'Unsubscribe link has expired. Please request a new link.' };
  }

  return {
    valid: true,
    email: email.toLowerCase().trim(),
    category: category as EmailCategory | 'ALL_MARKETING',
  };
}

/**
 * --------------------------------------------------------------------------
 * SIGNUP & OTP ENGINE
 * --------------------------------------------------------------------------
 * Pending signups live in the `verification` table (via DataStore), so a
 * restart doesn't invalidate codes already emailed. The OTP itself is stored
 * only as an HMAC.
 */
export interface PendingSignup {
  email: string;
  name: string | null;
  organizationName: string;
  passwordHash: string;
  expiresAt: Date;
  attempts: number;
  createdAt: Date;
  termsAccepted?: boolean;
  termsAcceptedAt?: Date;
  marketingOptIn?: boolean;
  ageAttested?: boolean;
  ageAttestedAt?: Date;
}

interface StoredPendingSignup extends Omit<PendingSignup, 'email' | 'expiresAt'> {
  otpHash: string;
  lastSentAt: Date;
}

const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_RESEND_COOLDOWN_SECONDS = 60;
const OTP_MAX_ATTEMPTS = 5;

function signupIdentifier(email: string): string {
  return `amaracus-signup:${email.toLowerCase().trim()}`;
}

function hashOtp(email: string, otp: string): string {
  return crypto
    .createHmac('sha256', getRequiredSecret('API_SECRET', 'AUTH_SECRET'))
    .update(`signup-otp:${email}:${otp}`)
    .digest('hex');
}

async function loadPendingSignup(email: string): Promise<(StoredPendingSignup & { expiresAt: Date }) | null> {
  const record = await db.getVerification(signupIdentifier(email));
  if (!record) return null;
  const stored = JSON.parse(record.value);
  return {
    ...stored,
    createdAt: new Date(stored.createdAt),
    lastSentAt: new Date(stored.lastSentAt),
    termsAcceptedAt: stored.termsAcceptedAt ? new Date(stored.termsAcceptedAt) : undefined,
    ageAttestedAt: stored.ageAttestedAt ? new Date(stored.ageAttestedAt) : undefined,
    expiresAt: record.expiresAt,
  };
}

async function storePendingSignup(email: string, data: StoredPendingSignup, expiresAt: Date): Promise<void> {
  await db.saveVerification({ identifier: signupIdentifier(email), value: JSON.stringify(data), expiresAt });
}

export function generateOtp(): string {
  return crypto.randomInt(100000, 1000000).toString();
}

export type EmailPurpose = 'VERIFY' | 'RECOVERY' | 'DEFAULT';

const RESEND_API_URL = 'https://api.resend.com/emails';
const RESEND_TIMEOUT_MS = 15000;

/** True when email goes out through the Resend HTTPS API. Never inside the test runner. */
export function isResendConfigured(): boolean {
  return !isTestEnv() && !!process.env.RESEND_API_KEY?.trim();
}

/**
 * Sender for Resend. It must be on the domain verified in Resend (amaracus.tech), so the
 * SMTP sender addresses (often a Gmail account) are not reused here.
 */
export function resendFromAddress(purpose: EmailPurpose): string {
  const override =
    purpose === 'VERIFY'
      ? process.env.EMAIL_FROM_VERIFY
      : purpose === 'RECOVERY'
        ? process.env.EMAIL_FROM_RECOVERY
        : process.env.EMAIL_FROM_DEFAULT;
  if (override?.trim()) return override.trim();
  if (purpose === 'VERIFY') return site('fromVerify');
  if (purpose === 'RECOVERY') return site('fromRecovery');
  return site('fromDefault');
}

export async function sendViaResend(message: {
  from: string;
  to: string;
  replyTo?: string;
  subject: string;
  html: string;
  text: string;
  headers?: Record<string, string>;
}): Promise<{ success: boolean; messageId?: string; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RESEND_TIMEOUT_MS);
  try {
    const res = await fetch(RESEND_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY!.trim()}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: message.from,
        to: [message.to],
        reply_to: message.replyTo || undefined,
        subject: message.subject,
        html: message.html,
        text: message.text,
        headers: message.headers && Object.keys(message.headers).length > 0 ? message.headers : undefined,
      }),
      signal: controller.signal,
    });
    const body: any = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = body?.message || body?.error || res.statusText;
      return { success: false, error: `Resend rejected the email (HTTP ${res.status}): ${detail}` };
    }
    return { success: true, messageId: body?.id };
  } catch (err: any) {
    const reason = err?.name === 'AbortError' ? `timed out after ${RESEND_TIMEOUT_MS}ms` : err?.message || String(err);
    return { success: false, error: `Resend request failed: ${reason}` };
  } finally {
    clearTimeout(timer);
  }
}

/** True when SMTP credentials for this purpose (or the default transport) are set. */
export function isSmtpConfigured(purpose: EmailPurpose = 'DEFAULT'): boolean {
  const user =
    purpose === 'RECOVERY'
      ? process.env.RECOVERY_SMTP_USER || process.env.SECURITY_SMTP_USER || process.env.SMTP_USER
      : purpose === 'VERIFY'
        ? process.env.VERIFY_SMTP_USER || process.env.AUTH_SMTP_USER || process.env.SMTP_USER
        : process.env.SMTP_USER;
  const pass =
    purpose === 'RECOVERY'
      ? process.env.RECOVERY_SMTP_PASS || process.env.SECURITY_SMTP_PASS || process.env.SMTP_PASS
      : purpose === 'VERIFY'
        ? process.env.VERIFY_SMTP_PASS || process.env.AUTH_SMTP_PASS || process.env.SMTP_PASS
        : process.env.SMTP_PASS;
  return !!user?.trim() && !!pass?.trim();
}

interface TransporterInstance {
  transporter: Transporter;
  host: string;
  user: string;
  pass: string;
  from: string;
  purpose: EmailPurpose;
}

function getTransporter(purpose: EmailPurpose = 'DEFAULT'): TransporterInstance | null {
  let user: string | undefined;
  let rawPass: string | undefined;
  let host: string | undefined;
  let port: number;
  let secure: boolean;
  let customFrom: string | undefined;

  if (purpose === 'RECOVERY') {
    user = (process.env.RECOVERY_SMTP_USER || process.env.SECURITY_SMTP_USER || process.env.SMTP_USER)?.trim();
    rawPass = (process.env.RECOVERY_SMTP_PASS || process.env.SECURITY_SMTP_PASS || process.env.SMTP_PASS)?.trim();
    host = (
      process.env.RECOVERY_SMTP_HOST ||
      process.env.SECURITY_SMTP_HOST ||
      (user?.includes('yahoo') ? 'smtp.mail.yahoo.com' : user?.includes('gmail') ? 'smtp.gmail.com' : process.env.SMTP_HOST)
    )?.trim() || 'smtp.gmail.com';
    port = parseInt(process.env.RECOVERY_SMTP_PORT || process.env.SECURITY_SMTP_PORT || process.env.SMTP_PORT || (host.includes('yahoo') ? '465' : '587'), 10);
    secure = process.env.RECOVERY_SMTP_SECURE === 'true' || port === 465;
    customFrom = (process.env.RECOVERY_SMTP_FROM || process.env.SECURITY_SMTP_FROM)?.trim();
  } else if (purpose === 'VERIFY') {
    user = (process.env.VERIFY_SMTP_USER || process.env.AUTH_SMTP_USER || process.env.SMTP_USER)?.trim();
    rawPass = (process.env.VERIFY_SMTP_PASS || process.env.AUTH_SMTP_PASS || process.env.SMTP_PASS)?.trim();
    host = (
      process.env.VERIFY_SMTP_HOST ||
      process.env.AUTH_SMTP_HOST ||
      (user?.includes('yahoo') ? 'smtp.mail.yahoo.com' : user?.includes('gmail') ? 'smtp.gmail.com' : process.env.SMTP_HOST)
    )?.trim() || 'smtp.gmail.com';
    port = parseInt(process.env.VERIFY_SMTP_PORT || process.env.AUTH_SMTP_PORT || process.env.SMTP_PORT || (host.includes('yahoo') ? '465' : '587'), 10);
    secure = process.env.VERIFY_SMTP_SECURE === 'true' || port === 465;
    customFrom = (process.env.VERIFY_SMTP_FROM || process.env.AUTH_SMTP_FROM)?.trim();
  } else {
    user = process.env.SMTP_USER?.trim();
    rawPass = process.env.SMTP_PASS?.trim();
    host = process.env.SMTP_HOST?.trim() || (user?.includes('yahoo') ? 'smtp.mail.yahoo.com' : user?.includes('gmail') ? 'smtp.gmail.com' : undefined);
    port = parseInt(process.env.SMTP_PORT || (host?.includes('yahoo') ? '465' : '587'), 10);
    secure = process.env.SMTP_SECURE === 'true' || port === 465;
    customFrom = process.env.SMTP_FROM?.trim();
  }

  // No credential fallbacks: without configured SMTP credentials nothing is sent.
  // Tests never use real SMTP.
  if (isTestEnv() || !user || !rawPass) {
    return null;
  }

  // Strip whitespace if user pasted 16-character code with spaces (e.g. "abcd efgh ijkl mnop")
  const pass = (host?.includes('gmail') || user?.includes('gmail') || host?.includes('yahoo') || user?.includes('yahoo'))
    ? rawPass.replace(/\s+/g, '')
    : rawPass;

  // Determine sender from address
  let fromAddress: string;
  if (customFrom) {
    fromAddress = customFrom;
  } else if (purpose === 'RECOVERY') {
    fromAddress = site('fromRecoverySmtp');
  } else if (purpose === 'VERIFY') {
    fromAddress = site('fromVerifySmtp');
  } else {
    fromAddress = site('fromDefaultSmtp');
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user,
      pass,
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
  });

  return { transporter, host: host!, user, pass, from: fromAddress, purpose };
}

/**
 * Audit log of sent emails (in-memory for development inspection and tests)
 */
export interface SentEmailRecord {
  toEmail: string;
  category: EmailCategory;
  subject: string;
  simulated: boolean;
  suppressed?: boolean;
  headers?: Record<string, string>;
  messageId?: string;
  sentAt: string;
}

const sentEmailsHistory: SentEmailRecord[] = [];

export function getSentEmailsHistory(): SentEmailRecord[] {
  return [...sentEmailsHistory];
}

export function getLastSentEmail(): SentEmailRecord | undefined {
  return sentEmailsHistory[sentEmailsHistory.length - 1];
}

export function clearSentEmailsHistory(): void {
  sentEmailsHistory.length = 0;
}

/**
 * --------------------------------------------------------------------------
 * SENDER IDENTIFICATION & FOOTER GENERATION
 * --------------------------------------------------------------------------
 */
function buildEmailFooter(category: EmailCategory, recipientEmail: string): { html: string; text: string } {
  const metadata = EMAIL_CATEGORY_METADATA[category];
  const isMarketing = !metadata.isEssential;

  if (isMarketing) {
    const token = generateUnsubscribeToken(recipientEmail, category);
    const appBaseUrl = process.env.NEXT_PUBLIC_APP_URL || appUrl();
    const unsubUrl = `${appBaseUrl}/unsubscribe?token=${token}`;

    const html = `
      <div style="border-top: 1px solid #E9EDE7; padding-top: 24px; margin-top: 32px; font-size: 11px; color: #767676; line-height: 1.6;">
        <p style="margin: 0 0 8px 0;">
          <strong>${SENDER_LEGAL_ENTITY.company}</strong> • ${SENDER_LEGAL_ENTITY.physicalAddress}
        </p>
        <p style="margin: 0 0 10px 0;">
          You received this email because you opted in to receive technical updates from AMARACUS. 
          <a href="${unsubUrl}" style="color: #008031; text-decoration: underline; font-weight: 500;">Unsubscribe from marketing emails</a> with 1-click.
        </p>
        <p style="margin: 0; color: #8C928C; font-size: 10px;">
          Support: <a href="mailto:${SENDER_LEGAL_ENTITY.supportEmail}" style="color: #767676;">${SENDER_LEGAL_ENTITY.supportEmail}</a> | 
          Privacy: <a href="mailto:${SENDER_LEGAL_ENTITY.privacyEmail}" style="color: #767676;">${SENDER_LEGAL_ENTITY.privacyEmail}</a> | 
          Grievance Officer: <a href="mailto:${SENDER_LEGAL_ENTITY.grievanceEmail}" style="color: #767676;">${SENDER_LEGAL_ENTITY.grievanceEmail}</a>
        </p>
      </div>
    `;

    const text = `
--
${SENDER_LEGAL_ENTITY.company} • ${SENDER_LEGAL_ENTITY.physicalAddress}
You received this email because you opted in to AMARACUS technical updates.
Unsubscribe with one-click: ${unsubUrl}
Support: ${SENDER_LEGAL_ENTITY.supportEmail} | Privacy: ${SENDER_LEGAL_ENTITY.privacyEmail}
    `.trim();

    return { html, text };
  }

  // Essential / Transactional / Security Footer
  const html = `
    <div style="border-top: 1px solid #E9EDE7; padding-top: 20px; margin-top: 28px; font-size: 11px; color: #767676; line-height: 1.5;">
      <p style="margin: 0 0 6px 0;">
        <strong>${SENDER_LEGAL_ENTITY.company}</strong> • ${SENDER_LEGAL_ENTITY.physicalAddress}
      </p>
      <p style="margin: 0; color: #8C928C; font-size: 10px;">
        This is an automated essential notification regarding your account or security credentials. Under our Terms of Service and applicable privacy statutes (${metadata.legalBasis}), essential service and security messages cannot be unsubscribed from.
      </p>
    </div>
  `;

  const text = `
--
${SENDER_LEGAL_ENTITY.company} • ${SENDER_LEGAL_ENTITY.physicalAddress}
This is an automated essential security or transactional notice delivered under ${metadata.legalBasis}.
Support: ${SENDER_LEGAL_ENTITY.supportEmail}
  `.trim();

  return { html, text };
}

/**
 * --------------------------------------------------------------------------
 * CENTRAL DISPATCHER ENGINE
 * --------------------------------------------------------------------------
 */
export async function sendEmail(options: {
  toEmail: string;
  category: EmailCategory;
  subject: string;
  htmlContent: string;
  textContent: string;
  recipientName?: string | null;
  dryRun?: boolean;
  purpose?: EmailPurpose;
}): Promise<{
  success: boolean;
  simulated: boolean;
  suppressed?: boolean;
  messageId?: string;
  error?: string;
  headers?: Record<string, string>;
}> {
  const { toEmail, category, subject, htmlContent, textContent, recipientName, dryRun } = options;
  const normalizedEmail = toEmail.toLowerCase().trim();
  const metadata = EMAIL_CATEGORY_METADATA[category] || EMAIL_CATEGORY_METADATA.ACCOUNT_TRANSACTIONAL;

  // 1a. Consent Gate (Marketing only): no marketing email without the recipient's opt-in.
  if (metadata.senderProfile === 'MARKETING' && !(await hasMarketingConsent(normalizedEmail))) {
    console.log(`[EMAIL DISPATCH] BLOCKED: ${normalizedEmail} has not opted in to ${category}`);
    sentEmailsHistory.push({
      toEmail: normalizedEmail,
      category,
      subject,
      simulated: true,
      suppressed: true,
      sentAt: new Date().toISOString(),
    });
    return {
      success: false,
      simulated: true,
      suppressed: true,
      error: `Recipient ${normalizedEmail} has not opted in to marketing email.`,
    };
  }

  // 1b. Suppression List Gate (Marketing only)
  if (!metadata.isEssential && (await isEmailSuppressed(normalizedEmail, category))) {
    console.log(`[EMAIL DISPATCH] BLOCKED: ${normalizedEmail} is suppressed from ${category}`);
    const record: SentEmailRecord = {
      toEmail: normalizedEmail,
      category,
      subject,
      simulated: true,
      suppressed: true,
      sentAt: new Date().toISOString(),
    };
    sentEmailsHistory.push(record);
    return {
      success: false,
      simulated: true,
      suppressed: true,
      error: `Recipient ${normalizedEmail} has unsubscribed from ${category} communications.`,
    };
  }

  // 2. Sender Profile Selection
  const senderConfig = SENDER_PROFILES[metadata.senderProfile] || SENDER_PROFILES.TRANSACTIONAL;

  // 3. RFC 8058 One-Click Header Generation (Only for marketing)
  const headers: Record<string, string> = {};
  if (metadata.requiresUnsubscribeHeaders) {
    const unsubToken = generateUnsubscribeToken(normalizedEmail, category);
    const appBaseUrl = process.env.NEXT_PUBLIC_APP_URL || appUrl();
    headers['List-Unsubscribe'] = `<${appBaseUrl}/api/v1/email/unsubscribe?token=${unsubToken}>, <mailto:${site('unsubscribeEmail')}?subject=unsubscribe-${unsubToken}>`;
    headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
  }

  // 4. Construct Full HTML & Text Bodies with Legal Footers
  const footer = buildEmailFooter(category, normalizedEmail);
  const fullHtml = htmlContent.includes('</body>')
    ? htmlContent.replace('</body>', `${footer.html}</body>`)
    : `${htmlContent}\n${footer.html}`;
  const fullText = `${textContent}\n\n${footer.text}`;

  // 5. Safety Dry-Run Gate (Prevents accidental mass delivery to real users)
  if (dryRun) {
    const record: SentEmailRecord = {
      toEmail: normalizedEmail,
      category,
      subject,
      simulated: true,
      headers,
      sentAt: new Date().toISOString(),
    };
    sentEmailsHistory.push(record);
    return { success: true, simulated: true, headers };
  }

  const resolvedPurpose: EmailPurpose = options.purpose ||
    (category === 'SECURITY_OTP' ? 'VERIFY' : category === 'ACCOUNT_TRANSACTIONAL' ? 'RECOVERY' : 'DEFAULT');

  // 6a. Resend HTTPS API. Used whenever RESEND_API_KEY is set: hosts such as Render's free
  // tier block outbound SMTP ports, so there is no SMTP fallback (it would only add timeouts).
  if (isResendConfigured()) {
    const result = await sendViaResend({
      from: resendFromAddress(resolvedPurpose),
      to: normalizedEmail,
      replyTo: senderConfig.replyTo,
      subject,
      html: fullHtml,
      text: fullText,
      headers,
    });
    if (result.success) {
      console.log(`[EMAIL DISPATCH] Dispatched via Resend (${resolvedPurpose}) to ${normalizedEmail} (${category}, id: ${result.messageId})`);
      sentEmailsHistory.push({
        toEmail: normalizedEmail,
        category,
        subject,
        simulated: false,
        headers,
        messageId: result.messageId,
        sentAt: new Date().toISOString(),
      });
      return { success: true, simulated: false, messageId: result.messageId, headers };
    }
    console.error(`[EMAIL DISPATCH] NOT SENT via Resend to ${normalizedEmail} (${category}): ${result.error}`);
    return { success: false, simulated: false, error: result.error, headers };
  }

  // 6b. SMTP Dispatch (local development, or hosts that allow outbound SMTP)
  const smtpResult = getTransporter(resolvedPurpose);
  if (smtpResult) {
    try {
      const from = smtpResult.from || senderConfig.from;
      const sendPromise = smtpResult.transporter.sendMail({
        from,
        to: normalizedEmail,
        replyTo: senderConfig.replyTo,
        subject,
        text: fullText,
        html: fullHtml,
        headers,
      });

      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('SMTP dispatch timed out after 15000ms')), 15000)
      );

      const info = await Promise.race([sendPromise, timeoutPromise]);

      console.log(`[EMAIL DISPATCH] Dispatched via ${resolvedPurpose} SMTP (${smtpResult.user}) to ${normalizedEmail} (${category}, id: ${info.messageId})`);
      const record: SentEmailRecord = {
        toEmail: normalizedEmail,
        category,
        subject,
        simulated: false,
        headers,
        messageId: info.messageId,
        sentAt: new Date().toISOString(),
      };
      sentEmailsHistory.push(record);
      return { success: true, simulated: false, messageId: info.messageId, headers };
    } catch (err: any) {
      console.error(`[EMAIL DISPATCH ERROR] Primary SMTP attempt failed to ${normalizedEmail}:`, err.message);

      // Retry the same provider over SSL port 465 (handles cloud port 587 blockages)
      try {
        console.log(`[EMAIL DISPATCH RETRY] Attempting direct SSL port 465 fallback for ${normalizedEmail}...`);
        const fallbackTransporter = nodemailer.createTransport({
          host: smtpResult.host,
          port: 465,
          secure: true,
          auth: {
            user: smtpResult.user,
            pass: smtpResult.pass,
          },
          connectionTimeout: 10000,
          greetingTimeout: 10000,
          socketTimeout: 15000,
        });

        const fallbackFrom = smtpResult.from || site('fromVerifySmtp');
        const fallbackPromise = fallbackTransporter.sendMail({
          from: fallbackFrom,
          to: normalizedEmail,
          replyTo: senderConfig.replyTo,
          subject,
          text: fullText,
          html: fullHtml,
          headers,
        });

        const fallbackTimeout = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Fallback SMTP timed out after 15000ms')), 15000)
        );

        const fbInfo = await Promise.race([fallbackPromise, fallbackTimeout]);
        console.log(`[EMAIL DISPATCH SUCCESS] Dispatched via port 465 SSL fallback to ${normalizedEmail} (${category}, id: ${fbInfo.messageId})`);
        const record: SentEmailRecord = {
          toEmail: normalizedEmail,
          category,
          subject,
          simulated: false,
          headers,
          messageId: fbInfo.messageId,
          sentAt: new Date().toISOString(),
        };
        sentEmailsHistory.push(record);
        return { success: true, simulated: false, messageId: fbInfo.messageId, headers };
      } catch (fbErr: any) {
        console.error(`[EMAIL DISPATCH ERROR] Fallback port 465 also failed:`, fbErr.message);
      }
    }
  }

  // 7. Outside the test runner, an unsent email is a failure, never a simulated success.
  if (!isTestEnv()) {
    const reason = smtpResult
      ? 'SMTP delivery failed on both the configured port and port 465.'
      : `SMTP is not configured for ${resolvedPurpose} email.`;
    console.error(`[EMAIL DISPATCH] NOT SENT to ${normalizedEmail} (${category}): ${reason}`);
    return { success: false, simulated: false, error: reason, headers };
  }

  // Test runner only: record the email instead of sending it.
  console.log(`\n======================================================`);
  console.log(`[EMAIL SERVICE SIMULATION] Category: ${category}`);
  console.log(`To:          ${normalizedEmail}`);
  console.log(`From:        ${senderConfig.from}`);
  console.log(`Subject:     ${subject}`);
  if (headers['List-Unsubscribe']) {
    console.log(`List-Unsub:  ${headers['List-Unsubscribe']}`);
  }
  console.log(`======================================================\n`);

  const record: SentEmailRecord = {
    toEmail: normalizedEmail,
    category,
    subject,
    simulated: true,
    headers,
    sentAt: new Date().toISOString(),
  };
  sentEmailsHistory.push(record);
  return { success: true, simulated: true, headers };
}

/**
 * --------------------------------------------------------------------------
 * APPLICATION SPECIFIC MAILERS
 * --------------------------------------------------------------------------
 */

/**
 * 1. Dispatch an OTP Verification Code (Category: SECURITY_OTP)
 */
export async function sendOtpEmail(
  toEmail: string,
  otp: string,
  recipientName?: string | null
): Promise<{ success: boolean; simulated: boolean; messageId?: string; headers?: Record<string, string> }> {
  const safeName = recipientName ? escapeHtml(recipientName) : null;
  const safeOtp = escapeHtml(otp);
  const nameGreeting = safeName ? `Hello <strong>${safeName}</strong>,` : 'Hello,';

  const subject = `Your AMARACUS Verification Code: ${otp}`;
  const textContent = `Your AMARACUS verification code is: ${otp}. It will expire in 10 minutes. Do not share this code with anyone.`;
  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AMARACUS Security Verification</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #F8F7F4; margin: 0; padding: 24px; color: #1A1A1A; }
    .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E9EDE7; padding: 36px 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .brand { display: flex; align-items: center; gap: 8px; margin-bottom: 24px; }
    .logo-badge { display: inline-block; width: 32px; height: 32px; background: #EAF3EC; border: 1px solid #C8E0CF; border-radius: 8px; text-align: center; line-height: 32px; color: #008031; font-weight: bold; font-size: 16px; }
    .brand-title { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; color: #1A1A1A; margin-left: 8px; vertical-align: middle; }
    h1 { font-size: 20px; font-weight: 700; color: #1A1A1A; margin: 0 0 12px; }
    p { font-size: 14px; line-height: 1.6; color: #555555; margin: 0 0 20px; }
    .otp-box { background: #F3F8F4; border: 1.5px dashed #008031; border-radius: 12px; padding: 18px 24px; text-align: center; margin: 28px 0; }
    .otp-code { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #008031; margin: 0; }
    .otp-caption { font-size: 12px; color: #636863; margin-top: 6px; }
    .badge { display: inline-block; padding: 4px 8px; background: #EAF3EC; color: #008031; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">
      <span class="logo-badge">🛡️</span>
      <span class="brand-title">AMARACUS</span>
    </div>
    <span class="badge">Security Verification</span>
    <h1>Confirm your email address</h1>
    <p>${nameGreeting}</p>
    <p>Please enter the one-time verification code below to verify your email address and activate your cryptographic access:</p>
    
    <div class="otp-box">
      <div class="otp-code">${safeOtp}</div>
      <div class="otp-caption">Valid for 10 minutes • Do not share this code with anyone</div>
    </div>

    <p>If you did not request this verification code, you can safely ignore this email.</p>
  </div>
</body>
</html>
  `.trim();

  return sendEmail({
    toEmail,
    category: 'SECURITY_OTP',
    subject,
    htmlContent,
    textContent,
    recipientName,
    purpose: 'VERIFY',
  });
}

/**
 * Dispatch Password Reset Email with Direct Reset Link
 */
export async function sendPasswordResetEmail(params: {
  toEmail: string;
  resetLink: string;
  recipientName?: string | null;
}): Promise<{ success: boolean; simulated: boolean; messageId?: string }> {
  const safeName = params.recipientName ? escapeHtml(params.recipientName) : null;
  const nameGreeting = safeName ? `Hello <strong>${safeName}</strong>,` : 'Hello,';
  const subject = `Reset your AMARACUS account password`;
  const textContent = `You recently requested to reset your password for your AMARACUS account. Open this link to set a new password: ${params.resetLink}. This link is valid for 1 hour. If you did not request this, you can safely ignore this email.`;

  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AMARACUS Password Reset</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #F8F7F4; margin: 0; padding: 24px; color: #1A1A1A; }
    .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E9EDE7; padding: 36px 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .brand { display: flex; align-items: center; gap: 8px; margin-bottom: 24px; }
    .logo-badge { display: inline-block; width: 32px; height: 32px; background: #EAF3EC; border: 1px solid #C8E0CF; border-radius: 8px; text-align: center; line-height: 32px; color: #008031; font-weight: bold; font-size: 16px; }
    .brand-title { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; color: #1A1A1A; margin-left: 8px; vertical-align: middle; }
    h1 { font-size: 20px; font-weight: 700; color: #1A1A1A; margin: 0 0 12px; }
    p { font-size: 14px; line-height: 1.6; color: #555555; margin: 0 0 20px; }
    .btn { display: inline-block; background-color: #008031; color: #ffffff !important; text-decoration: none; padding: 14px 28px; border-radius: 10px; font-size: 14px; font-weight: 600; text-align: center; box-shadow: 0 2px 4px rgba(0,128,49,0.2); }
    .badge { display: inline-block; padding: 4px 8px; background: #EAF3EC; color: #008031; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">
      <span class="logo-badge">🛡️</span>
      <span class="brand-title">AMARACUS</span>
    </div>
    <span class="badge">Password Assistance</span>
    <h1>Reset your password</h1>
    <p>${nameGreeting}</p>
    <p>We received a request to reset your password for your AMARACUS account. Tap the button below to choose a new password:</p>

    <div style="text-align: center; margin: 28px 0;">
      <a href="${params.resetLink}" class="btn" target="_blank">Reset My Password &rarr;</a>
    </div>

    <p style="font-size: 12px; color: #767676; line-height: 1.6;">
      This password reset link will expire in 1 hour. If you did not request a password reset, you can safely disregard this email — your password remains completely secure.
    </p>
  </div>
</body>
</html>
  `.trim();

  return sendEmail({
    toEmail: params.toEmail,
    category: 'ACCOUNT_TRANSACTIONAL',
    subject,
    htmlContent,
    textContent,
    recipientName: params.recipientName,
    purpose: 'RECOVERY',
  });
}

/**
 * 2. Dispatch Hackathon Confirmation Receipt (Category: HACKATHON_RECEIPT)
 */
export async function sendHackathonConfirmationEmail(params: {
  toEmail: string;
  projectName: string;
  category: string;
  receiptToken: string;
  receiptHash: string;
  submissionDate: string;
}): Promise<{ success: boolean; simulated: boolean; headers?: Record<string, string> }> {
  const { toEmail, projectName, category, receiptToken, receiptHash, submissionDate } = params;
  const safeProjectName = escapeHtml(projectName);
  const safeCategory = escapeHtml(category);
  const safeReceiptToken = escapeHtml(receiptToken);
  const safeReceiptHash = escapeHtml(receiptHash);

  const subject = `[AMARACUS Hackathon 2026] Submission Confirmed: ${projectName} (${receiptToken})`;
  const textContent = `Congratulations! Your hackathon project "${projectName}" has been successfully submitted to the AMARACUS Cryptographic Innovation Hackathon 2026.\n\nReceipt Token: ${receiptToken}\nReceipt Hash: ${receiptHash}\nTrack: ${category}\nSubmitted At: ${submissionDate}\nPrize: GTA 6 or $100 USD\n\nEvaluation begins December 16, 2026.`;

  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AMARACUS Hackathon Submission Confirmation</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #F8F7F4; margin: 0; padding: 24px; color: #1A1A1A; }
    .container { max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E9EDE7; padding: 36px 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .badge { display: inline-block; padding: 4px 8px; background: #EAF3EC; color: #008031; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 16px; }
    .receipt-box { background: #F3F8F4; border: 1.5px dashed #008031; border-radius: 12px; padding: 18px 24px; margin: 24px 0; }
    .receipt-token { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 20px; font-weight: 800; color: #008031; margin: 0 0 6px 0; }
    .hash { font-family: monospace; font-size: 11px; color: #636863; word-break: break-all; }
  </style>
</head>
<body>
  <div class="container">
    <span class="badge">Official Hackathon Receipt • GTA 6 or $100 Prize</span>
    <h1 style="font-size: 22px; margin: 0 0 12px 0;">Project Submission Confirmed!</h1>
    <p style="font-size: 14px; color: #555555; line-height: 1.5;">
      Your project <strong>${safeProjectName}</strong> has been officially registered for the <strong>AMARACUS Cryptographic Innovation Hackathon 2026</strong>.
    </p>

    <div class="receipt-box">
      <div style="font-size: 11px; color: #636863; text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">Cryptographic Receipt Token</div>
      <div class="receipt-token">${safeReceiptToken}</div>
      <div class="hash">SHA-256 Signature: ${safeReceiptHash}</div>
    </div>

    <table style="width: 100%; font-size: 13px; color: #444444; border-collapse: collapse; margin-bottom: 20px;">
      <tr>
        <td style="padding: 6px 0; color: #767676;">Track / Category:</td>
        <td style="padding: 6px 0; font-weight: 600; text-align: right;">${safeCategory}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #767676;">Submitted At:</td>
        <td style="padding: 6px 0; font-weight: 600; text-align: right;">${submissionDate}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #767676;">Evaluation Window:</td>
        <td style="padding: 6px 0; font-weight: 600; text-align: right;">Dec 16 – Dec 22, 2026</td>
      </tr>
    </table>
  </div>
</body>
</html>
  `.trim();

  return sendEmail({
    toEmail,
    category: 'HACKATHON_RECEIPT',
    subject,
    htmlContent,
    textContent,
  });
}

/**
 * 3. Dispatch Security Alert Email (Category: SECURITY_ALERT)
 */
export async function sendSecurityAlertEmail(params: {
  toEmail: string;
  alertTitle: string;
  alertDetails: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recipientName?: string | null;
}): Promise<{ success: boolean; simulated: boolean; headers?: Record<string, string> }> {
  const { toEmail, alertTitle, alertDetails, severity = 'HIGH', recipientName } = params;
  const safeTitle = escapeHtml(alertTitle);
  const safeDetails = escapeHtml(alertDetails);

  const subject = `[AMARACUS SECURITY ALERT] ${alertTitle}`;
  const textContent = `SECURITY ALERT: ${alertTitle}\nSeverity: ${severity}\n\nDetails:\n${alertDetails}\n\nTimestamp: ${new Date().toISOString()}`;
  const htmlContent = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; background-color: #F8F7F4; padding: 24px;">
  <div style="max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E9EDE7; padding: 32px;">
    <div style="display: inline-block; padding: 4px 8px; background: #FEF3F2; color: #B42318; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; margin-bottom: 12px;">
      ${severity} Severity Alert
    </div>
    <h1 style="font-size: 20px; color: #1A1A1A; margin: 0 0 12px 0;">${safeTitle}</h1>
    <p style="font-size: 14px; color: #555555; line-height: 1.6;">${safeDetails}</p>
  </div>
</body>
</html>
  `.trim();

  return sendEmail({
    toEmail,
    category: 'SECURITY_ALERT',
    subject,
    htmlContent,
    textContent,
    recipientName,
  });
}

export interface UsageLimitWarningContent {
  planName: string;
  operationsUsed: number;
  includedOperations: number;
  resetsOn: Date;
  overageAuthorized: boolean;
  upgradeAdvice: string;
}

export function buildUsageLimitWarningEmail(params: UsageLimitWarningContent): { subject: string; textContent: string; htmlContent: string } {
  const { planName, operationsUsed, includedOperations, resetsOn, overageAuthorized, upgradeAdvice } = params;
  const used = operationsUsed.toLocaleString('en-US');
  const included = includedOperations.toLocaleString('en-US');
  const resetDate = new Date(resetsOn).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
  const billingUrl = `${appUrl()}/dashboard/billing`;
  const atLimit = overageAuthorized
    ? 'After that, operations continue at your overage rate until your overage spending limit is reached.'
    : 'When you reach the limit, operations stop until you upgrade or your allowance resets.';

  const subject = `You've used ${used} of your ${included} AMARACUS operations`;
  const intro = `Your ${planName} plan has used ${used} of the ${included} operations included this month.`;
  const textContent = `${intro}\n\n${atLimit} Your allowance resets on ${resetDate}.\n\n${upgradeAdvice}\n\nBilling page: ${billingUrl}`;
  const htmlContent = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; background-color: #F8F7F4; padding: 24px;">
  <div style="max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E9EDE7; padding: 32px;">
    <h1 style="font-size: 20px; color: #1A1A1A; margin: 0 0 12px 0;">Your plan is close to its limit</h1>
    <p style="font-size: 14px; color: #555555; line-height: 1.6;">${escapeHtml(intro)}</p>
    <p style="font-size: 14px; color: #555555; line-height: 1.6;">${escapeHtml(atLimit)} Your allowance resets on ${escapeHtml(resetDate)}.</p>
    <p style="font-size: 14px; color: #555555; line-height: 1.6;">${escapeHtml(upgradeAdvice)}</p>
    <a href="${escapeHtml(billingUrl)}" style="display: inline-block; margin-top: 8px; padding: 10px 18px; background-color: #008031; color: #ffffff; border-radius: 8px; font-size: 14px; font-weight: 600; text-decoration: none;">Go to billing</a>
  </div>
</body>
</html>
  `.trim();

  return { subject, textContent, htmlContent };
}

/**
 * Tells a billing contact that usage is near the monthly included operations.
 * A service notice about their own plan, so it is sent as BILLING_TRANSACTIONAL.
 */
export async function sendUsageLimitWarningEmail(
  params: UsageLimitWarningContent & { toEmail: string; recipientName?: string | null }
): Promise<{ success: boolean; simulated: boolean; headers?: Record<string, string> }> {
  return sendEmail({
    toEmail: params.toEmail,
    category: 'BILLING_TRANSACTIONAL',
    recipientName: params.recipientName,
    ...buildUsageLimitWarningEmail(params),
  });
}

/**
 * 4. Dispatch Product Announcement Email (Category: MARKETING_ANNOUNCEMENT)
 * Strictly requires active opt-in consent and respects the suppression list.
 */
export async function sendProductAnnouncementEmail(params: {
  toEmail: string;
  title: string;
  announcementBody: string;
  recipientName?: string | null;
  dryRun?: boolean;
}): Promise<{ success: boolean; simulated: boolean; suppressed?: boolean; headers?: Record<string, string> }> {
  const { toEmail, title, announcementBody, recipientName, dryRun } = params;
  const safeTitle = escapeHtml(title);
  const safeBody = escapeHtml(announcementBody);

  const subject = `[AMARACUS Update] ${title}`;
  const textContent = `${title}\n\n${announcementBody}`;
  const htmlContent = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; background-color: #F8F7F4; padding: 24px;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E9EDE7; padding: 32px;">
    <div style="display: inline-block; padding: 4px 8px; background: #EAF3EC; color: #008031; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 12px;">
      Product Announcement
    </div>
    <h1 style="font-size: 20px; color: #1A1A1A; margin: 0 0 16px 0;">${safeTitle}</h1>
    <p style="font-size: 14px; color: #555555; line-height: 1.6;">${safeBody}</p>
  </div>
</body>
</html>
  `.trim();

  return sendEmail({
    toEmail,
    category: 'MARKETING_ANNOUNCEMENT',
    subject,
    htmlContent,
    textContent,
    recipientName,
    dryRun,
  });
}

/**
 * 5. Dispatch Technical Newsletter Email (Category: MARKETING_NEWSLETTER)
 */
export async function sendNewsletterEmail(params: {
  toEmail: string;
  issueNumber: number;
  title: string;
  summary: string;
  recipientName?: string | null;
  dryRun?: boolean;
}): Promise<{ success: boolean; simulated: boolean; suppressed?: boolean; headers?: Record<string, string> }> {
  const { toEmail, issueNumber, title, summary, recipientName, dryRun } = params;
  const safeTitle = escapeHtml(title);
  const safeSummary = escapeHtml(summary);

  const subject = `AMARACUS Cryptographic Digest #${issueNumber}: ${title}`;
  const textContent = `AMARACUS Cryptographic Digest #${issueNumber}\n${title}\n\n${summary}`;
  const htmlContent = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; background-color: #F8F7F4; padding: 24px;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #E9EDE7; padding: 32px;">
    <div style="display: inline-block; padding: 4px 8px; background: #EAF3EC; color: #008031; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 12px;">
      Issue #${issueNumber} • Cryptographic Engineering
    </div>
    <h1 style="font-size: 20px; color: #1A1A1A; margin: 0 0 16px 0;">${safeTitle}</h1>
    <p style="font-size: 14px; color: #555555; line-height: 1.6;">${safeSummary}</p>
  </div>
</body>
</html>
  `.trim();

  return sendEmail({
    toEmail,
    category: 'MARKETING_NEWSLETTER',
    subject,
    htmlContent,
    textContent,
    recipientName,
    dryRun,
  });
}

/**
 * --------------------------------------------------------------------------
 * REGISTRATION PENDING SIGNUP HELPERS
 * --------------------------------------------------------------------------
 */
export async function savePendingSignup(data: {
  email: string;
  name: string | null;
  organizationName: string;
  passwordHash: string;
  otp: string;
  termsAccepted?: boolean;
  marketingOptIn?: boolean;
  ageAttested?: boolean;
}): Promise<void> {
  const normalizedEmail = data.email.toLowerCase().trim();
  const now = new Date();
  await storePendingSignup(
    normalizedEmail,
    {
      name: data.name,
      organizationName: data.organizationName,
      passwordHash: data.passwordHash,
      otpHash: hashOtp(normalizedEmail, data.otp),
      attempts: 0,
      createdAt: now,
      lastSentAt: now,
      termsAccepted: data.termsAccepted ?? true,
      termsAcceptedAt: now,
      marketingOptIn: data.marketingOptIn ?? false,
      ageAttested: data.ageAttested ?? true,
      ageAttestedAt: now,
    },
    new Date(now.getTime() + OTP_TTL_MS)
  );
}

/** Drops a pending signup, e.g. when its verification email could not be sent. */
export async function discardPendingSignup(email: string): Promise<void> {
  await db.deleteVerification(signupIdentifier(email));
}

export async function canResendOtp(email: string): Promise<{ allowed: boolean; waitSeconds: number }> {
  const pending = await loadPendingSignup(email);
  if (!pending) return { allowed: true, waitSeconds: 0 };

  const elapsedSeconds = Math.floor((Date.now() - pending.lastSentAt.getTime()) / 1000);
  if (elapsedSeconds < OTP_RESEND_COOLDOWN_SECONDS) {
    return { allowed: false, waitSeconds: OTP_RESEND_COOLDOWN_SECONDS - elapsedSeconds };
  }
  return { allowed: true, waitSeconds: 0 };
}

export async function getPendingSignup(email: string): Promise<PendingSignup | undefined> {
  const normalizedEmail = email.toLowerCase().trim();
  const pending = await loadPendingSignup(normalizedEmail);
  if (!pending) return undefined;
  const { otpHash: _otpHash, lastSentAt: _lastSentAt, ...rest } = pending;
  return { ...rest, email: normalizedEmail };
}

export async function verifyAndConsumeOtp(
  email: string,
  enteredOtp: string
): Promise<{ success: boolean; error?: string; pendingData?: PendingSignup }> {
  const normalizedEmail = email.toLowerCase().trim();
  const pending = await loadPendingSignup(normalizedEmail);

  if (!pending) {
    return {
      success: false,
      error: 'No pending registration found for this email, or the code has expired. Please sign up again.',
    };
  }

  if (new Date() > pending.expiresAt) {
    await discardPendingSignup(normalizedEmail);
    return {
      success: false,
      error: 'The verification code has expired. Please request a new code.',
    };
  }

  const attempts = pending.attempts + 1;
  if (attempts > OTP_MAX_ATTEMPTS) {
    await discardPendingSignup(normalizedEmail);
    return {
      success: false,
      error: 'Too many incorrect attempts. For your security, this registration request has been canceled. Please start over.',
    };
  }

  const expected = Buffer.from(pending.otpHash, 'hex');
  const actual = Buffer.from(hashOtp(normalizedEmail, enteredOtp.trim()), 'hex');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    const { expiresAt, ...stored } = pending;
    await storePendingSignup(normalizedEmail, { ...stored, attempts }, expiresAt);
    const remaining = OTP_MAX_ATTEMPTS - attempts;
    return {
      success: false,
      error: `Invalid verification code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`,
    };
  }

  await discardPendingSignup(normalizedEmail);
  const { otpHash: _otpHash, lastSentAt: _lastSentAt, ...pendingData } = pending;
  return {
    success: true,
    pendingData: { ...pendingData, attempts, email: normalizedEmail },
  };
}
