import { describeCloud, itCloud } from './helpers/edition';
import fs from 'fs';
import path from 'path';
import http from 'http';
import express from 'express';
import emailRouter from '../src/routes/v1/email';
import {
  EMAIL_CATEGORY_METADATA,
  EmailCategory,
  generateUnsubscribeToken,
  verifyUnsubscribeToken,
  addToSuppressionList,
  removeFromSuppressionList,
  isEmailSuppressed,
  clearSuppressionList,
  sendOtpEmail,
  sendHackathonConfirmationEmail,
  sendSecurityAlertEmail,
  sendProductAnnouncementEmail,
  sendNewsletterEmail,
  getSentEmailsHistory,
  clearSentEmailsHistory,
  SENDER_LEGAL_ENTITY,
  SENDER_PROFILES,
} from '../src/lib/email-service';
import { db } from '../src/lib/data-store';
import { setUserPreferences } from '../src/lib/user-preferences';

/** Gives an address an account that has opted in to marketing email, as signup or Settings would. */
async function optInToMarketing(email: string) {
  const user = (await db.findUserByEmail(email)) || (await db.createUser({ email, passwordHash: 'test-hash' }));
  await setUserPreferences(user.id, { marketingEmails: true });
}

describe('Audit: Outbound Email Communications, Taxonomy & Unsubscribe Architecture', () => {
  let app: express.Express;
  let server: http.Server;
  let baseUrl: string;

  beforeAll((done) => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use('/v1/email', emailRouter);

    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address() as any;
      baseUrl = `http://127.0.0.1:${addr.port}`;
      done();
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        if (typeof (server as any).closeAllConnections === 'function') {
          (server as any).closeAllConnections();
        }
        server.close(() => {
          resolve();
        });
      });
      await new Promise((r) => setTimeout(r, 100));
    }
  });

  beforeEach(() => {
    clearSuppressionList();
    clearSentEmailsHistory();
  });

  describe('1. Message Classification & Taxonomy', () => {
    test('All 9 formal email categories are defined with explicit metadata', () => {
      const categories: EmailCategory[] = [
        'SECURITY_OTP',
        'SECURITY_ALERT',
        'SECURITY_INCIDENT',
        'ACCOUNT_TRANSACTIONAL',
        'BILLING_TRANSACTIONAL',
        'HACKATHON_RECEIPT',
        'MARKETING_ANNOUNCEMENT',
        'MARKETING_NEWSLETTER',
        'MARKETING_PROMOTION',
      ];

      for (const cat of categories) {
        expect(EMAIL_CATEGORY_METADATA[cat]).toBeDefined();
        expect(EMAIL_CATEGORY_METADATA[cat].legalBasis).toBeDefined();
        expect(EMAIL_CATEGORY_METADATA[cat].senderProfile).toBeDefined();
      }
    });

    test('Essential security and transactional emails are strictly segregated from marketing', () => {
      // Essential categories must NOT have unsubscribe headers
      expect(EMAIL_CATEGORY_METADATA.SECURITY_OTP.isEssential).toBe(true);
      expect(EMAIL_CATEGORY_METADATA.SECURITY_OTP.requiresUnsubscribeHeaders).toBe(false);

      expect(EMAIL_CATEGORY_METADATA.SECURITY_ALERT.isEssential).toBe(true);
      expect(EMAIL_CATEGORY_METADATA.SECURITY_ALERT.requiresUnsubscribeHeaders).toBe(false);

      expect(EMAIL_CATEGORY_METADATA.SECURITY_INCIDENT.isEssential).toBe(true);
      expect(EMAIL_CATEGORY_METADATA.SECURITY_INCIDENT.requiresUnsubscribeHeaders).toBe(false);

      expect(EMAIL_CATEGORY_METADATA.ACCOUNT_TRANSACTIONAL.isEssential).toBe(true);
      expect(EMAIL_CATEGORY_METADATA.ACCOUNT_TRANSACTIONAL.requiresUnsubscribeHeaders).toBe(false);

      expect(EMAIL_CATEGORY_METADATA.BILLING_TRANSACTIONAL.isEssential).toBe(true);
      expect(EMAIL_CATEGORY_METADATA.BILLING_TRANSACTIONAL.requiresUnsubscribeHeaders).toBe(false);

      expect(EMAIL_CATEGORY_METADATA.HACKATHON_RECEIPT.isEssential).toBe(true);
      expect(EMAIL_CATEGORY_METADATA.HACKATHON_RECEIPT.requiresUnsubscribeHeaders).toBe(false);

      // Marketing categories MUST have unsubscribe headers and footer
      expect(EMAIL_CATEGORY_METADATA.MARKETING_ANNOUNCEMENT.isEssential).toBe(false);
      expect(EMAIL_CATEGORY_METADATA.MARKETING_ANNOUNCEMENT.requiresUnsubscribeHeaders).toBe(true);
      expect(EMAIL_CATEGORY_METADATA.MARKETING_ANNOUNCEMENT.requiresUnsubscribeFooter).toBe(true);

      expect(EMAIL_CATEGORY_METADATA.MARKETING_NEWSLETTER.isEssential).toBe(false);
      expect(EMAIL_CATEGORY_METADATA.MARKETING_NEWSLETTER.requiresUnsubscribeHeaders).toBe(true);

      expect(EMAIL_CATEGORY_METADATA.MARKETING_PROMOTION.isEssential).toBe(false);
      expect(EMAIL_CATEGORY_METADATA.MARKETING_PROMOTION.requiresUnsubscribeHeaders).toBe(true);
    });
  });

  describe('2. Cryptographic HMAC Unsubscribe Token Engine', () => {
    const testEmail = 'developer@enterprise-security.org';

    test('Generates verifiable HMAC-SHA256 tokens without plain PII query parameters', () => {
      const token = generateUnsubscribeToken(testEmail, 'MARKETING_ANNOUNCEMENT');
      expect(typeof token).toBe('string');
      expect(token).toContain('.');

      const result = verifyUnsubscribeToken(token);
      expect(result.valid).toBe(true);
      expect(result.email).toBe(testEmail);
      expect(result.category).toBe('MARKETING_ANNOUNCEMENT');
    });

    test('Rejects tampered tokens or altered signatures', () => {
      const token = generateUnsubscribeToken(testEmail, 'ALL_MARKETING');
      const parts = token.split('.');
      // Tamper with signature
      const tamperedSignature = parts[1].replace(/^[a-f0-9]/, 'x');
      const tamperedToken = `${parts[0]}.${tamperedSignature}`;

      const result = verifyUnsubscribeToken(tamperedToken);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/Invalid cryptographic signature/);
    });

    test('Rejects malformed tokens', () => {
      expect(verifyUnsubscribeToken('invalid-token')).toEqual({
        valid: false,
        error: 'Malformed token structure.',
      });
      expect(verifyUnsubscribeToken('')).toEqual({
        valid: false,
        error: 'Missing or invalid token format.',
      });
    });
  });

  describe('3. Suppression List & Pre-Send Gating', () => {
    const targetEmail = 'user-to-suppress@cyber-corp.io';

    test('Marketing email is never sent to an address that has not opted in', async () => {
      const res = await sendProductAnnouncementEmail({
        toEmail: 'never-opted-in@cyber-corp.io',
        title: 'New Feature',
        announcementBody: 'Body',
      });
      expect(res.success).toBe(false);
      expect(res.error).toContain('has not opted in');
    });

    test('Pre-send check suppresses marketing emails for unsubscribed recipients', async () => {
      await optInToMarketing(targetEmail);
      // 1. Initially unsuppressed
      expect(await isEmailSuppressed(targetEmail, 'MARKETING_ANNOUNCEMENT')).toBe(false);

      const res1 = await sendProductAnnouncementEmail({
        toEmail: targetEmail,
        title: 'New NIST FIPS 203 ML-KEM Algorithm Ready',
        announcementBody: 'We have updated our post-quantum key encapsulation mechanism.',
      });
      expect(res1.success).toBe(true);
      expect(res1.suppressed).toBeFalsy();

      // 2. Add to suppression list
      await addToSuppressionList({
        email: targetEmail,
        source: 'UNSUBSCRIBE_LINK',
        reason: 'Customer clicked 1-click unsubscribe',
      });
      expect(await isEmailSuppressed(targetEmail, 'MARKETING_ANNOUNCEMENT')).toBe(true);

      // 3. Marketing send is blocked by pre-send gate
      const res2 = await sendProductAnnouncementEmail({
        toEmail: targetEmail,
        title: 'Enterprise Cryptographic Suite Upgrade',
        announcementBody: 'Check out new hardware HSM features.',
      });
      expect(res2.success).toBe(false);
      expect(res2.suppressed).toBe(true);

      // 4. Newsletter send is also blocked
      const res3 = await sendNewsletterEmail({
        toEmail: targetEmail,
        issueNumber: 12,
        title: 'Quantum Advantage Benchmarks',
        summary: 'Latest lattice-based performance figures.',
      });
      expect(res3.success).toBe(false);
      expect(res3.suppressed).toBe(true);
    });

    test('Suppression of marketing NEVER blocks essential security OTPs or incident notices', async () => {
      await addToSuppressionList({
        email: targetEmail,
        source: 'USER_SETTINGS',
        reason: 'User opted out of commercial promotions',
      });

      // Essential Security OTP is NEVER suppressed
      const otpRes = await sendOtpEmail(targetEmail, '839201', 'Alice');
      expect(otpRes.success).toBe(true);

      // Essential Security Alert is NEVER suppressed
      const alertRes = await sendSecurityAlertEmail({
        toEmail: targetEmail,
        alertTitle: 'Critical Key Rotation Advisory',
        alertDetails: 'Your master signing key is approaching its 90-day lifecycle limit.',
        severity: 'HIGH',
      });
      expect(alertRes.success).toBe(true);

      // Essential Hackathon Receipt is NEVER suppressed
      const hackathonRes = await sendHackathonConfirmationEmail({
        toEmail: targetEmail,
        projectName: 'QuantumGuard',
        category: 'POST_QUANTUM_CRYPTO',
        receiptToken: 'RCPT-AMARACUS-TEST-99',
        receiptHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        submissionDate: '2026-10-16 14:00 UTC',
      });
      expect(hackathonRes.success).toBe(true);
    });

    test('Re-subscribing removes address from suppression list', async () => {
      await addToSuppressionList({
        email: targetEmail,
        source: 'ONE_CLICK_POST',
      });
      expect(await isEmailSuppressed(targetEmail, 'MARKETING_ANNOUNCEMENT')).toBe(true);

      await removeFromSuppressionList(targetEmail);
      expect(await isEmailSuppressed(targetEmail, 'MARKETING_ANNOUNCEMENT')).toBe(false);
    });
  });

  describeCloud('4. Deliverability Headers (RFC 8058 One-Click)', () => {
    test('Marketing emails inject List-Unsubscribe and List-Unsubscribe-Post headers', async () => {
      const email = 'marketing-recipient@domain.com';
      await optInToMarketing(email);
      const result = await sendProductAnnouncementEmail({
        toEmail: email,
        title: 'Post-Quantum SDK 2.0 Released',
        announcementBody: 'Discover unified cryptographic primitives.',
      });

      expect(result.headers).toBeDefined();
      expect(result.headers!['List-Unsubscribe']).toMatch(/<https:\/\/.*\/api\/v1\/email\/unsubscribe\?token=.*>/);
      expect(result.headers!['List-Unsubscribe-Post']).toBe('List-Unsubscribe=One-Click');
    });

    test('Security OTP emails do NOT inject List-Unsubscribe headers', async () => {
      const email = 'security-user@domain.com';
      const result = await sendOtpEmail(email, '554433');

      expect(result.headers).toBeDefined();
      expect(result.headers!['List-Unsubscribe']).toBeUndefined();
      expect(result.headers!['List-Unsubscribe-Post']).toBeUndefined();
    });
  });

  describeCloud('5. Sender Identity & Footers (CAN-SPAM / DPDPA / GDPR)', () => {
    test('Sender identity and business contact details are configured', () => {
      expect(SENDER_LEGAL_ENTITY.company).toBe('Amaracus Technologies');
      expect(SENDER_LEGAL_ENTITY.physicalAddress).toContain('Bengaluru, Karnataka 560103, India');
      expect(SENDER_LEGAL_ENTITY.supportEmail).toBe('support@amaracus.tech');
      expect(SENDER_LEGAL_ENTITY.privacyEmail).toBe('privacy@amaracus.tech');
      expect(SENDER_LEGAL_ENTITY.grievanceEmail).toBe('grievance@amaracus.tech');
    });

    test('Sender profiles use legitimate @amaracus.tech inboxes', () => {
      expect(SENDER_PROFILES.SECURITY.from).toContain('security@amaracus.tech');
      expect(SENDER_PROFILES.TRANSACTIONAL.from).toContain('noreply@amaracus.tech');
      expect(SENDER_PROFILES.MARKETING.from).toContain('updates@amaracus.tech');
    });
  });

  describe('6. REST API Endpoints (/v1/email)', () => {
    test('GET /v1/email/categories returns formal taxonomy and compliance metadata', async () => {
      const res = await fetch(`${baseUrl}/v1/email/categories`);
      const body = (await res.json()) as any;
      expect(res.status).toBe(200);
      expect(body.data.categories).toBeDefined();
      expect(body.data.standardsCompliance.rfc8058OneClick).toBe(true);
      expect(body.data.standardsCompliance.canSpamAct15USC7701).toBe(true);
    });

    test('GET /v1/email/unsubscribe with valid token suppresses email and returns 200', async () => {
      const email = 'api-test-recipient@domain.com';
      const token = generateUnsubscribeToken(email, 'MARKETING_ANNOUNCEMENT');

      const res = await fetch(`${baseUrl}/v1/email/unsubscribe?token=${token}`);
      const body = (await res.json()) as any;
      expect(res.status).toBe(200);
      expect(body.data.unsubscribed).toBe(true);
      expect(body.data.maskedEmail).toMatch(/ap\*\*\*@domain\.com/);
      expect(body.data.essentialNoticesNotice).toContain('Essential security and account notices');

      // Verify email is now in suppression list
      expect(await isEmailSuppressed(email, 'MARKETING_ANNOUNCEMENT')).toBe(true);
    });

    test('GET /v1/email/unsubscribe with missing or tampered token returns 400', async () => {
      const resNoToken = await fetch(`${baseUrl}/v1/email/unsubscribe`);
      const bodyNoToken = (await resNoToken.json()) as any;
      expect(resNoToken.status).toBe(400);
      expect(bodyNoToken.error.code).toBe('MISSING_TOKEN');

      const resBadToken = await fetch(`${baseUrl}/v1/email/unsubscribe?token=malformed.payload`);
      const bodyBadToken = (await resBadToken.json()) as any;
      expect(resBadToken.status).toBe(400);
      expect(bodyBadToken.error.code).toBe('INVALID_TOKEN');
    });

    test('POST /v1/email/unsubscribe (RFC 8058 One-Click) returns HTTP 200 and suppresses', async () => {
      const email = 'rfc8058-client@gmail-style-mail.com';
      const token = generateUnsubscribeToken(email, 'ALL_MARKETING');

      const res = await fetch(`${baseUrl}/v1/email/unsubscribe?token=${token}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'List-Unsubscribe=One-Click',
      });
      const body = (await res.json()) as any;

      expect(res.status).toBe(200);
      expect(body.data.unsubscribed).toBe(true);
      expect(body.data.standard).toBe('RFC_8058');
      expect(await isEmailSuppressed(email, 'MARKETING_ANNOUNCEMENT')).toBe(true);
    });

    test('POST /v1/email/resubscribe needs the signed token, not just an address', async () => {
      const email = 'accidental-unsub@company.com';
      await addToSuppressionList({ email, source: 'UNSUBSCRIBE_LINK' });
      expect(await isEmailSuppressed(email, 'MARKETING_ANNOUNCEMENT')).toBe(true);

      // A typed address would let anyone opt anyone in.
      const forged = await fetch(`${baseUrl}/v1/email/resubscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      expect(forged.status).toBe(400);
      expect(await isEmailSuppressed(email, 'MARKETING_ANNOUNCEMENT')).toBe(true);

      const res = await fetch(`${baseUrl}/v1/email/resubscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: generateUnsubscribeToken(email, 'ALL_MARKETING') }),
      });
      const body = (await res.json()) as any;

      expect(res.status).toBe(200);
      expect(body.data.resubscribed).toBe(true);
      expect(await isEmailSuppressed(email, 'MARKETING_ANNOUNCEMENT')).toBe(false);
    });

    test('GET /v1/email/suppression-status is not public (it would reveal who unsubscribed)', async () => {
      const email = 'check-suppressed@example.com';
      await addToSuppressionList({ email, source: 'ADMIN' });

      const res = await fetch(`${baseUrl}/v1/email/suppression-status?email=${encodeURIComponent(email)}`);
      expect(res.status).toBe(401);
    });
  });

  describeCloud('7. Web Client Unsubscribe Interface & Public Links', () => {
    const webSrcRoot = path.resolve(__dirname, '../../web/src');

    test('Unsubscribe page exists with Suspense boundary and accessible states', () => {
      const pagePath = path.resolve(webSrcRoot, 'app/unsubscribe/page.tsx');
      expect(fs.existsSync(pagePath)).toBe(true);
      const content = fs.readFileSync(pagePath, 'utf8');

      expect(content).toContain('Unsubscribe Management');
      expect(content).toContain('Essential Security &amp; Transactional Notice');
      expect(content).toContain('Suspense');
      expect(content).toContain('Re-subscribe');
    });

    test('Public footer links to /unsubscribe', () => {
      const footerPath = path.resolve(webSrcRoot, 'components/public-footer.tsx');
      const content = fs.readFileSync(footerPath, 'utf8');
      expect(content).toContain('href="/unsubscribe"');
      expect(content).toContain('Email &amp; Unsubscribe');
    });
  });
});
