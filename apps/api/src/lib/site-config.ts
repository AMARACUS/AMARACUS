import { isSelfHosted } from './edition';

/**
 * Addresses and names that identify who runs this installation: URLs, contact mailboxes,
 * email senders and the legal sender shown in email footers.
 *
 * AMARACUS Cloud's own values are defaults of the hosted service and live in the Cloud-only
 * module (`../cloud/site-defaults`), which the public source tree does not contain. A
 * self-hosted installation takes every value from its own environment and never falls back
 * to AMARACUS's domains, mailboxes or servers.
 */
export type SiteKey =
  | 'appUrl'
  | 'apiUrl'
  | 'supportEmail'
  | 'privacyEmail'
  | 'grievanceEmail'
  | 'securityEmail'
  | 'unsubscribeEmail'
  | 'fromSecurity'
  | 'fromNotifications'
  | 'fromMarketing'
  | 'fromVerify'
  | 'fromRecovery'
  | 'fromDefault'
  | 'fromVerifySmtp'
  | 'fromRecoverySmtp'
  | 'fromDefaultSmtp'
  | 'legalCompany'
  | 'legalAddress';

let cloudDefaults: Partial<Record<SiteKey, string>> | null | undefined;

/** A default of the hosted service, or '' in a tree without the Cloud module. */
export function cloudDefault(key: SiteKey): string {
  if (cloudDefaults === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      cloudDefaults = require('../cloud/site-defaults').CLOUD_SITE_DEFAULTS;
    } catch {
      cloudDefaults = null;
    }
  }
  return cloudDefaults?.[key] || '';
}

function env(...names: string[]): string {
  for (const n of names) {
    const v = process.env[n]?.trim();
    if (v) return v;
  }
  return '';
}

function stripSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

/** The bare address inside a From line such as `"Name" <a@b.c>`. */
export function addressOf(from: string): string {
  const m = /<([^>]+)>/.exec(from);
  return (m ? m[1] : from).trim();
}

function selfHostedAppUrl(): string {
  return stripSlash(env('APP_URL', 'NEXT_PUBLIC_APP_URL') || 'http://localhost:3000');
}

function selfHostedDefaultFrom(): string {
  const from = env('EMAIL_FROM_DEFAULT', 'SMTP_FROM');
  if (from) return from;
  let host = 'localhost';
  try {
    host = new URL(selfHostedAppUrl()).hostname;
  } catch {
    // keep localhost
  }
  return `noreply@${host}`;
}

function selfHostedValue(key: SiteKey): string {
  const defaultFrom = selfHostedDefaultFrom();
  const support = env('SUPPORT_EMAIL') || addressOf(defaultFrom);
  switch (key) {
    case 'appUrl':
      return selfHostedAppUrl();
    case 'apiUrl':
      return stripSlash(env('API_URL', 'NEXT_PUBLIC_API_URL') || `http://localhost:${process.env.PORT || 4000}`);
    case 'supportEmail':
      return support;
    case 'privacyEmail':
      return env('PRIVACY_EMAIL') || support;
    case 'grievanceEmail':
      return env('GRIEVANCE_EMAIL', 'PRIVACY_EMAIL') || support;
    case 'securityEmail':
      return env('SECURITY_EMAIL') || support;
    case 'unsubscribeEmail':
      return env('UNSUBSCRIBE_EMAIL') || support;
    case 'fromSecurity':
      return env('SMTP_FROM_SECURITY') || defaultFrom;
    case 'fromNotifications':
      return env('SMTP_FROM_NOTIFICATIONS') || defaultFrom;
    case 'fromMarketing':
      return env('SMTP_FROM_MARKETING') || defaultFrom;
    case 'fromVerify':
      return env('EMAIL_FROM_VERIFY') || defaultFrom;
    case 'fromRecovery':
      return env('EMAIL_FROM_RECOVERY') || defaultFrom;
    case 'fromDefault':
      return defaultFrom;
    case 'fromVerifySmtp':
      return env('VERIFY_SMTP_FROM') || defaultFrom;
    case 'fromRecoverySmtp':
      return env('RECOVERY_SMTP_FROM') || defaultFrom;
    case 'fromDefaultSmtp':
      return env('SMTP_FROM') || defaultFrom;
    case 'legalCompany':
      return env('ORGANIZATION_LEGAL_NAME') || 'The operator of this AMARACUS installation';
    case 'legalAddress':
      return env('ORGANIZATION_POSTAL_ADDRESS') || 'Postal address not configured (set ORGANIZATION_POSTAL_ADDRESS)';
  }
}

/**
 * The value for this installation. On Cloud it is the hosted service's default (environment
 * overrides keep working exactly where they did before, at the call sites).
 */
export function site(key: SiteKey): string {
  if (isSelfHosted()) return selfHostedValue(key);
  return cloudDefault(key) || selfHostedValue(key);
}

/** Public URL of the web console, without a trailing slash. */
export function appUrl(): string {
  if (isSelfHosted()) return selfHostedAppUrl();
  return stripSlash(env('APP_URL', 'NEXT_PUBLIC_APP_URL') || cloudDefault('appUrl') || 'http://localhost:3000');
}
