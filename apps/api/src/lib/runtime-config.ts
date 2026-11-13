import { masterKeyEnvNames } from '@amaracus/crypto-core';
import { editionConfigErrors, getEdition } from './edition';

/**
 * Central runtime configuration checks.
 *
 * Secrets have no hardcoded fallbacks. Outside the Jest runner the API refuses
 * to boot unless every required secret is present and long enough.
 */

export const MIN_SECRET_LENGTH = 32;

export function isTestEnv(): boolean {
  return process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID !== undefined;
}

/**
 * Treat a missing NODE_ENV as production so that dev-only behaviour
 * (relaxed CORS, no HSTS, exposed codes) is opt-in rather than the default.
 */
export function applyNodeEnvDefault(): void {
  if (!process.env.NODE_ENV) {
    process.env.NODE_ENV = 'production';
  }
}

/**
 * Express `trust proxy` setting: how many proxy hops in front of the API may set
 * X-Forwarded-For, so req.ip (and per-IP rate limits) see the real client.
 *
 * In production the API usually sits behind one load balancer or reverse proxy (1 hop), and
 * sometimes a CDN in front of that as well (2 hops). The default is 1 because the origin is
 * often also reachable directly, where a client could forge an extra hop. Set
 * TRUST_PROXY_HOPS=2 once the origin only accepts traffic from the CDN.
 */
export function resolveTrustProxyHops(): number | false {
  const raw = process.env.TRUST_PROXY_HOPS;
  if (raw !== undefined && raw.trim() !== '') {
    const hops = Number(raw);
    if (!Number.isInteger(hops) || hops < 0 || hops > 5) {
      throw new Error(`TRUST_PROXY_HOPS must be an integer from 0 to 5 (got "${raw}").`);
    }
    return hops === 0 ? false : hops;
  }
  return process.env.NODE_ENV === 'production' && !isTestEnv() ? 1 : false;
}

interface SecretSpec {
  names: string[];
  purpose: string;
}

const REQUIRED_SECRETS: SecretSpec[] = [
  { names: ['API_SECRET', 'AUTH_SECRET'], purpose: 'encrypts stored customer secrets (secret vault)' },
  { names: ['UNSUBSCRIBE_SECRET'], purpose: 'signs email unsubscribe tokens' },
];

/** Values that ship in .env.example and must never reach a running installation. */
const PLACEHOLDER_VALUES = /^(replace_me|change_me|changeme|your[_-]|example|placeholder|secret$|password$)/i;

/**
 * Extra checks for a self-hosted installation: the customer supplies every address and
 * credential; nothing falls back to AMARACUS's infrastructure.
 */
function validateSelfHostedConfig(errors: string[]): void {
  const appUrl = (process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL || '').trim();
  if (!appUrl) {
    errors.push('APP_URL is not set (public URL of your web console, e.g. https://amaracus.example.com). It is used in emails and for CORS.');
  } else {
    try {
      const host = new URL(appUrl).hostname.toLowerCase();
      if (host === 'amaracus.tech' || host.endsWith('.amaracus.tech')) {
        errors.push('APP_URL points at amaracus.tech. A self-hosted installation must use your own domain.');
      }
    } catch {
      errors.push(`APP_URL is not a valid URL (got "${appUrl}").`);
    }
  }

  for (const name of ['API_URL', 'NEXT_PUBLIC_API_URL', 'API_INTERNAL_URL']) {
    const v = process.env[name]?.trim();
    if (!v) continue;
    try {
      const host = new URL(v).hostname.toLowerCase();
      if (host === 'amaracus.tech' || host.endsWith('.amaracus.tech')) {
        errors.push(`${name} points at amaracus.tech. A self-hosted installation must use the address of your own API.`);
      }
    } catch {
      errors.push(`${name} is not a valid URL (got "${v}").`);
    }
  }

  for (const name of ['API_SECRET', 'AUTH_SECRET', 'UNSUBSCRIBE_SECRET', 'AMARACUS_LOCAL_MASTER_KEY']) {
    const v = process.env[name]?.trim();
    if (v && PLACEHOLDER_VALUES.test(v)) {
      errors.push(`${name} still has the placeholder value from .env.example. Generate your own (see .env.example).`);
    }
  }

  const hasResend = !!process.env.RESEND_API_KEY?.trim();
  const hasSmtp = !!(process.env.SMTP_HOST?.trim() || process.env.VERIFY_SMTP_HOST?.trim());
  if (!hasResend && !hasSmtp) {
    console.warn('[Config] No email provider is configured (RESEND_API_KEY or SMTP_HOST). Sign-up codes and password resets cannot be sent.');
  } else if (!process.env.EMAIL_FROM_DEFAULT?.trim() && !process.env.SMTP_FROM?.trim()) {
    errors.push('EMAIL_FROM_DEFAULT (or SMTP_FROM) is not set. Email needs a sender address on a domain you control.');
  }

  for (const name of ['EMAIL_FROM_DEFAULT', 'EMAIL_FROM_VERIFY', 'EMAIL_FROM_RECOVERY', 'SMTP_FROM', 'SMTP_FROM_SECURITY', 'SMTP_FROM_NOTIFICATIONS', 'SMTP_FROM_MARKETING', 'VERIFY_SMTP_FROM', 'RECOVERY_SMTP_FROM', 'SUPPORT_EMAIL']) {
    if (/@([a-z0-9-]+\.)*amaracus\.tech\b/i.test(process.env[name] || '')) {
      errors.push(`${name} uses an amaracus.tech address. Use a sender on your own domain.`);
    }
  }

  // Azure uses DefaultAzureCredential: a service principal (all three variables) or a managed
  // identity (none, or AZURE_CLIENT_ID alone for a user-assigned identity).
  const azureVars = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'];
  const azureSet = azureVars.filter((n) => process.env[n]?.trim());
  if (process.env.AZURE_CLIENT_SECRET?.trim() && azureSet.length < azureVars.length) {
    errors.push(`Azure is partly configured: AZURE_CLIENT_SECRET needs AZURE_TENANT_ID and AZURE_CLIENT_ID as well.`);
  }
  if ((process.env.AZURE_KEY_VAULT_URL?.trim() || process.env.AZURE_MANAGED_HSM_URL?.trim()) && azureSet.length === 0) {
    console.warn('[Config] An Azure vault URL is set without AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET; a managed identity must be available to the API.');
  }
}

export function validateStartupConfig(): string[] {
  const errors: string[] = [...editionConfigErrors()];
  if (getEdition() === 'selfhosted') validateSelfHostedConfig(errors);

  // Platform master key (wraps LOCAL_DEV key material): plain, or sealed by Azure Key Vault
  // and unsealed at boot. Exactly one form. The previous key is optional and set only while
  // rotating (see docs/recovery/phase-9.md).
  for (const slot of ['current', 'previous'] as const) {
    const env = masterKeyEnvNames(slot);
    const plain = process.env[env.plain]?.trim();
    const wrapped = process.env[env.wrapped]?.trim();
    const kekId = process.env[env.kekId]?.trim();
    if (wrapped || kekId) {
      if (!wrapped || !kekId) {
        errors.push(`${env.wrapped} and ${env.kekId} must both be set (sealed ${slot} platform master key).`);
      }
      if (plain) {
        errors.push(`${env.plain} must not be set when the ${slot} master key is sealed by Azure Key Vault.`);
      }
    } else if (!plain) {
      if (slot === 'current') {
        errors.push(
          `${env.plain} (or the sealed pair ${env.wrapped} + ${env.kekId}) is not set (wraps platform key material).`
        );
      }
    } else if (plain.length < MIN_SECRET_LENGTH) {
      errors.push(`${env.plain} must be at least ${MIN_SECRET_LENGTH} characters (wraps platform key material).`);
    }
  }

  for (const spec of REQUIRED_SECRETS) {
    const value = spec.names.map((n) => process.env[n]).find((v) => v && v.trim().length > 0);
    if (!value) {
      errors.push(`${spec.names.join(' or ')} is not set (${spec.purpose}).`);
    } else if (value.length < MIN_SECRET_LENGTH) {
      errors.push(`${spec.names.join(' or ')} must be at least ${MIN_SECRET_LENGTH} characters (${spec.purpose}).`);
    }
  }
  if (!process.env.DATABASE_URL) {
    errors.push('DATABASE_URL is not set (Postgres is the only data store outside tests).');
  }
  if (!process.env.PLATFORM_ADMIN_EMAILS) {
    console.warn(
      getEdition() === 'selfhosted'
        ? '[Config] PLATFORM_ADMIN_EMAILS is not set; any signed-in user can accept the licences and add licence keys. Set it to restrict that to your administrators.'
        : '[Config] PLATFORM_ADMIN_EMAILS is not set; platform-admin routes will reject every caller.'
    );
  }
  return errors;
}

/**
 * Returns the named secret. Under Jest a deterministic per-name value is used
 * so tests run without real secrets; anywhere else a missing secret throws.
 */
export function getRequiredSecret(...names: string[]): string {
  for (const name of names) {
    const value = process.env[name];
    if (value && value.trim().length > 0) return value;
  }
  if (isTestEnv()) {
    return `test-only-secret:${names[0]}:not-for-production-use`;
  }
  throw new Error(`Required secret ${names.join(' or ')} is not configured.`);
}

export function getPlatformAdminEmails(): Set<string> {
  return new Set(
    (process.env.PLATFORM_ADMIN_EMAILS || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}
