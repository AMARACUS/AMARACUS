import crypto from 'crypto';

export type ApiKeyEnvironment = 'live' | 'test';

export interface GeneratedKeyResult {
  fullKey: string;
  prefix: string;
  keyHash: string;
  env: ApiKeyEnvironment;
}

export const VALID_SCOPES = [
  'keys:read',
  'keys:write',
  'keys:create',
  'keys:rotate',
  'keys:delete',
  'keys:use',
  'crypto:read',
  'crypto:execute',
  'crypto:encrypt',
  'crypto:decrypt',
  'crypto:sign',
  'crypto:verify',
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'pqc:read',
  'pqc:execute',
  'certificates:read',
  'certificates:write',
  'certificates:issue',
  'certificates:revoke',
  'inventory:read',
  'findings:read',
  'findings:write',
  'cbom:read',
  'cbom:write',
  'cbom:export',
  'advanced:execute',
  'advanced_crypto:execute',
  'webhooks:read',
  'webhooks:write',
  'credentials:read',
  'credentials:manage',
  'jobs:read',
  'jobs:write',
  'usage:read',
  'migrations:read',
  'migrations:write',
  'migrations:plan',
  'migrations:approve',
  'migrations:execute',
  'os:read',
  'os:write',
  'os:workflows',
  'os:posture',
  'os:automation',
  'intelligence:recommendations',
  'intelligence:optimize',
  'intelligence:analyze',
  'intelligence:remediate',
  'compliance:read',
  'compliance:assess',
  'compliance:evidence',
  'compliance:exceptions',
  'compliance:export',
] as const;


export type ApiScope = (typeof VALID_SCOPES)[number];

/**
 * Computes SHA-256 hex digest of an API key secret for safe database lookup.
 */
export function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey.trim()).digest('hex');
}

/**
 * Generates an official production or test AMARACUS API credential.
 * Format: am_live_<6-char-prefix><26-char-secret> -> 64-char high-entropy credential
 * Example: am_live_ab12cd34ef...
 */
export function generateAmaracusApiKey(env: ApiKeyEnvironment = 'live'): GeneratedKeyResult {
  const envTag = env === 'test' ? 'test' : 'live';
  const entropy = crypto.randomBytes(32).toString('hex'); // 64 chars hex
  const prefix = `am_${envTag}_${entropy.slice(0, 8)}`;
  const fullKey = `${prefix}_${entropy.slice(8)}`;
  const keyHash = hashApiKey(fullKey);

  return {
    fullKey,
    prefix,
    keyHash,
    env,
  };
}

/**
 * Validates whether a provided scope list is valid.
 */
export function validateScopes(scopes: string[]): { valid: boolean; invalidScopes: string[] } {
  const invalidScopes = scopes.filter((s) => !(VALID_SCOPES as readonly string[]).includes(s));
  return {
    valid: invalidScopes.length === 0,
    invalidScopes,
  };
}

/**
 * Checks if a credential has all requested scopes.
 * Supports wildcard "*" or specific scopes.
 */
export function hasRequiredScope(credentialScopes: string[] | null | undefined, requiredScope: string): boolean {
  if (!credentialScopes || credentialScopes.length === 0) {
    return false;
  }
  if (credentialScopes.includes('*') || credentialScopes.includes('admin')) {
    return true;
  }
  if (credentialScopes.includes(requiredScope)) {
    return true;
  }

  // crypto:execute grants all cryptographic execution scopes
  const isCryptoOp = ['encrypt', 'decrypt', 'sign', 'verify', 'hash', 'crypto:encrypt', 'crypto:decrypt', 'crypto:sign', 'crypto:verify', 'crypto:hash', 'crypto:execute'].includes(requiredScope);
  if (isCryptoOp && (credentialScopes.includes('crypto:execute') || credentialScopes.includes('crypto:*'))) {
    return true;
  }

  // Cross-alias matching (e.g. 'encrypt' <-> 'crypto:encrypt')
  if (requiredScope.startsWith('crypto:')) {
    const bareOp = requiredScope.replace('crypto:', '');
    if (credentialScopes.includes(bareOp)) return true;
  } else {
    if (credentialScopes.includes(`crypto:${requiredScope}`)) return true;
  }

  // Support category wildcards e.g. "keys:*" matches "keys:read", "keys:write", "keys:use"
  const [category] = requiredScope.split(':');
  if (category && credentialScopes.includes(`${category}:*`)) {
    return true;
  }

  return false;
}
