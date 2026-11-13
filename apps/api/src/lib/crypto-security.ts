import crypto from 'crypto';
import { sanitizeText } from './sanitize';

function scryptAsync(password: string, salt: string, keyLength: number, options: crypto.ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, keyLength, options, (err, key) => (err ? reject(err) : resolve(key)))
  );
}

/**
 * scrypt cost. OWASP's minimums are equivalent pairs (N=2^17/p=1 … N=2^14/p=5); N=2^14, r=8, p=5
 * keeps memory at 16 MiB per hash, which suits a small API instance, at OWASP-level work.
 */
const SCRYPT = { N: 16384, r: 8, p: 5 };
// Hashes made before parameters were stored used Node's defaults.
const LEGACY_SCRYPT = { N: 16384, r: 8, p: 1 };

/**
 * Hashes a password with scrypt and a random 16-byte salt.
 * Stored format: scrypt$<N>$<r>$<p>$<salt_hex>$<derived_key_hex>
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = (await scryptAsync(password, salt, 64, SCRYPT)) as Buffer;
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt}$${derivedKey.toString('hex')}`;
}

function parseStoredHash(storedHash: string): { params: typeof SCRYPT; salt: string; key: string; current: boolean } | null {
  if (typeof storedHash !== 'string') return null;
  const parts = storedHash.split('$');
  if (parts.length === 6 && parts[0] === 'scrypt') {
    const [N, r, p] = parts.slice(1, 4).map(Number);
    // Bounds stop a tampered row from requesting an enormous computation.
    if (![N, r, p].every(Number.isInteger) || N < 1024 || N > 2 ** 17 || r < 1 || r > 16 || p < 1 || p > 16) return null;
    const current = N === SCRYPT.N && r === SCRYPT.r && p === SCRYPT.p;
    return { params: { N, r, p }, salt: parts[4], key: parts[5], current };
  }
  const legacy = storedHash.split(':');
  if (legacy.length === 2) return { params: LEGACY_SCRYPT, salt: legacy[0], key: legacy[1], current: false };
  return null;
}

/** Whether a stored hash uses older parameters or format and should be replaced after sign-in. */
export function passwordHashNeedsUpgrade(storedHash: string): boolean {
  const parsed = parseStoredHash(storedHash);
  return !!parsed && !parsed.current;
}

/**
 * Verifies a password against a stored hash (current or legacy format) in constant time.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  try {
    const parsed = parseStoredHash(storedHash);
    if (!parsed) return false;
    const derivedKey = (await scryptAsync(password, parsed.salt, 64, {
      ...parsed.params,
      maxmem: 256 * parsed.params.N * parsed.params.r,
    })) as Buffer;
    const keyBuffer = Buffer.from(parsed.key, 'hex');
    if (derivedKey.length !== keyBuffer.length) return false;
    return crypto.timingSafeEqual(derivedKey, keyBuffer);
  } catch {
    return false;
  }
}

/**
 * Checks an account password. `legacy` is true when the password is right but the stored hash
 * is in an older form, and callers should then store a fresh hash of the password as typed:
 *  - until Phase 7 the request sanitizer HTML-escaped, trimmed and NFC-normalized passwords
 *    before hashing, so those hashes match that form instead of the password as typed;
 *  - hashes made before the security audit use weaker scrypt parameters.
 */
export async function verifyAccountPassword(
  password: string,
  storedHash: string
): Promise<{ valid: boolean; legacy: boolean }> {
  if (await verifyPassword(password, storedHash)) {
    return { valid: true, legacy: passwordHashNeedsUpgrade(storedHash) };
  }
  if (typeof password !== 'string') return { valid: false, legacy: false };
  const legacyForm = sanitizeText(password);
  if (legacyForm !== password && (await verifyPassword(legacyForm, storedHash))) {
    return { valid: true, legacy: true };
  }
  return { valid: false, legacy: false };
}

/**
 * Generates a high-entropy hex string for sessions, verification tokens, or secrets.
 */
export function generateSecureToken(byteLength = 32): string {
  return crypto.randomBytes(byteLength).toString('hex');
}

/**
 * Computes a SHA-256 hash of an API key or sensitive secret for secure database storage.
 */
export function hashSecret(secret: string): string {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

export interface GeneratedApiKey {
  fullKey: string;
  prefix: string;
  keyHash: string;
}

/**
 * Generates a production-format API credential.
 * Format: amk_<env>_<32-byte-hex>
 * Only the prefix and hash are stored in the database. The full key is displayed exactly once.
 */
export function generateApiKey(envType = 'live'): GeneratedApiKey {
  const secret = crypto.randomBytes(24).toString('hex');
  const prefix = `amk_${envType}_${secret.slice(0, 6)}`;
  const fullKey = `${prefix}_${secret.slice(6)}`;
  const keyHash = hashSecret(fullKey);
  return { fullKey, prefix, keyHash };
}
