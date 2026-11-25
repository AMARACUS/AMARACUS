import crypto from 'crypto';
import { getRequiredSecret } from '../lib/runtime-config';

/**
 * Values the OAuth flow hands to clients and browsers (client IDs, pending authorization requests,
 * authorization codes, refresh tokens) are encrypted and authenticated with AES-256-GCM, so nothing
 * has to be stored for them and none can be forged or altered. The purpose is bound as additional
 * data: a value made for one step is rejected at every other step.
 */
export type SealPurpose = 'client' | 'request' | 'code' | 'refresh';

const MAX_LENGTH = 8192;

function sealingKey(): Buffer {
  const secret = getRequiredSecret('API_SECRET', 'AUTH_SECRET');
  return Buffer.from(crypto.hkdfSync('sha256', secret, 'amaracus-mcp-oauth', 'sealed-token-v1', 32));
}

export function seal(purpose: SealPurpose, payload: object, ttlSeconds?: number): string {
  const body = ttlSeconds === undefined ? payload : { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sealingKey(), iv);
  cipher.setAAD(Buffer.from(`amaracus-mcp:${purpose}`));
  const ct = Buffer.concat([cipher.update(JSON.stringify(body), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64url');
}

/** The payload, or null when the value is not ours, was altered, was made for another step or has expired. */
export function unseal<T>(purpose: SealPurpose, token: unknown): T | null {
  if (typeof token !== 'string' || token.length < 40 || token.length > MAX_LENGTH) return null;
  try {
    const raw = Buffer.from(token, 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', sealingKey(), raw.subarray(0, 12), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(`amaracus-mcp:${purpose}`));
    decipher.setAuthTag(raw.subarray(12, 28));
    const text = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
    const payload = JSON.parse(text);
    if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload as T;
  } catch {
    return null;
  }
}
