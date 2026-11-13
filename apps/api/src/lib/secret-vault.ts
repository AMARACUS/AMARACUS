import crypto from 'crypto';
import { getRequiredSecret } from './runtime-config';

function getVaultKey(): Buffer {
  const masterSecret = getRequiredSecret('API_SECRET', 'AUTH_SECRET');
  return crypto.createHash('sha256').update(masterSecret).digest();
}

/**
 * Encrypts a customer secret (such as an Azure Service Principal client secret)
 * using AES-256-GCM before persisting to PostgreSQL.
 */
export function encryptSecret(plaintext: string): string {
  if (!plaintext) return '';
  const key = getVaultKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `v1:${iv.toString('base64url')}:${tag.toString('base64url')}:${ciphertext.toString('base64url')}`;
}

/**
 * Decrypts a customer secret at runtime when required to authorize Azure operations.
 */
export function decryptSecret(encryptedString: string): string {
  if (!encryptedString) return '';
  if (!encryptedString.startsWith('v1:')) {
    // Never treat an unencrypted value as a valid secret: a plaintext credential in the
    // database is a bug or tampering, not a legacy format to accept.
    throw new Error('Stored secret is not in the encrypted v1 format.');
  }

  const parts = encryptedString.split(':');
  if (parts.length !== 4) {
    throw new Error('Malformed encrypted secret format.');
  }

  const [, ivB64, tagB64, ctB64] = parts;
  const key = getVaultKey();
  const iv = Buffer.from(ivB64, 'base64url');
  const tag = Buffer.from(tagB64, 'base64url');
  const ciphertext = Buffer.from(ctB64, 'base64url');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}
