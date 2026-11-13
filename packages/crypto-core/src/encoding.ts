import crypto from 'crypto';
import { CryptoEngineError } from './errors';
import { EncodingFormat } from './types';

export function toBuffer(data: string | Buffer | Uint8Array, encoding: EncodingFormat = 'utf8'): Buffer {
  if (Buffer.isBuffer(data)) {
    return data;
  }
  if (data instanceof Uint8Array) {
    return Buffer.from(data);
  }
  if (typeof data !== 'string') {
    throw new CryptoEngineError('INVALID_INPUT', 'Input data must be a string, Buffer, or Uint8Array');
  }

  try {
    if (encoding === 'hex') {
      const cleanHex = data.replace(/^0x/i, '').trim();
      if (cleanHex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(cleanHex)) {
        throw new Error('Invalid hexadecimal string');
      }
      return Buffer.from(cleanHex, 'hex');
    }
    if (encoding === 'base64') {
      return Buffer.from(data.trim(), 'base64');
    }
    if (encoding === 'base64url') {
      return Buffer.from(data.trim(), 'base64url');
    }
    if (encoding === 'raw') {
      return Buffer.from(data, 'binary');
    }
    return Buffer.from(data, 'utf8');
  } catch (err: any) {
    throw new CryptoEngineError('INVALID_INPUT', `Failed to decode ${encoding} input: ${err.message}`);
  }
}

export function encodeBuffer(buffer: Buffer, encoding: 'hex' | 'base64' | 'base64url' | 'utf8' = 'hex'): string {
  if (!Buffer.isBuffer(buffer)) {
    throw new CryptoEngineError('INVALID_INPUT', 'Expected Buffer for encoding');
  }
  if (encoding === 'base64url') {
    return buffer.toString('base64url');
  }
  return buffer.toString(encoding);
}

export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

export function generateSecureRandom(length: number): Buffer {
  if (!Number.isInteger(length) || length <= 0 || length > 65536) {
    throw new CryptoEngineError('INVALID_INPUT', 'Random length must be an integer between 1 and 65536 bytes');
  }
  return crypto.randomBytes(length);
}
