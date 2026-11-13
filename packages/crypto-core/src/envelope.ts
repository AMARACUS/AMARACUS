import { EncryptedEnvelope } from './types';
import { CryptoEngineError } from './errors';

export const CURRENT_ENVELOPE_VERSION = 1;

export function serializeEnvelope(envelope: EncryptedEnvelope): string {
  return Buffer.from(JSON.stringify(envelope)).toString('base64url');
}

export function parseEnvelope(input: EncryptedEnvelope | string): EncryptedEnvelope {
  let parsed: any;
  if (typeof input === 'string') {
    const trimmed = input.trim();
    try {
      if (trimmed.startsWith('{')) {
        parsed = JSON.parse(trimmed);
      } else {
        const decoded = Buffer.from(trimmed, 'base64url').toString('utf8');
        parsed = JSON.parse(decoded);
      }
    } catch {
      throw new CryptoEngineError('INVALID_INPUT', 'Malformed encrypted envelope: invalid JSON or Base64URL encoding.');
    }
  } else if (typeof input === 'object' && input !== null) {
    parsed = input;
  } else {
    throw new CryptoEngineError('INVALID_INPUT', 'Invalid envelope format: expected JSON string or object.');
  }

  if (parsed.v !== CURRENT_ENVELOPE_VERSION) {
    throw new CryptoEngineError(
      'INVALID_INPUT',
      `Unsupported envelope version '${parsed.v}'. Expected version ${CURRENT_ENVELOPE_VERSION}.`
    );
  }
  if (parsed.alg !== 'AES-256-GCM') {
    throw new CryptoEngineError(
      'UNSUPPORTED_ALGORITHM',
      `Unsupported envelope algorithm '${parsed.alg}'. Expected 'AES-256-GCM'.`
    );
  }
  if (!parsed.iv || typeof parsed.iv !== 'string') {
    throw new CryptoEngineError('INVALID_NONCE', 'Envelope is missing required nonce/IV.');
  }
  if (!parsed.ct || typeof parsed.ct !== 'string') {
    throw new CryptoEngineError('INVALID_INPUT', 'Envelope is missing required ciphertext payload.');
  }
  if (!parsed.tag || typeof parsed.tag !== 'string') {
    throw new CryptoEngineError('AUTHENTICATION_FAILED', 'Envelope is missing required GCM authentication tag.');
  }

  return {
    v: parsed.v,
    alg: parsed.alg,
    iv: parsed.iv,
    ct: parsed.ct,
    tag: parsed.tag,
    aad: parsed.aad || null,
    wrappedDek: parsed.wrappedDek || null,
    wrapAlg: parsed.wrapAlg || null,
    keyVersion: typeof parsed.keyVersion === 'number' ? parsed.keyVersion : null,
  };
}
