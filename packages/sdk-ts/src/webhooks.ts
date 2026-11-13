import crypto from 'crypto';
import { AmaracusError } from './errors';

export class WebhookVerificationError extends AmaracusError {
  constructor(message: string) {
    super(message, { code: 'WEBHOOK_SIGNATURE_VERIFICATION_FAILED', status: 400 });
    this.name = 'WebhookVerificationError';
    Object.setPrototypeOf(this, WebhookVerificationError.prototype);
  }
}

export interface WebhookHeaderComponents {
  timestamp: number;
  signature: string;
}

export function parseWebhookHeader(headerValue: string): WebhookHeaderComponents {
  if (!headerValue || typeof headerValue !== 'string') {
    throw new WebhookVerificationError('Missing or invalid X-AMARACUS-Signature header.');
  }

  const parts = headerValue.split(',');
  let timestamp: number | null = null;
  let signature: string | null = null;

  for (const part of parts) {
    const [k, v] = part.trim().split('=');
    if (k === 't') {
      timestamp = parseInt(v, 10);
    } else if (k === 'v1') {
      signature = v;
    }
  }

  if (!timestamp || isNaN(timestamp) || !signature) {
    throw new WebhookVerificationError('Malformed X-AMARACUS-Signature header format. Expected "t=...,v1=..."');
  }

  return { timestamp, signature };
}

export function verifyWebhookSignature(
  rawPayload: string | Buffer,
  headerValue: string,
  secret: string,
  toleranceSeconds = 300
): boolean {
  if (!secret) {
    throw new WebhookVerificationError('Webhook signing secret is required.');
  }

  const { timestamp, signature } = parseWebhookHeader(headerValue);

  const currentTime = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTime - timestamp) > toleranceSeconds) {
    throw new WebhookVerificationError(
      `Webhook timestamp outside tolerance window. Request timestamp: ${timestamp}, Current timestamp: ${currentTime}, Allowed tolerance: ${toleranceSeconds}s`
    );
  }

  const payloadString = typeof rawPayload === 'string' ? rawPayload : rawPayload.toString('utf-8');
  const signedPayload = `${timestamp}.${payloadString}`;

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signedPayload, 'utf-8')
    .digest('hex');

  const expectedBuffer = Buffer.from(expectedSignature, 'utf-8');
  const actualBuffer = Buffer.from(signature, 'utf-8');

  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

export function constructWebhookEvent<T = any>(
  rawPayload: string | Buffer,
  headerValue: string,
  secret: string,
  toleranceSeconds = 300
): T {
  const isValid = verifyWebhookSignature(rawPayload, headerValue, secret, toleranceSeconds);
  if (!isValid) {
    throw new WebhookVerificationError('HMAC-SHA256 signature mismatch.');
  }

  const payloadString = typeof rawPayload === 'string' ? rawPayload : rawPayload.toString('utf-8');
  try {
    return JSON.parse(payloadString) as T;
  } catch (err: any) {
    throw new WebhookVerificationError(`Malformed webhook JSON payload: ${err.message}`);
  }
}
