import crypto from 'crypto';
import { db, WebhookEndpointRecord, WebhookDeliveryRecord } from './data-store';

export interface WebhookEventPayload<T = any> {
  id: string;
  type: string;
  timestamp: string;
  data: T;
}

/**
 * Computes the HMAC-SHA256 signature for a webhook payload.
 * Canonical scheme: HMAC_SHA256(secret, `${timestamp}.${payloadString}`)
 */
export function signWebhookPayload(secret: string, payload: string, timestamp: number): string {
  return crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${payload}`)
    .digest('hex');
}

/**
 * Verifies an incoming X-AMARACUS-Signature header against the webhook signing secret.
 * Defends against replay attacks by enforcing a timestamp tolerance window (default: 300 seconds).
 */
export function verifyWebhookSignature(
  secret: string,
  payload: string,
  signatureHeader: string,
  toleranceSeconds = 300
): { valid: boolean; reason?: string } {
  if (!signatureHeader) {
    return { valid: false, reason: 'Missing signature header' };
  }

  // Parse header: t=123456789,v1=abcdef...
  const parts = signatureHeader.split(',');
  let timestampStr: string | undefined;
  let signature: string | undefined;

  for (const part of parts) {
    const [key, val] = part.split('=');
    if (key === 't') timestampStr = val;
    if (key === 'v1') signature = val;
  }

  if (!timestampStr || !signature) {
    return { valid: false, reason: 'Malformed signature header format' };
  }

  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp)) {
    return { valid: false, reason: 'Invalid timestamp format' };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) {
    return { valid: false, reason: `Timestamp outside tolerance window (${toleranceSeconds}s)` };
  }

  const expectedSignature = signWebhookPayload(secret, payload, timestamp);

  try {
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (sigBuffer.length !== expectedBuffer.length) {
      return { valid: false, reason: 'Signature mismatch length' };
    }

    const isMatch = crypto.timingSafeEqual(sigBuffer, expectedBuffer);
    return isMatch ? { valid: true } : { valid: false, reason: 'Signature cryptographic mismatch' };
  } catch {
    return { valid: false, reason: 'Cryptographic verification error' };
  }
}

export class WebhookEngine {
  private static instance: WebhookEngine;

  private constructor() {
    this.startRetryWorker();
  }

  public static getInstance(): WebhookEngine {
    if (!WebhookEngine.instance) {
      WebhookEngine.instance = new WebhookEngine();
    }
    return WebhookEngine.instance;
  }

  /**
   * Dispatches an event to all active endpoints subscribed to this event type.
   */
  public async dispatch<T = any>(organizationId: string, eventType: string, data: T): Promise<void> {
    const endpoints = await db.getWebhookEndpointsByOrg(organizationId);
    const activeEndpoints = endpoints.filter(
      (ep) => ep.status === 'ACTIVE' && (ep.events.includes('*') || ep.events.includes(eventType))
    );

    if (activeEndpoints.length === 0) {
      return;
    }

    const eventId = `evt_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
    const timestampIso = new Date().toISOString();
    const eventPayload: WebhookEventPayload<T> = {
      id: eventId,
      type: eventType,
      timestamp: timestampIso,
      data,
    };

    for (const endpoint of activeEndpoints) {
      await this.deliverToEndpoint(endpoint, eventPayload, 1);
    }
  }

  /**
   * Delivers a webhook payload to a single endpoint.
   */
  public async deliverToEndpoint(
    endpoint: WebhookEndpointRecord,
    payload: WebhookEventPayload,
    attempt: number
  ): Promise<WebhookDeliveryRecord> {
    const payloadStr = JSON.stringify(payload);
    const timestampSeconds = Math.floor(Date.now() / 1000);
    // Use secretPrefix + secretHash as the HMAC key
    const secret = endpoint.secretHash;
    const signature = signWebhookPayload(secret, payloadStr, timestampSeconds);
    const signatureHeader = `t=${timestampSeconds},v1=${signature}`;

    const startTime = Date.now();
    let responseStatus: number | null = null;
    let responseBody: string | null = null;
    let error: string | null = null;
    let status: 'DELIVERED' | 'FAILED' | 'RETRYING' = 'DELIVERED';

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

      const res = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'AMARACUS-Webhook-Notifier/1.0',
          'X-AMARACUS-Signature': signatureHeader,
          'X-AMARACUS-Event-Id': payload.id,
          'X-AMARACUS-Event-Type': payload.type,
        },
        body: payloadStr,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      responseStatus = res.status;
      responseBody = (await res.text()).substring(0, 1000); // Record up to 1KB response

      if (res.ok) {
        status = 'DELIVERED';
        // Reset failure count on success
        if (endpoint.failureCount > 0) {
          await db.updateWebhookEndpoint(endpoint.id, { failureCount: 0 });
        }
      } else {
        status = attempt < 3 ? 'RETRYING' : 'FAILED';
        error = `HTTP ${res.status}: ${res.statusText}`;
      }
    } catch (err: any) {
      status = attempt < 3 ? 'RETRYING' : 'FAILED';
      error = err.message || 'Connection failed';
    }

    const durationMs = Date.now() - startTime;
    const nextRetryAt =
      status === 'RETRYING'
        ? new Date(Date.now() + Math.pow(3, attempt) * 5000) // 15s, 45s backoff
        : null;

    if (status === 'FAILED') {
      const newFailureCount = endpoint.failureCount + 1;
      await db.updateWebhookEndpoint(endpoint.id, {
        failureCount: newFailureCount,
        // Automatically disable endpoint if 10 consecutive failures occur
        status: newFailureCount >= 10 ? 'DISABLED' : endpoint.status,
      });
    }

    return await db.createWebhookDelivery({
      endpointId: endpoint.id,
      eventType: payload.type,
      eventId: payload.id,
      payload,
      responseStatus,
      responseBody,
      durationMs,
      status,
      attempts: attempt,
      nextRetryAt,
      error,
    });
  }

  /**
   * Background retry worker polling for retries every 30 seconds.
   */
  private startRetryWorker(): void {
    setInterval(async () => {
      try {
        const now = new Date();
        for (const delivery of await db.listDueWebhookRetries(now)) {
          const endpoint = await db.getWebhookEndpointById(delivery.endpointId);
          if (endpoint && endpoint.status === 'ACTIVE') {
            await this.deliverToEndpoint(endpoint, delivery.payload, delivery.attempts + 1);
          } else {
            await db.updateWebhookDelivery(delivery.id, { status: 'FAILED', error: 'Endpoint inactive' });
          }
        }
      } catch {}
    }, 30000).unref();
  }
}

export const webhookEngine = WebhookEngine.getInstance();
