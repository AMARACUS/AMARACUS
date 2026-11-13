import { verifyWebhookSignature, constructWebhookEvent, WebhookVerificationError } from './webhooks';

export interface WebhookMiddlewareOptions {
  secret: string;
  toleranceSeconds?: number;
}

/**
 * Express-compatible middleware for validating AMARACUS webhook signatures.
 * Automatically verifies the X-AMARACUS-Signature header against the raw body buffer.
 *
 * Usage:
 * ```ts
 * import express from 'express';
 * import { amaracusWebhookMiddleware } from '@amaracus/sdk';
 *
 * const app = express();
 * app.use('/webhook', express.raw({ type: 'application/json' }), amaracusWebhookMiddleware({ secret: 'whsec_...' }), (req, res) => {
 *   console.log('Verified Event:', req.amaracusEvent);
 *   res.sendStatus(200);
 * });
 * ```
 */
export function amaracusWebhookMiddleware(options: WebhookMiddlewareOptions) {
  const { secret, toleranceSeconds = 300 } = options;

  return (req: any, res: any, next: any) => {
    const signatureHeader = req.headers['x-amaracus-signature'] || req.headers['X-AMARACUS-Signature'];

    if (!signatureHeader) {
      return res.status(400).json({
        error: {
          code: 'MISSING_WEBHOOK_SIGNATURE',
          message: 'Missing required X-AMARACUS-Signature header.',
        },
      });
    }

    const rawBody = req.rawBody || (typeof req.body === 'string' ? req.body : JSON.stringify(req.body));

    try {
      const isValid = verifyWebhookSignature(rawBody, signatureHeader as string, secret, toleranceSeconds);
      if (!isValid) {
        return res.status(400).json({
          error: {
            code: 'INVALID_WEBHOOK_SIGNATURE',
            message: 'HMAC signature verification failed.',
          },
        });
      }

      req.amaracusEvent = typeof rawBody === 'string' ? JSON.parse(rawBody) : rawBody;
      next();
    } catch (err: any) {
      return res.status(400).json({
        error: {
          code: err.code || 'WEBHOOK_VERIFICATION_FAILED',
          message: err.message,
        },
      });
    }
  };
}

/**
 * Next.js App Router (Route Handlers) helper for validating AMARACUS webhooks.
 *
 * Usage in app/api/webhooks/route.ts:
 * ```ts
 * import { verifyNextJsWebhook } from '@amaracus/sdk';
 *
 * export async function POST(req: Request) {
 *   try {
 *     const event = await verifyNextJsWebhook(req, process.env.AMARACUS_WEBHOOK_SECRET!);
 *     console.log('Received Event:', event.type);
 *     return Response.json({ received: true });
 *   } catch (err: any) {
 *     return Response.json({ error: err.message }, { status: 400 });
 *   }
 * }
 * ```
 */
export async function verifyNextJsWebhook<T = any>(
  req: Request,
  secret: string,
  toleranceSeconds = 300
): Promise<T> {
  const signatureHeader = req.headers.get('x-amaracus-signature');

  if (!signatureHeader) {
    throw new WebhookVerificationError('Missing X-AMARACUS-Signature header in Next.js request.');
  }

  const rawBody = await req.text();
  return constructWebhookEvent<T>(rawBody, signatureHeader, secret, toleranceSeconds);
}
