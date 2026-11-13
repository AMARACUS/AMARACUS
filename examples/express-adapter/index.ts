import express, { Request, Response } from 'express';
import { Amaracus, amaracusWebhookMiddleware } from '@amaracus/sdk';

const app = express();
const port = process.env.PORT || 8080;

// Initialize AMARACUS Client using server-side environment variables
// NEVER EXPOSE THIS KEY TO BROWSER CLIENTS
const amaracus = new Amaracus({
  apiKey: process.env.AMARACUS_API_KEY || 'am_live_example_secret_key_123',
  baseUrl: process.env.AMARACUS_BASE_URL || 'http://localhost:4000',
});

const WEBHOOK_SECRET = process.env.AMARACUS_WEBHOOK_SECRET || 'whsec_sample_secret_key_456';

// -----------------------------------------------------------------------------
// 1. Webhook Ingestion Endpoint (Using Official Express Middleware Adapter)
// -----------------------------------------------------------------------------
app.post(
  '/webhooks/amaracus',
  express.raw({ type: 'application/json' }), // Preserves raw bytes for HMAC verification
  amaracusWebhookMiddleware({ secret: WEBHOOK_SECRET }),
  (req: Request, res: Response) => {
    // Verified event attached by middleware
    const event = (req as any).amaracusEvent;
    console.log(`[Webhook Ingestion] Authenticated event: ${event.type} (ID: ${event.id})`);

    switch (event.type) {
      case 'key.rotated':
        console.log(`Key ${event.data?.keyId} was rotated to version ${event.data?.newVersion}`);
        break;
      case 'operation.completed':
        console.log(`Async operation ${event.data?.operationId} completed successfully`);
        break;
      case 'policy.violation':
        console.warn(`SECURITY ALERT: Policy violation detected: ${event.data?.reason}`);
        break;
      default:
        console.log(`Event data received:`, event.data);
    }

    res.status(200).json({ received: true });
  }
);

// Standard JSON parser for other application endpoints
app.use(express.json());

// -----------------------------------------------------------------------------
// 2. Application Backend Cryptographic Gateway
// Demonstrates how browser or mobile frontends talk to this backend,
// while only this backend speaks to AMARACUS with authenticated credentials.
// -----------------------------------------------------------------------------
app.post('/api/user/encrypt-pii', async (req: Request, res: Response) => {
  try {
    const { ssn, fullName } = req.body;
    if (!ssn || !fullName) {
      return res.status(400).json({ error: 'Missing required PII fields' });
    }

    // Call AMARACUS Universal Cryptographic API via official SDK.
    // AMARACUS_KEY_ID: a managed AES-256-GCM key created in the dashboard or with keys.create().
    const encrypted = await amaracus.encrypt({
      key: process.env.AMARACUS_KEY_ID!,
      data: JSON.stringify({ ssn, fullName }),
    });

    console.log(`[PII Encryption] Successfully protected record with key envelope.`);
    return res.status(200).json({
      success: true,
      ciphertextEnvelope: encrypted.envelope,
    });
  } catch (err: any) {
    console.error(`[Encryption Error]:`, err.message);
    return res.status(500).json({ error: err.message });
  }
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(port, () => {
    console.log(`[Express Adapter Example] Server running on http://localhost:${port}`);
    console.log(`[Express Adapter Example] Webhook listener: POST http://localhost:${port}/webhooks/amaracus`);
  });
}

export { app };
