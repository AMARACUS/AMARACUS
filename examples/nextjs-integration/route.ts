/**
 * AMARACUS Next.js 14 App Router Integration Example
 * Location: app/api/webhooks/amaracus/route.ts
 */

import { verifyNextJsWebhook, Amaracus } from '@amaracus/sdk';

// Server-side client instance (NEVER expose NEXT_PUBLIC_AMARACUS_API_KEY)
const amaracus = new Amaracus({
  apiKey: process.env.AMARACUS_API_KEY || 'am_live_server_secret_only',
  baseUrl: process.env.AMARACUS_BASE_URL || 'http://localhost:4000',
});

/**
 * Route Handler: POST /api/webhooks/amaracus
 * Ingests and cryptographically verifies webhook events from AMARACUS.
 */
export async function POST(request: Request) {
  try {
    const webhookSecret = process.env.AMARACUS_WEBHOOK_SECRET || 'whsec_sample_secret';

    // Verify incoming HMAC-SHA256 signature and timestamp tolerance window
    const event = await verifyNextJsWebhook(request, webhookSecret);

    console.log(`[Next.js Webhook] Verified event: ${event.type} (${event.id})`);

    // Handle business logic based on event type
    switch (event.type) {
      case 'key.rotated':
        console.log(`[Next.js] Key ${event.data.keyId} updated.`);
        break;
      case 'policy.violation':
        console.error(`[Next.js] Policy alert: ${event.data.message}`);
        break;
      default:
        console.log(`[Next.js] Event received:`, event.data);
    }

    return Response.json({ success: true, eventId: event.id });
  } catch (err: any) {
    console.error(`[Next.js Webhook Verification Error]:`, err.message);
    return Response.json(
      { error: { code: 'INVALID_SIGNATURE', message: err.message } },
      { status: 400 }
    );
  }
}

/**
 * Server Action Example (app/actions/encrypt.ts)
 * Called from React Client Components to perform cryptographic operations
 * on the server, ensuring zero browser leakage of keys or master secrets.
 */
export async function encryptSensitiveDataAction(plaintext: string) {
  'use server';

  // AMARACUS_KEY_ID: a managed AES-256-GCM key created in the dashboard or with keys.create().
  const res = await amaracus.encrypt({
    key: process.env.AMARACUS_KEY_ID!,
    data: plaintext,
  });

  // The envelope is all decrypt() needs: amaracus.decrypt({ key, envelope }).
  return {
    envelope: res.envelope,
  };
}
