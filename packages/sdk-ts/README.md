# @amaracus-sdk/sdk

Official TypeScript & JavaScript client library for the **AMARACUS Cryptographic Infrastructure Platform**.

AMARACUS is an API-first cryptographic infrastructure company. This SDK is a thin, high-performance, strictly typed client for the AMARACUS Universal Cryptographic API. It contains **zero client-side cryptographic primitives**; all operations execute within authorized data-plane environments and Hardware Security Modules (HSMs).

---

## Installation

```bash
npm install @amaracus-sdk/sdk
# or
pnpm add @amaracus-sdk/sdk
# or
yarn add @amaracus-sdk/sdk
```

---

## Quickstart

```typescript
import { Amaracus } from '@amaracus-sdk/sdk';

// Initialize with your project API key
const amaracus = new Amaracus({
  apiKey: process.env.AMARACUS_API_KEY!, // e.g. am_live_...
  baseUrl: process.env.AMARACUS_BASE_URL || 'https://api.amaracus.tech',
});

async function main() {
  // 1. Universal Authenticated Symmetric Encryption
  const encrypted = await amaracus.crypto.encrypt({
    algorithm: 'AES-256-GCM',
    plaintext: Buffer.from('Sensitive Customer Record', 'utf-8'),
  });

  console.log('Encrypted Envelope:', encrypted.envelope);

  // 2. Universal Decryption
  const decrypted = await amaracus.crypto.decrypt({
    envelope: encrypted.envelope,
  });

  console.log('Decrypted Plaintext:', decrypted.plaintext.toString('utf-8'));
}

main();
```

---

## Post-Quantum Cryptography (PQC)

```typescript
// NIST FIPS 203 ML-KEM Key Encapsulation
const kem = await amaracus.pqc.encapsulate({
  algorithm: 'ML-KEM-768',
  recipientPublicKey: '0123...hex',
});

console.log('Shared Secret:', kem.sharedSecret);
console.log('Ciphertext:', kem.ciphertext);
```

---

## Webhook Verification & Framework Adapters

### Express Middleware Adapter
```typescript
import express from 'express';
import { amaracusWebhookMiddleware } from '@amaracus/sdk';

const app = express();

app.post(
  '/webhooks/amaracus',
  express.raw({ type: 'application/json' }),
  amaracusWebhookMiddleware({ secret: process.env.AMARACUS_WEBHOOK_SECRET! }),
  (req, res) => {
    const event = req.amaracusEvent;
    console.log(`Verified Event Received: ${event.type} (${event.id})`);
    res.status(200).json({ received: true });
  }
);
```

### Next.js App Router Route Handler
```typescript
// app/api/webhooks/amaracus/route.ts
import { verifyNextJsWebhook } from '@amaracus/sdk';

export async function POST(req: Request) {
  try {
    const event = await verifyNextJsWebhook(req, process.env.AMARACUS_WEBHOOK_SECRET!);
    console.log('Verified Event:', event.type);
    return Response.json({ received: true });
  } catch (err: any) {
    return Response.json({ error: err.message }, { status: 400 });
  }
}
```

---

## Security Invariants

1. **Zero Browser Secret Exposure**: Never expose server-side API keys (`am_live_...`) to frontend or browser code.
2. **Replay Protection**: Webhook headers enforce timestamp verification with an automatic 300-second tolerance window.
3. **Idempotency**: Pass `idempotencyKey` in request options for state-changing operations to protect against duplicate execution.
