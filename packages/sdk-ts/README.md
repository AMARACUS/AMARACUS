# @amaracus/sdk

Official TypeScript and JavaScript SDK for [AMARACUS](https://amaracus.tech): encryption as a service, managed keys with rotation, hashing, signing, post-quantum ML-KEM and signed webhooks, from any Node.js backend.

The SDK sends requests to the AMARACUS API; managed keys stay on the AMARACUS side and are never returned. Use it **on your server only** (Node.js 18 or newer). Never put an API key in browser, mobile or device code.

## Install

```bash
npm install @amaracus/sdk
# or
pnpm add @amaracus/sdk
# or
yarn add @amaracus/sdk
```

## Set up

1. In the AMARACUS console, open **API Credentials** and generate an API key (`am_live_…`). Tick only the scopes the service needs (for example **Encrypt** for a service that only saves data).
2. Open **Key Management → Internal & Development Keys**, click **Create Managed Key** (AES-256-GCM) and copy its **Key ID**.
3. Put both in your server's environment:

```bash
AMARACUS_API_KEY=am_live_...
AMARACUS_KEY_ID=your-key-id
```

`new Amaracus()` reads `AMARACUS_API_KEY`, and `AMARACUS_BASE_URL` if you run a self-hosted API (for example `http://localhost:4000/v1`).

## Encrypt and decrypt

```ts
import { Amaracus } from '@amaracus/sdk';

const am = new Amaracus();
const KEY_ID = process.env.AMARACUS_KEY_ID!;

// Encrypt: store only the envelope (in your database, cache or file store).
const { envelope } = await am.encrypt({ key: KEY_ID, data: 'Sensitive customer record', aad: 'customers:42:address' });

// Decrypt: pass the envelope back with the same key and context.
const { data } = await am.decrypt({ key: KEY_ID, envelope, aad: 'customers:42:address' });
```

`aad` (optional context) is sealed into the envelope: decryption fails if the envelope is moved to another record.

## Keys

```ts
const key = await am.keys.create({ name: 'customer-data', algorithm: 'AES-256-GCM', purpose: 'ENCRYPT_DECRYPT' });
const rotated = await am.keys.rotate(key.id); // same Key ID, new version; old envelopes still decrypt
```

## Hashing

```ts
const digest = await am.hash({ data: 'hello', algorithm: 'SHA-256' });
```

## Post-quantum key exchange (ML-KEM, FIPS 203)

```ts
const kp = await am.pqc.keypair({ algorithm: 'ML_KEM_768' });
const enc = await am.pqc.encapsulate({ algorithm: 'ML_KEM_768', publicKey: kp.publicKey });
const dec = await am.pqc.decapsulate({ algorithm: 'ML_KEM_768', cipherText: enc.cipherText, privateKey: kp.privateKey });
// enc.sharedSecret === dec.sharedSecret
```

## Webhooks

### Express

```ts
import express from 'express';
import { amaracusWebhookMiddleware } from '@amaracus/sdk';

const app = express();
app.post(
  '/webhooks/amaracus',
  express.raw({ type: 'application/json' }), // raw body, before express.json()
  amaracusWebhookMiddleware({ secret: process.env.AMARACUS_WEBHOOK_SECRET! }),
  (req, res) => {
    console.log('Verified event:', req.amaracusEvent.type);
    res.json({ received: true });
  }
);
```

### Next.js route handler

```ts
// app/api/webhooks/amaracus/route.ts
import { verifyNextJsWebhook } from '@amaracus/sdk';

export async function POST(req: Request) {
  try {
    const event = await verifyNextJsWebhook(req, process.env.AMARACUS_WEBHOOK_SECRET!);
    return Response.json({ received: true, type: event.type });
  } catch (err: any) {
    return Response.json({ error: err.message }, { status: 400 });
  }
}
```

Signatures are HMAC-SHA256 over `timestamp.body` in the `X-AMARACUS-Signature` header; messages older than 300 seconds are rejected.

## Errors

| Status | Meaning |
|---|---|
| 401 | API key missing or wrong |
| 402 | No active plan |
| 403 `INSUFFICIENT_SCOPE` | The API key lacks a scope; the message names it |
| 404 `KEY_NOT_FOUND` | Wrong Key ID, or the key is in another project or environment |

Each request is limited to 1 MB.

## Links

- Documentation: https://amaracus.tech/docs/
- Source: https://github.com/AMARACUS/AMARACUS

## Licence

Apache-2.0
