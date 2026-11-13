# Breach drill

A demo shop that keeps customer details encrypted with AMARACUS, and a script that plays out
three attacks against it. Everything uses made-up customers and a private local copy of the
AMARACUS API. Nothing touches production.

| File | What it is |
|---|---|
| `shop.mjs` | The demo shop. Each personal field (name, email, phone, address) is encrypted with `POST /v1/encrypt` and only the envelope is stored, bound to the customer id and field name (AAD). Sign-up uses a key that can only encrypt; staff screens use a key that can only decrypt. If AMARACUS is down, sign-up fails instead of storing plain text. |
| `local-amaracus.mjs` | Starts the real API code from `apps/api/dist` in its in-memory mode, with every production variable blanked and a throwaway master key. |
| `drill.mjs` | The drills. Prints PASS / FAIL / INFO for each check and writes `results/<date>-local.md`. |

## Run it

Needs Node 22.5 or later (for the built-in SQLite).

```bash
cd apps/api && npx tsc && cd ../..
node examples/breach-drill/drill.mjs
```

It takes about ten seconds.

## The drills

1. **Stolen database.** The attacker copies the shop's database file. Can they read the customers?
2. **Stolen API key.** The attacker also gets an AMARACUS API key. What can each kind of key do? Can
   another AMARACUS account use the shop's data? Is a copied envelope detected? Does revoking work?
   Does the rate limit slow a bulk read? Does the owner see it in the audit log?
3. **AMARACUS outage.** The API cannot be reached. Does the shop store plain text, or refuse?

The findings and fixes are in `docs/recovery/breach-drill-2026-11.md`.

## Using this pattern in a real app

- Give the server that **writes** personal data a key with only `crypto:encrypt`, and the screens
  that **show** it a separate key with only `crypto:decrypt`.
- Limit each key to your server's public IP addresses ("Allowed IPs" in the console). A copy of the key
  used from anywhere else is refused.
- AMARACUS locks a key that decrypts more than its alert level in an hour (1,000 by default, one level
  for the whole platform) and emails you, which caps what a thief on your own server can read. If your
  normal traffic is near that, split the work across keys.
- Pass an AAD that names the record and field (`customer:<id>:email`), and check the AAD inside the
  envelope before you decrypt (see `AmaracusClient.decrypt` in `shop.mjs`).
- Fail closed: if encryption fails, do not save the record.
- Put a timeout on every call to AMARACUS.
