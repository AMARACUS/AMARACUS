/**
 * Integration notes for coding agents, returned by the get_integration_guide tool. Every request
 * shown here matches apps/api/src/routes/v1 (crypto-universal.ts, keys-universal.ts). The base URL
 * is the address of this installation.
 */
export const GUIDE_TOPICS = ['quickstart', 'nodejs', 'python', 'curl', 'errors', 'best_practices'] as const;
export type GuideTopic = (typeof GUIDE_TOPICS)[number];

export function integrationGuide(topic: GuideTopic, baseUrl: string): string {
  const v1 = `${baseUrl}/v1`;
  switch (topic) {
    case 'quickstart':
      return [
        '# AMARACUS quickstart',
        '',
        '1. Create an AES-256-GCM key with purpose ENCRYPTION (the create_key tool, or the console). Keep its key ID.',
        '2. In the console, open API Keys and create an API key for your server with only the scopes it needs (crypto:encrypt, crypto:decrypt).',
        '3. Put both in the server environment: AMARACUS_API_KEY and AMARACUS_KEY_ID. Never in browser or mobile code, and never in source control.',
        `4. Encrypt with POST ${v1}/encrypt and store only the returned "envelope" string. Decrypt with POST ${v1}/decrypt.`,
        '5. Send "aad" with the table, record and field, for example "customers:42:address". Decryption fails if the envelope is moved to another record.',
        '',
        'Key material stays in AMARACUS and is never returned. Each request is limited to 1 MB.',
      ].join('\n');
    case 'nodejs':
      return [
        '# Node.js 18 or newer, no dependencies',
        '',
        '```js',
        `const BASE = process.env.AMARACUS_BASE_URL || "${v1}";`,
        '',
        'async function amaracus(path, body) {',
        '  const res = await fetch(`${BASE}${path}`, {',
        '    method: "POST",',
        '    headers: {',
        '      "Content-Type": "application/json",',
        '      Authorization: `Bearer ${process.env.AMARACUS_API_KEY}`,',
        '    },',
        '    body: JSON.stringify(body),',
        '  });',
        '  const json = await res.json();',
        '  if (!res.ok) throw new Error(`${json.error?.code}: ${json.error?.message}`);',
        '  return json.data;',
        '}',
        '',
        'export async function encrypt(text, aad) {',
        '  const { envelope } = await amaracus("/encrypt", { key: process.env.AMARACUS_KEY_ID, data: text, aad });',
        '  return envelope; // store this string',
        '}',
        '',
        'export async function decrypt(envelope, aad) {',
        '  const { plaintext } = await amaracus("/decrypt", { key: process.env.AMARACUS_KEY_ID, envelope, aad });',
        '  return plaintext;',
        '}',
        '```',
      ].join('\n');
    case 'python':
      return [
        '# Python 3, standard library only',
        '',
        '```python',
        'import json, os, urllib.error, urllib.request',
        '',
        `BASE = os.environ.get("AMARACUS_BASE_URL", "${v1}")`,
        '',
        'def amaracus(path, body):',
        '    req = urllib.request.Request(',
        '        BASE + path,',
        '        data=json.dumps(body).encode(),',
        '        headers={',
        '            "Content-Type": "application/json",',
        '            "Authorization": "Bearer " + os.environ["AMARACUS_API_KEY"],',
        '            "User-Agent": "my-app/1.0",',
        '        },',
        '        method="POST",',
        '    )',
        '    try:',
        '        with urllib.request.urlopen(req, timeout=30) as res:',
        '            return json.load(res)["data"]',
        '    except urllib.error.HTTPError as err:',
        '        detail = json.load(err).get("error", {})',
        '        raise RuntimeError(f"{detail.get(\'code\')}: {detail.get(\'message\')}") from None',
        '',
        'def encrypt(text, aad):',
        '    return amaracus("/encrypt", {"key": os.environ["AMARACUS_KEY_ID"], "data": text, "aad": aad})["envelope"]',
        '',
        'def decrypt(envelope, aad):',
        '    return amaracus("/decrypt", {"key": os.environ["AMARACUS_KEY_ID"], "envelope": envelope, "aad": aad})["plaintext"]',
        '```',
      ].join('\n');
    case 'curl':
      return [
        '# curl',
        '',
        '```bash',
        `curl -s ${v1}/encrypt \\`,
        '  -H "Authorization: Bearer $AMARACUS_API_KEY" \\',
        '  -H "Content-Type: application/json" \\',
        '  -d "{\\"key\\":\\"$AMARACUS_KEY_ID\\",\\"data\\":\\"hello\\",\\"aad\\":\\"demo:1\\"}"',
        '',
        `curl -s ${v1}/decrypt \\`,
        '  -H "Authorization: Bearer $AMARACUS_API_KEY" \\',
        '  -H "Content-Type: application/json" \\',
        '  -d "{\\"key\\":\\"$AMARACUS_KEY_ID\\",\\"envelope\\":\\"$ENVELOPE\\",\\"aad\\":\\"demo:1\\"}"',
        '```',
      ].join('\n');
    case 'errors':
      return [
        '# Errors',
        '',
        'Errors are JSON: {"error": {"code", "message"}, "requestId"}.',
        '',
        '- 400 INVALID_REQUEST: a field is missing or malformed.',
        '- 400 AAD_MISMATCH: the envelope belongs to a different record or field.',
        '- 401: the API key is missing, wrong, expired, disabled or revoked.',
        '- 402 PAYMENT_REQUIRED: the organization has no active plan.',
        '- 403 INSUFFICIENT_SCOPE: the API key lacks a scope; the message names it.',
        '- 403 IP_NOT_ALLOWED: the API key is limited to other IP addresses.',
        '- 404 KEY_NOT_FOUND: wrong key ID, or the key is in another project or environment.',
        '- 409 KEY_ALREADY_EXISTS: a key with that name exists in the environment.',
        '- 413: the request is larger than 1 MB.',
        '- 429 RATE_LIMITED: wait for the number of seconds in retryAfter.',
      ].join('\n');
    case 'best_practices':
      return [
        '# Best practices',
        '',
        '- Call AMARACUS from a server only. Keep the API key in the environment or a secret manager.',
        '- Give each service its own API key with the fewest scopes: a service that only saves data needs crypto:encrypt and not crypto:decrypt.',
        '- Limit production API keys to your server IP addresses (Allowed IPs, in the console).',
        '- Always send aad, so an encrypted value cannot be copied into another record.',
        '- Use one key per kind of data, and a separate environment for development.',
        '- Rotate keys on a schedule. Old envelopes still decrypt after a rotation; new data uses the new version.',
        '- Passwords are hashed with a password hashing function such as scrypt or Argon2id, not encrypted.',
        '- Do not log plaintext, envelopes with their keys, or API keys.',
      ].join('\n');
  }
}
