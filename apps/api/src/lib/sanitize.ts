/**
 * Comprehensive input sanitization and HTML escaping utility
 * Protects against XSS, HTML injection, control character attacks, and prototype pollution.
 */

const HTML_ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;',
};

const DANGEROUS_PROTOCOLS = /^(javascript|vbscript|data|file):/i;
const SCRIPT_REGEX = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
const TAG_REGEX = /<[^>]+>/g;
const CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

// Keys that hold raw cryptographic data or URLs which should not have their punctuation altered
const CRYPTO_PAYLOAD_KEYS = new Set([
  'data',
  'payload',
  'plaintext',
  'ciphertext',
  'rawkey',
  'key',
  'aad',
  'envelope',
  'ct',
  'signature',
  'keydata',
  'csr',
  'rawbody',
  'iv',
  'tag',
  'authtag',
  'sharedsecret',
  'message',
  'digest',
  'input',
  'inputs',
  'passwordhash',
  'token',
  'apikey',
  'secret',
  'encryptedkey',
  'plaintextkey',
  'url',
  'webhookurl',
  'vaulturl',
  'hsmurl',
  'endpoint',
  'successurl',
  'cancelurl',
  'returnurl',
  'publickey',
  'privatekey',
  'secretkey',
  'relinkeys',
  'galoiskeys',
  'ciphertexta',
  'ciphertextb',
  'resultciphertext',
  'context',
  'sourcecodeurl',
  'demourl',
  'videourl',
  'content',
  'sourcecode',
  'code',
  'snippet',
  'pem',
  'certificatepem',
  'publickeypem',
  'privatekeypem',
  'csrpem',
  'ciphertexts',
  'ciphertextbase64',
  'resultciphertextbase64',
  'publickeybase64',
  'secretkeybase64',
  'relinbase64',
  'proof',
  'proofs',
  'witness',
  'shares',
  'share',
  'subject',
  'issuer',
  'dn',
  'distinguishedname',
  'san',
]);

/**
 * Escapes characters with special meaning in HTML contexts (& < > " ' / ` =)
 */
export function escapeHtml(str: unknown): string {
  if (typeof str !== 'string') {
    return typeof str === 'number' || typeof str === 'boolean' ? String(str) : '';
  }
  return str.replace(/[&<>"'/`=]/g, (match) => HTML_ESCAPE_MAP[match] || match);
}

/**
 * Strips all HTML tags and script elements from a string
 */
export function stripHtml(str: string): string {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(SCRIPT_REGEX, '')
    .replace(TAG_REGEX, '')
    .trim();
}

/**
 * Normalizes text, removes null bytes and control chars, strips script tags, and escapes HTML
 */
export function sanitizeText(str: unknown, options?: { allowMultiline?: boolean; maxLen?: number }): string {
  if (typeof str !== 'string') {
    return typeof str === 'number' || typeof str === 'boolean' ? String(str) : '';
  }

  let cleaned = str
    .replace(/\0/g, '') // Remove null bytes
    .replace(CONTROL_CHARS_REGEX, '') // Remove dangerous ASCII control characters
    .normalize('NFC');

  // Strip script tags
  cleaned = cleaned.replace(SCRIPT_REGEX, '');

  if (!options?.allowMultiline) {
    cleaned = cleaned.replace(/[\r\n]+/g, ' ');
  }

  // Escape HTML characters
  cleaned = escapeHtml(cleaned.trim());

  if (options?.maxLen && cleaned.length > options.maxLen) {
    cleaned = cleaned.slice(0, options.maxLen);
  }

  return cleaned;
}

/**
 * Validates and sanitizes a URL, blocking dangerous pseudo-protocols like javascript: or data:
 */
export function sanitizeUrl(url: unknown, fallback = 'about:blank'): string {
  if (typeof url !== 'string' || !url.trim()) return fallback;
  const trimmed = url.trim().replace(/\0/g, '').replace(CONTROL_CHARS_REGEX, '');

  // Block dangerous protocols
  if (DANGEROUS_PROTOCOLS.test(trimmed)) {
    return fallback;
  }

  // Allow safe relative paths
  if (trimmed.startsWith('/') || trimmed.startsWith('./') || trimmed.startsWith('../') || trimmed.startsWith('#')) {
    return trimmed;
  }

  // Verify protocol if absolute
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:' || parsed.protocol === 'mailto:') {
      return trimmed;
    }
    return fallback;
  } catch {
    return fallback;
  }
}

/**
 * Removes null bytes and ASCII control characters, keeping tab, newline and carriage return.
 */
export function stripControlChars(str: string): string {
  return str.replace(CONTROL_CHARS_REGEX, '');
}

/**
 * Recursively cleans request input: drops prototype-pollution keys and strips control
 * characters from text. It does not HTML-escape: input is stored as typed and escaped
 * where it is output (React in the console, escapeHtml in email templates, formula
 * guarding in CSV exports), so stored values never carry entities like `&amp;`.
 */
export function sanitizePayload<T>(data: T, currentKey = '', options: { preserveStrings?: boolean } = {}): T {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    // Crypto request bodies carry exact bytes and user data; altering them corrupts results
    if (options.preserveStrings) {
      return data;
    }
    const keyLower = currentKey.toLowerCase();
    // For raw crypto payloads, preserve exact characters and bytes
    if (CRYPTO_PAYLOAD_KEYS.has(keyLower)) {
      return data as unknown as T;
    }
    return stripControlChars(data) as unknown as T;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizePayload(item, currentKey, options)) as unknown as T;
  }

  if (typeof data === 'object') {
    // Prevent prototype pollution
    const cleanObj: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      cleanObj[key] = sanitizePayload(value, key, options);
    }
    return cleanObj as T;
  }

  return data;
}
