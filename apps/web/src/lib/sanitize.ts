/**
 * Client-Side Input Sanitization and HTML Escaping Utility
 * Escapes and sanitizes anything a user submits before it gets shown on the page.
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

// Keys that hold raw cryptographic data (like ciphertext or key bytes)
const CRYPTO_PAYLOAD_KEYS = new Set([
  'plaintext',
  'ciphertext',
  'signature',
  'keydata',
  'csr',
  'rawbody',
  'iv',
  'tag',
  'authtag',
  'sharedsecret',
  'passwordhash',
  'token',
  'apikey',
  'secret',
  'encryptedkey',
  'plaintextkey',
  'url',
  'webhookurl',
  'sourcecodeurl',
  'demourl',
  'videourl',
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

  // Escape HTML entities to guarantee safe rendering everywhere
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
  const trimmed = url.trim();

  // Block dangerous protocols
  if (DANGEROUS_PROTOCOLS.test(trimmed)) {
    return fallback;
  }

  // Allow safe relative paths
  if (trimmed.startsWith('/') || trimmed.startsWith('./') || trimmed.startsWith('../') || trimmed.startsWith('#')) {
    return escapeHtml(trimmed);
  }

  // Verify protocol if absolute
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:' || parsed.protocol === 'mailto:') {
      return escapeHtml(trimmed);
    }
    return fallback;
  } catch {
    return fallback;
  }
}

/**
 * Recursively sanitizes any data structure before submitting to API or displaying on the page
 */
export function sanitizePayload<T>(data: T, currentKey = ''): T {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    const keyLower = currentKey.toLowerCase();
    // For raw crypto payloads, remove null bytes but preserve exact characters
    if (CRYPTO_PAYLOAD_KEYS.has(keyLower)) {
      return data.replace(/\0/g, '') as unknown as T;
    }
    // For general text/metadata, sanitize and escape HTML
    return sanitizeText(data) as unknown as T;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizePayload(item, currentKey)) as unknown as T;
  }

  if (typeof data === 'object') {
    // Prevent prototype pollution
    const cleanObj: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      cleanObj[key] = sanitizePayload(value, key);
    }
    return cleanObj as T;
  }

  return data;
}
