import { Request, Response, NextFunction } from 'express';
import { sanitizePayload } from '../lib/sanitize';

/**
 * Routes whose request bodies are cryptographic inputs (plaintext, keys, signatures,
 * certificates). Their strings are passed through unchanged: HTML-escaping or
 * stripping control characters would change the bytes being encrypted, signed or
 * verified. The web app renders all text through React, which escapes on output.
 */
const CRYPTO_BODY_PATH = new RegExp(
  '^/(api/)?v1/(' +
    'encrypt|decrypt|hash|sign|verify|crypto|pqc|keys|pki|certificates|certificate-authorities|' +
    'advanced|advanced-crypto|customer-key-providers|operations|jobs|' +
    'organizations/[^/]+/(crypto|keys|byok|pki|advanced)' +
    ')(/|$)'
);

export function isCryptoBodyPath(path: string): boolean {
  return CRYPTO_BODY_PATH.test(path);
}

/**
 * Express middleware that cleans req.body, req.query and req.params before route handlers run:
 * prototype-pollution keys are dropped and control characters stripped from text. HTML escaping
 * happens on output, not here. Crypto request bodies only get prototype-pollution keys removed.
 */
export function sanitizeRequestMiddleware() {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizePayload(req.body, '', { preserveStrings: isCryptoBodyPath(req.path) });
      }

      if (req.query && typeof req.query === 'object') {
        req.query = sanitizePayload(req.query);
      }

      if (req.params && typeof req.params === 'object') {
        req.params = sanitizePayload(req.params);
      }
    } catch (err) {
      console.error('[Sanitization Middleware] Error sanitizing request inputs:', err);
    }
    next();
  };
}
