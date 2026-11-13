import { describeCloud, itCloud } from './helpers/edition';
import { escapeHtml, stripHtml, sanitizeText, sanitizeUrl, sanitizePayload } from '../src/lib/sanitize';
import express from 'express';
import { sanitizeRequestMiddleware } from '../src/middleware/sanitize';

describe('Cryptographic & Platform Input Sanitization Security', () => {
  describe('escapeHtml', () => {
    it('escapes standard HTML special characters', () => {
      const input = '<script>alert("pwned" & \'xss\')</script>';
      const result = escapeHtml(input);
      expect(result).not.toContain('<');
      expect(result).not.toContain('>');
      expect(result).not.toContain('"');
      expect(result).not.toContain("'");
      expect(result).toContain('&lt;script&gt;');
      expect(result).toContain('&quot;pwned&quot;');
    });

    it('escapes backticks and slashes to prevent template injection and closing tags', () => {
      const input = '`onerror=alert(1)//';
      const result = escapeHtml(input);
      expect(result).toContain('&#x60;');
      expect(result).toContain('&#x2F;');
    });

    it('handles non-string primitives safely', () => {
      expect(escapeHtml(12345)).toBe('12345');
      expect(escapeHtml(true)).toBe('true');
      expect(escapeHtml(null)).toBe('');
      expect(escapeHtml(undefined)).toBe('');
    });
  });

  describe('stripHtml', () => {
    it('strips script tags and inner blocks', () => {
      const input = 'Hello <script>maliciousCode()</script>World!';
      expect(stripHtml(input)).toBe('Hello World!');
    });

    it('strips general HTML tags', () => {
      const input = '<b>Bold</b> <a href="http://evil.com">Link</a>';
      expect(stripHtml(input)).toBe('Bold Link');
    });
  });

  describe('sanitizeText', () => {
    it('strips null bytes and ASCII control characters', () => {
      const input = 'Admin\0User\x07\x1F';
      const result = sanitizeText(input);
      expect(result).toBe('AdminUser');
    });

    it('normalizes single-line text and escapes HTML', () => {
      const input = '  <img src=x onerror=alert(1)>  ';
      const result = sanitizeText(input);
      expect(result).not.toContain('<img');
      expect(result).toContain('&lt;img');
    });
  });

  describe('sanitizeUrl', () => {
    it('blocks dangerous javascript: pseudo-protocol', () => {
      expect(sanitizeUrl('javascript:alert(1)')).toBe('about:blank');
      expect(sanitizeUrl('JAVASCRIPT:alert(document.cookie)')).toBe('about:blank');
    });

    it('blocks data: and vbscript: URLs', () => {
      expect(sanitizeUrl('data:text/html,<script>alert(1)</script>')).toBe('about:blank');
      expect(sanitizeUrl('vbscript:msgbox("hi")')).toBe('about:blank');
    });

    it('permits valid HTTPS URLs', () => {
      expect(sanitizeUrl('https://api.amaracus.cloud/v1')).toBe('https://api.amaracus.cloud/v1');
    });

    it('permits safe relative paths', () => {
      expect(sanitizeUrl('/dashboard/projects')).toBe('/dashboard/projects');
    });
  });

  describe('sanitizePayload', () => {
    it('keeps text as typed (escaping happens on output) but strips control characters', () => {
      const payload = {
        name: "O'Brien & Sons <Production>\u0000",
        description: 'Line one\nLine two\u0007',
        organization: {
          title: 'ACME & Sons <tag>',
          meta: ['Normal', 'a/b=c\u001b'],
        },
        // Raw crypto payload must retain exact characters
        ciphertext: 'am:aes:v1:7f8a9/+=&<>',
        plaintext: 'Secret Key Value 123!@#',
      };

      const sanitized = sanitizePayload(payload);

      expect(sanitized.name).toBe("O'Brien & Sons <Production>");
      expect(sanitized.description).toBe('Line one\nLine two');
      expect(sanitized.organization.title).toBe('ACME & Sons <tag>');
      expect(sanitized.organization.meta).toEqual(['Normal', 'a/b=c']);

      // Crypto payload preserved
      expect(sanitized.ciphertext).toBe('am:aes:v1:7f8a9/+=&<>');
      expect(sanitized.plaintext).toBe('Secret Key Value 123!@#');
    });

    it('prevents prototype pollution injection', () => {
      const malicious = JSON.parse('{"__proto__":{"polluted":true},"name":"Alice"}');
      const sanitized = sanitizePayload(malicious);
      expect(sanitized.name).toBe('Alice');
      expect(({} as any).polluted).toBeUndefined();
    });
  });

  describe('Express Sanitization Middleware Integration', () => {
    let server: any;
    let baseUrl: string;

    beforeAll((done) => {
      const app = express();
      app.use(express.json());
      app.use(sanitizeRequestMiddleware());

      app.post('/test', (req, res) => {
        res.json({ body: req.body, query: req.query });
      });

      server = app.listen(0, () => {
        const port = (server.address() as any).port;
        baseUrl = `http://127.0.0.1:${port}`;
        done();
      });
    });

    afterAll((done) => {
      server.close(done);
    });

    it('cleans request bodies and queries before route handlers receive them, without HTML-escaping', async () => {
      const res = await fetch(`${baseUrl}/test?search=%3Cmarquee%3Esearch%3C/marquee%3E%01`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectName: 'My <marquee>Project</marquee>',
          description: 'Tom & Jerry\u0000',
          nested: JSON.parse('{"__proto__":{"polluted":true},"ok":1}'),
        }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.body.projectName).toBe('My <marquee>Project</marquee>');
      expect(data.body.description).toBe('Tom & Jerry');
      expect(data.body.nested).toEqual({ ok: 1 });
      expect(data.query.search).toBe('<marquee>search</marquee>');
    });
  });

  describe('Phase 7: output escaping where the API renders text', () => {
    itCloud('hackathon CSV export neutralizes spreadsheet formulas', () => {
      const { HackathonCsvExporter } = require('../src/lib/hackathon-csv');
      const csv: string = new HackathonCsvExporter().generateCsv([
        {
          id: 'hck_1',
          projectName: '=HYPERLINK("http://evil.example","x")',
          category: '+cmd',
          description: '@SUM(A1)',
          userEmail: 'a@b.test',
          sourceCodeUrl: '-2+3',
          apiUsageEndpoints: [],
          score: -5,
          createdAt: new Date('2026-10-28T00:00:00Z'),
        } as any,
      ]);
      expect(csv).toContain(`"'=HYPERLINK(""http://evil.example"",""x"")"`);
      expect(csv).toContain(`"'+cmd"`);
      expect(csv).toContain(`"'@SUM(A1)"`);
      expect(csv).toContain(`"'-2+3"`);
      expect(csv).toContain('"-5"');
    });
  });

  describe('Phase 7: passwords hashed under the old input escaping', () => {
    it('still match, and are flagged for rehashing', async () => {
      const { hashPassword, verifyAccountPassword } = require('../src/lib/crypto-security');
      const typed = "p@ss'word<1>";
      const legacyHash = await hashPassword(sanitizeText(typed));
      expect(await verifyAccountPassword(typed, legacyHash)).toEqual({ valid: true, legacy: true });
      expect(await verifyAccountPassword(typed, await hashPassword(typed))).toEqual({ valid: true, legacy: false });
      expect(await verifyAccountPassword('wrong-password', legacyHash)).toEqual({ valid: false, legacy: false });
    });
  });
});
