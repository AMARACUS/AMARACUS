import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * File Security and Isolated Storage Engine
 * Enforces strict file type validation (extension allowlist + binary magic byte inspection),
 * strict size limits, and non-executable storage isolation.
 */

export interface FileValidationResult {
  valid: boolean;
  error?: string;
  detectedType?: string;
  sanitizedFileName: string;
}

export interface StoredFileDescriptor {
  fileId: string;
  storageName: string;
  originalName: string;
  sanitizedName: string;
  mimeType: string;
  size: number;
  sha256: string;
  storagePath: string;
  createdAt: string;
}

// 1. Strict Allowlist of Allowed File Extensions
export const ALLOWED_EXTENSIONS = new Set<string>([
  // Cryptographic & PKI Formats
  '.pem', '.crt', '.cer', '.der', '.csr', '.p7b', '.p7c', '.p12', '.pfx', '.key', '.pub', '.asc', '.sig',
  // Structured Documents & Data
  '.pdf', '.txt', '.csv', '.json', '.yaml', '.yml', '.md',
  // Safe Image Formats
  '.png', '.jpg', '.jpeg', '.gif', '.webp',
  // Archives & Bundles
  '.zip', '.tar', '.gz'
]);

// 2. Explicit Denylist of Executable, Script, and Active Content Extensions
export const FORBIDDEN_EXTENSIONS = new Set<string>([
  '.exe', '.bat', '.cmd', '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.vbs', '.vbe',
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.php', '.php3', '.php4', '.php5', '.phtml', '.phps',
  '.py', '.pyc', '.pyw', '.rb', '.pl', '.cgi',
  '.jar', '.war', '.ear', '.class',
  '.dll', '.so', '.dylib', '.bin', '.com', '.scr', '.hta', '.cpl', '.msc', '.msp', '.msi',
  '.reg', '.wsf', '.wsh', '.inf',
  '.asp', '.aspx', '.jsp', '.jspx', '.cfm', '.svg', '.html', '.htm', '.xhtml'
]);

// 3. Strict Size Limits
export const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
export const CERT_MAX_FILE_SIZE = 2 * 1024 * 1024;    // 2 MB

// 4. Executable Magic Signatures (Forbidden Byte Headers)
const EXECUTABLE_SIGNATURES: Array<{ name: string; bytes: number[]; offset?: number }> = [
  { name: 'Windows PE/EXE/DLL', bytes: [0x4D, 0x5A], offset: 0 }, // MZ
  { name: 'Linux/Unix ELF Binary', bytes: [0x7F, 0x45, 0x4C, 0x46], offset: 0 }, // \x7fELF
  { name: 'Mach-O Binary (32-bit BE)', bytes: [0xFE, 0xED, 0xFA, 0xCE], offset: 0 },
  { name: 'Mach-O Binary (64-bit BE)', bytes: [0xFE, 0xED, 0xFA, 0xCF], offset: 0 },
  { name: 'Mach-O Binary (32-bit LE)', bytes: [0xCE, 0xFA, 0xED, 0xFE], offset: 0 },
  { name: 'Mach-O Binary (64-bit LE)', bytes: [0xCF, 0xFA, 0xED, 0xFE], offset: 0 },
  { name: 'Java Class / Mach-O Fat', bytes: [0xCA, 0xFE, 0xBA, 0xBE], offset: 0 },
  { name: 'WebAssembly Binary', bytes: [0x00, 0x61, 0x73, 0x6D], offset: 0 }, // \0asm
  { name: 'Shell Shebang Script', bytes: [0x23, 0x21], offset: 0 }, // #!
];

/**
 * Sanitizes an incoming file name and protects against path traversal and double extensions.
 */
export function sanitizeFileName(originalName: string): { safeName: string; extension: string; valid: boolean; error?: string } {
  if (!originalName || typeof originalName !== 'string') {
    return { safeName: 'unnamed_file', extension: '', valid: false, error: 'File name is missing or invalid' };
  }

  // Strip null bytes and normalize
  const cleaned = originalName.replace(/\0/g, '').trim();

  // Strip path traversal components. Treat '\' as a separator too: on Linux,
  // path.basename would leave a Windows-style path like '..\..\x.txt' intact.
  const baseName = path.posix.basename(cleaned.replace(/\\/g, '/'));

  if (!baseName || baseName === '.' || baseName === '..') {
    return { safeName: 'unnamed_file', extension: '', valid: false, error: 'Invalid file name path' };
  }

  // Reject leading dots (hidden files, .env, .htaccess, etc.)
  if (baseName.startsWith('.')) {
    return { safeName: 'unnamed_file', extension: '', valid: false, error: 'Hidden files and dotfiles are not permitted' };
  }

  // Split name parts to inspect for multi-extension attacks (e.g. exploit.php.png)
  const parts = baseName.toLowerCase().split('.');
  if (parts.length > 1) {
    for (let i = 1; i < parts.length; i++) {
      const ext = '.' + parts[i];
      if (FORBIDDEN_EXTENSIONS.has(ext)) {
        return {
          safeName: 'rejected',
          extension: ext,
          valid: false,
          error: `File contains forbidden executable extension segment: "${ext}"`,
        };
      }
    }
  }

  const extension = path.extname(baseName).toLowerCase();

  // Validate extension against strict allowlist
  if (!extension || !ALLOWED_EXTENSIONS.has(extension)) {
    return {
      safeName: 'rejected',
      extension,
      valid: false,
      error: `File extension "${extension || 'none'}" is not permitted. Only approved cryptographic and document types are allowed.`,
    };
  }

  // Neutralize characters: keep only alphanumeric, dashes, dots, underscores
  const safeBase = path.basename(baseName, extension)
    .replace(/[^a-zA-Z0-9_\-]/g, '_')
    .slice(0, 100);

  const safeName = `${safeBase || 'upload'}${extension}`;

  return { safeName, extension, valid: true };
}

/**
 * Validates the file buffer against magic byte signatures, size constraints, and executable patterns.
 */
export function validateFileBuffer(
  buffer: Buffer,
  originalName: string,
  options?: { maxSize?: number; allowedExtensions?: Set<string> }
): FileValidationResult {
  const maxSize = options?.maxSize || DEFAULT_MAX_FILE_SIZE;

  // 1. File size check
  if (!buffer || buffer.length === 0) {
    return {
      valid: false,
      error: 'File is empty (0 bytes).',
      sanitizedFileName: 'empty',
    };
  }

  if (buffer.length > maxSize) {
    return {
      valid: false,
      error: `File size (${buffer.length} bytes) exceeds maximum allowable limit of ${maxSize} bytes (${Math.round(maxSize / (1024 * 1024))}MB).`,
      sanitizedFileName: 'oversized',
    };
  }

  // 2. File name & extension validation
  const nameCheck = sanitizeFileName(originalName);
  if (!nameCheck.valid) {
    return {
      valid: false,
      error: nameCheck.error,
      sanitizedFileName: nameCheck.safeName,
    };
  }

  const ext = nameCheck.extension;
  if (options?.allowedExtensions && !options.allowedExtensions.has(ext)) {
    return {
      valid: false,
      error: `Extension "${ext}" not permitted for this specific upload context.`,
      sanitizedFileName: nameCheck.safeName,
    };
  }

  // 3. Inspect buffer for forbidden executable binary signatures
  for (const sig of EXECUTABLE_SIGNATURES) {
    const offset = sig.offset || 0;
    if (buffer.length >= offset + sig.bytes.length) {
      let match = true;
      for (let i = 0; i < sig.bytes.length; i++) {
        if (buffer[offset + i] !== sig.bytes[i]) {
          match = false;
          break;
        }
      }
      if (match) {
        return {
          valid: false,
          error: `Executable binary signature detected (${sig.name}). Executable files can never be uploaded or stored.`,
          sanitizedFileName: nameCheck.safeName,
        };
      }
    }
  }

  // 4. Inspect buffer for embedded script tags or PHP / active script code
  const initialChunk = buffer.slice(0, Math.min(buffer.length, 4096)).toString('utf-8', 0, Math.min(buffer.length, 4096));
  const lowerChunk = initialChunk.toLowerCase();

  if (
    lowerChunk.includes('<?php') ||
    lowerChunk.includes('<?=') ||
    lowerChunk.includes('<script') ||
    lowerChunk.includes('<svg') ||
    lowerChunk.includes('<html')
  ) {
    return {
      valid: false,
      error: 'Active script or HTML tags detected in file header. Files containing active executable markup are prohibited.',
      sanitizedFileName: nameCheck.safeName,
    };
  }

  // 5. Positive validation based on file extension
  let detectedType = 'application/octet-stream';

  if (ext === '.pdf') {
    if (!initialChunk.startsWith('%PDF-')) {
      return {
        valid: false,
        error: 'Invalid PDF file: Missing %PDF- magic signature.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'application/pdf';
  } else if (ext === '.png') {
    const pngMagic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if (buffer.length < 8 || !pngMagic.every((b, i) => buffer[i] === b)) {
      return {
        valid: false,
        error: 'Invalid PNG file: Corrupt or spoofed PNG signature.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'image/png';
  } else if (ext === '.jpg' || ext === '.jpeg') {
    if (buffer.length < 3 || buffer[0] !== 0xFF || buffer[1] !== 0xD8 || buffer[2] !== 0xFF) {
      return {
        valid: false,
        error: 'Invalid JPEG file: Corrupt or spoofed JPEG signature.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'image/jpeg';
  } else if (ext === '.gif') {
    if (!initialChunk.startsWith('GIF87a') && !initialChunk.startsWith('GIF89a')) {
      return {
        valid: false,
        error: 'Invalid GIF file: Missing GIF87a/GIF89a signature.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'image/gif';
  } else if (ext === '.zip') {
    if (buffer.length < 4 || buffer[0] !== 0x50 || buffer[1] !== 0x4B) {
      return {
        valid: false,
        error: 'Invalid ZIP archive: Missing PK header.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'application/zip';
  } else if (ext === '.pem' || ext === '.crt' || ext === '.cer' || ext === '.csr' || ext === '.key' || ext === '.pub') {
    // Check that text is valid ASCII/UTF-8 and contains no binary null bytes
    if (buffer.includes(0x00)) {
      return {
        valid: false,
        error: 'PEM/Certificate file contains binary null bytes.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'application/x-pem-file';
  } else if (ext === '.json') {
    if (buffer.includes(0x00)) {
      return {
        valid: false,
        error: 'JSON file contains binary null bytes.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    try {
      JSON.parse(buffer.toString('utf-8'));
    } catch {
      return {
        valid: false,
        error: 'Malformed JSON payload.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'application/json';
  } else if (ext === '.txt' || ext === '.csv' || ext === '.md' || ext === '.yaml' || ext === '.yml') {
    if (buffer.includes(0x00)) {
      return {
        valid: false,
        error: 'Text document contains binary null bytes.',
        sanitizedFileName: nameCheck.safeName,
      };
    }
    detectedType = 'text/plain';
  }

  return {
    valid: true,
    detectedType,
    sanitizedFileName: nameCheck.safeName,
  };
}

/**
 * Isolated Secure Storage Manager
 * Stores files outside the web root, strips execution permissions,
 * and enforces random, inert file extensions.
 */
export class SecureStorageManager {
  private storageDir: string;

  constructor(customStorageDir?: string) {
    // Dedicated isolated storage directory outside web root and build output
    this.storageDir = customStorageDir || process.env.SECURE_UPLOADS_DIR || path.resolve(process.cwd(), 'storage', 'secure_uploads');
    this.initStorage();
  }

  /**
   * Initializes storage directory and writes protective execution blockers.
   */
  private initStorage(): void {
    try {
      if (!fs.existsSync(this.storageDir)) {
        fs.mkdirSync(this.storageDir, { recursive: true, mode: 0o700 });
      }

      // 1. Write Apache / LiteSpeed .htaccess execution blocker
      const htaccessPath = path.join(this.storageDir, '.htaccess');
      if (!fs.existsSync(htaccessPath)) {
        fs.writeFileSync(
          htaccessPath,
          `# Amaracus Upload Isolation Shield\n` +
          `# Deny all direct HTTP execution and script interpretation\n` +
          `Options -ExecCGI -Indexes\n` +
          `RemoveHandler .php .phtml .php3 .php4 .php5 .py .pl .cgi .sh .bash .js .ts .exe\n` +
          `SetHandler default-handler\n` +
          `<Files *>\n` +
          `  Order allow,deny\n` +
          `  Deny from all\n` +
          `</Files>\n`,
          { mode: 0o600 }
        );
      }

      // 2. Write IIS web.config execution blocker
      const webConfigPath = path.join(this.storageDir, 'web.config');
      if (!fs.existsSync(webConfigPath)) {
        fs.writeFileSync(
          webConfigPath,
          `<?xml version="1.0" encoding="UTF-8"?>\n` +
          `<configuration>\n` +
          `  <system.webServer>\n` +
          `    <handlers accessPolicy="None">\n` +
          `      <clear />\n` +
          `    </handlers>\n` +
          `    <authorization>\n` +
          `      <deny users="*" />\n` +
          `    </authorization>\n` +
          `  </system.webServer>\n` +
          `</configuration>\n`,
          { mode: 0o600 }
        );
      }

      // 3. Write README explaining non-executable isolation
      const readmePath = path.join(this.storageDir, 'README.txt');
      if (!fs.existsSync(readmePath)) {
        fs.writeFileSync(
          readmePath,
          `Amaracus Isolated Storage Directory\n` +
          `All files stored in this directory are non-executable raw blobs.\n` +
          `They cannot be executed by any web server, shell, or runtime environment.\n`,
          { mode: 0o600 }
        );
      }
    } catch (err) {
      console.error('[SecureStorageManager] Failed to initialize storage directory:', err);
    }
  }

  public getStorageDirectory(): string {
    return this.storageDir;
  }

  /**
   * Saves a validated file buffer into isolated non-executable storage.
   */
  public async storeFile(
    buffer: Buffer,
    originalName: string,
    options?: { maxSize?: number; allowedExtensions?: Set<string>; mimeType?: string }
  ): Promise<StoredFileDescriptor> {
    // Validate buffer and extension
    const validation = validateFileBuffer(buffer, originalName, options);
    if (!validation.valid) {
      throw new Error(`File upload rejected: ${validation.error}`);
    }

    const fileId = `file_${crypto.randomUUID()}`;
    // Use an inert, non-executable storage name
    const storageName = `${fileId}.inert`;
    const storagePath = path.join(this.storageDir, storageName);

    // Compute SHA-256 integrity hash
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    // Write file to disk with non-executable permissions (read/write owner only: 0o600)
    fs.writeFileSync(storagePath, buffer, { mode: 0o600 });

    return {
      fileId,
      storageName,
      originalName,
      sanitizedName: validation.sanitizedFileName,
      mimeType: validation.detectedType || options?.mimeType || 'application/octet-stream',
      size: buffer.length,
      sha256,
      storagePath,
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Retrieves a stored file buffer and ensures no path traversal outside storage directory.
   */
  public getFilePath(storageName: string): string {
    const safeName = path.basename(storageName);
    const resolvedPath = path.join(this.storageDir, safeName);

    // Path traversal check
    if (!resolvedPath.startsWith(this.storageDir)) {
      throw new Error('Access denied: Path traversal detected.');
    }

    if (!fs.existsSync(resolvedPath)) {
      throw new Error('File not found in secure storage.');
    }

    return resolvedPath;
  }

  /**
   * Reads file buffer safely from isolated storage.
   */
  public readFile(storageName: string): Buffer {
    const filePath = this.getFilePath(storageName);
    return fs.readFileSync(filePath);
  }

  /**
   * Securely removes a file from isolated storage.
   */
  public deleteFile(storageName: string): boolean {
    try {
      const filePath = this.getFilePath(storageName);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }
}

// Global Singleton Instance
export const secureStorage = new SecureStorageManager();
