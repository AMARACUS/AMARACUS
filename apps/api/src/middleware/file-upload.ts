import { Request, Response, NextFunction } from 'express';
import multer, { MulterError } from 'multer';
import {
  validateFileBuffer,
  sanitizeFileName,
  secureStorage,
  DEFAULT_MAX_FILE_SIZE,
  StoredFileDescriptor,
  ALLOWED_EXTENSIONS,
} from '../lib/file-security';

export interface SecureUploadRequest extends Request {
  secureFile?: StoredFileDescriptor;
  secureFiles?: StoredFileDescriptor[];
}

export interface UploadMiddlewareOptions {
  fieldName?: string;
  maxSize?: number;
  allowedExtensions?: Set<string>;
  optional?: boolean;
}

/**
 * Creates an Express middleware for secure file upload.
 * Validates file size, file extension, magic byte signatures, and stores into non-executable storage.
 */
export function createSecureUploadMiddleware(options: UploadMiddlewareOptions = {}) {
  const fieldName = options.fieldName || 'file';
  const maxSize = options.maxSize || DEFAULT_MAX_FILE_SIZE;
  const allowedExtensions = options.allowedExtensions || ALLOWED_EXTENSIONS;

  // Use in-memory storage so buffer is inspected before saving to disk
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: maxSize,
      files: 1,
    },
    fileFilter: (_req, file, cb) => {
      // Early check on filename & extension
      const check = sanitizeFileName(file.originalname);
      if (!check.valid) {
        return cb(new Error(check.error || 'Invalid file name or unapproved extension.'));
      }
      if (allowedExtensions && !allowedExtensions.has(check.extension)) {
        return cb(new Error(`Extension "${check.extension}" not allowed for this upload.`));
      }
      cb(null, true);
    },
  }).single(fieldName);

  return (req: Request, res: Response, next: NextFunction) => {
    upload(req, res, async (err: any) => {
      if (err) {
        if (err instanceof MulterError) {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({
              error: {
                code: 'FILE_TOO_LARGE',
                message: `File exceeds maximum allowable size of ${maxSize} bytes (${Math.round(maxSize / (1024 * 1024))}MB).`,
              },
            });
          }
          return res.status(400).json({
            error: {
              code: 'UPLOAD_ERROR',
              message: err.message,
            },
          });
        }
        return res.status(400).json({
          error: {
            code: 'INVALID_FILE_TYPE',
            message: err.message || 'File upload failed validation.',
          },
        });
      }

      const file = (req as any).file;
      if (!file) {
        if (options.optional) {
          return next();
        }
        return res.status(400).json({
          error: {
            code: 'MISSING_FILE',
            message: `No file uploaded in form field "${fieldName}".`,
          },
        });
      }

      // In-depth buffer inspection: magic bytes, binary executable check, and size verification
      const validation = validateFileBuffer(file.buffer, file.originalname, {
        maxSize,
        allowedExtensions,
      });

      if (!validation.valid) {
        return res.status(400).json({
          error: {
            code: 'FILE_VALIDATION_FAILED',
            message: validation.error || 'Uploaded file failed security checks.',
          },
        });
      }

      try {
        // Store safely in non-executable storage
        const stored = await secureStorage.storeFile(file.buffer, file.originalname, {
          maxSize,
          allowedExtensions,
          mimeType: file.mimetype,
        });

        (req as SecureUploadRequest).secureFile = stored;
        next();
      } catch (storeErr: any) {
        return res.status(500).json({
          error: {
            code: 'STORAGE_ERROR',
            message: storeErr.message || 'Failed to safely store uploaded file.',
          },
        });
      }
    });
  };
}
