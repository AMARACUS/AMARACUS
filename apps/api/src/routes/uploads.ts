import { Router, Request, Response, NextFunction } from 'express';
import { requireAuth, requireOrgMember } from '../middleware/auth';
import { createRateLimiter } from '../middleware/rate-limiter';
import { createSecureUploadMiddleware, SecureUploadRequest } from '../middleware/file-upload';
import { secureStorage, DEFAULT_MAX_FILE_SIZE, StoredFileDescriptor } from '../lib/file-security';
import { db, UploadRecord } from '../lib/data-store';

const router = Router({ mergeParams: true });

// Middleware common to all uploads endpoints
router.use(requireAuth);
router.use(requireOrgMember);
router.use(createRateLimiter({ limit: 120, windowMs: 60 * 1000 }));

// Helper to sanitize upload records before returning via API
function sanitizeUploadRecord(upload: UploadRecord) {
  return {
    id: upload.id,
    organizationId: upload.organizationId,
    originalName: upload.originalName,
    fileName: upload.sanitizedName,
    mimeType: upload.mimeType,
    size: upload.size,
    sha256: upload.sha256,
    createdAt: upload.createdAt,
    updatedAt: upload.updatedAt,
  };
}

/**
 * POST /v1/organizations/:orgId/uploads
 * Uploads a file, performs comprehensive type, size and magic byte checks,
 * and stores it in non-executable isolated storage.
 */
router.post(
  '/',
  createSecureUploadMiddleware({
    fieldName: 'file',
    maxSize: DEFAULT_MAX_FILE_SIZE,
  }),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = req.params.orgId;
      const userId = (req as any).user?.id || null;
      const secureFile = (req as SecureUploadRequest).secureFile;

      if (!secureFile) {
        return res.status(400).json({
          error: {
            code: 'MISSING_FILE',
            message: 'No file was provided or file failed validation checks.',
          },
        });
      }

      // Persist upload metadata into DB
      const record = await db.createUpload({
        organizationId: orgId,
        userId,
        storageName: secureFile.storageName,
        originalName: secureFile.originalName,
        sanitizedName: secureFile.sanitizedName,
        mimeType: secureFile.mimeType,
        size: secureFile.size,
        sha256: secureFile.sha256,
        storagePath: secureFile.storagePath,
        metadata: {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        },
      });

      // Audit event
      await db.createAuditEvent({
        action: 'FILE_UPLOADED',
        organizationId: orgId,
        userId,
        resourceType: 'SECURE_UPLOAD',
        resourceId: record.id,
        metadata: {
          fileName: record.sanitizedName,
          size: record.size,
          sha256: record.sha256,
          mimeType: record.mimeType,
        },
      });

      res.status(201).json({
        data: {
          upload: sanitizeUploadRecord(record),
        },
      });
    } catch (err: any) {
      next(err);
    }
  }
);

/**
 * GET /v1/organizations/:orgId/uploads
 * Lists uploaded files for an organization.
 */
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const orgId = req.params.orgId;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const offset = Math.max(parseInt(req.query.offset as string) || 0, 0);

    const { uploads, total } = await db.listUploads(orgId, { limit, offset });

    res.json({
      data: {
        uploads: uploads.map(sanitizeUploadRecord),
        pagination: {
          limit,
          offset,
          total,
        },
      },
    });
  } catch (err: any) {
    next(err);
  }
});

/**
 * GET /v1/organizations/:orgId/uploads/:uploadId
 * Retrieves metadata for a specific uploaded file.
 */
router.get('/:uploadId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { orgId, uploadId } = req.params;
    const record = await db.getUploadById(orgId, uploadId);

    if (!record) {
      return res.status(404).json({
        error: {
          code: 'UPLOAD_NOT_FOUND',
          message: `Upload with ID "${uploadId}" not found.`,
        },
      });
    }

    res.json({
      data: {
        upload: sanitizeUploadRecord(record),
      },
    });
  } catch (err: any) {
    next(err);
  }
});

/**
 * GET /v1/organizations/:orgId/uploads/:uploadId/download
 * Securely downloads a file with non-executable forced attachment headers.
 */
router.get('/:uploadId/download', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { orgId, uploadId } = req.params;
    const record = await db.getUploadById(orgId, uploadId);

    if (!record) {
      return res.status(404).json({
        error: {
          code: 'UPLOAD_NOT_FOUND',
          message: `Upload with ID "${uploadId}" not found.`,
        },
      });
    }

    // Read file from isolated non-executable storage
    const fileBuffer = secureStorage.readFile(record.storageName);

    // Enforce strict headers so the browser NEVER executes or renders the file as HTML, JS, or script
    const safeFilename = record.sanitizedName.replace(/["\r\n]/g, '_');
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('Cache-Control', 'private, no-transform, no-store');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', fileBuffer.length);

    res.send(fileBuffer);
  } catch (err: any) {
    next(err);
  }
});

/**
 * DELETE /v1/organizations/:orgId/uploads/:uploadId
 * Deletes an uploaded file from isolated storage and database.
 */
router.delete('/:uploadId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { orgId, uploadId } = req.params;
    const record = await db.getUploadById(orgId, uploadId);

    if (!record) {
      return res.status(404).json({
        error: {
          code: 'UPLOAD_NOT_FOUND',
          message: `Upload with ID "${uploadId}" not found.`,
        },
      });
    }

    // Delete file from disk
    secureStorage.deleteFile(record.storageName);

    // Delete from DB
    await db.deleteUpload(orgId, uploadId);

    // Audit event
    await db.createAuditEvent({
      action: 'FILE_DELETED',
      organizationId: orgId,
      userId: (req as any).user?.id || null,
      resourceType: 'SECURE_UPLOAD',
      resourceId: uploadId,
      metadata: {
        fileName: record.sanitizedName,
      },
    });

    res.json({
      data: {
        deleted: true,
        id: uploadId,
      },
    });
  } catch (err: any) {
    next(err);
  }
});

export default router;
